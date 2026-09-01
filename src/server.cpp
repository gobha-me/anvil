#include "server.hpp"

#include <fcntl.h>
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/libssh_version.h>
#include <libssh/server.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/random.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "admission.hpp"
#include "authentication.hpp"
#include "backup.hpp"
#include "health.hpp"
#include "sqlite_store.hpp"
#include "terminal_session.hpp"
#include "text_sanitization.hpp"

namespace anvil::server {
namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

constexpr std::size_t max_key_file_size = 64U * 1024U;
constexpr std::size_t max_tos_file_size = 256U * 1024U;
constexpr std::size_t max_pending_input = 64U * 1024U;
constexpr std::size_t max_remote_username_size = 256U;
constexpr auto authentication_timeout = 15s;
constexpr auto shutdown_timeout = 5s;
constexpr int auth_report_failure_exit = 75;
constexpr std::uint32_t worker_report_magic = 0x414E5657U;
constexpr std::uint16_t worker_report_version = 2U;

[[noreturn]] void throw_system_error(std::string_view operation);

void clear_secret(char *data, std::size_t size) noexcept {
  auto *cursor = static_cast<volatile char *>(data);
  while (size > 0U) {
    *cursor++ = '\0';
    --size;
  }
}

class FileDescriptor {
public:
  explicit FileDescriptor(int descriptor = -1) noexcept
      : descriptor_(descriptor) {}
  ~FileDescriptor() {
    if (descriptor_ >= 0) {
      static_cast<void>(::close(descriptor_));
    }
  }

  FileDescriptor(const FileDescriptor &) = delete;
  FileDescriptor &operator=(const FileDescriptor &) = delete;
  FileDescriptor(FileDescriptor &&other) noexcept
      : descriptor_(std::exchange(other.descriptor_, -1)) {}
  FileDescriptor &operator=(FileDescriptor &&other) noexcept {
    if (this != &other) {
      if (descriptor_ >= 0) {
        static_cast<void>(::close(descriptor_));
      }
      descriptor_ = std::exchange(other.descriptor_, -1);
    }
    return *this;
  }

  [[nodiscard]] int get() const noexcept { return descriptor_; }
  [[nodiscard]] int release() noexcept {
    return std::exchange(descriptor_, -1);
  }

private:
  int descriptor_;
};

class TemporaryDirectoryEntry {
public:
  TemporaryDirectoryEntry(int directory, std::string name)
      : directory_(directory), name_(std::move(name)) {}
  ~TemporaryDirectoryEntry() {
    if (present_) {
      static_cast<void>(::unlinkat(directory_, name_.c_str(), 0));
    }
  }

  TemporaryDirectoryEntry(const TemporaryDirectoryEntry &) = delete;
  TemporaryDirectoryEntry &operator=(const TemporaryDirectoryEntry &) = delete;

  void remove() {
    if (::unlinkat(directory_, name_.c_str(), 0) != 0) {
      throw_system_error("cannot remove temporary host key");
    }
    present_ = false;
  }

private:
  int directory_;
  std::string name_;
  bool present_{true};
};

struct KeyDeleter {
  void operator()(ssh_key_struct *key) const noexcept { ssh_key_free(key); }
};
using UniqueKey = std::unique_ptr<ssh_key_struct, KeyDeleter>;

struct ExportedKeyDeleter {
  void operator()(char *key) const noexcept {
    if (key != nullptr) {
      clear_secret(key, std::strlen(key));
      ssh_string_free_char(key);
    }
  }
};
using UniqueExportedKey = std::unique_ptr<char, ExportedKeyDeleter>;

struct BindDeleter {
  void operator()(ssh_bind_struct *bind) const noexcept { ssh_bind_free(bind); }
};
using UniqueBind = std::unique_ptr<ssh_bind_struct, BindDeleter>;

struct SessionDeleter {
  void operator()(ssh_session_struct *session) const noexcept {
    ssh_free(session);
  }
};
using UniqueSession = std::unique_ptr<ssh_session_struct, SessionDeleter>;

struct EventDeleter {
  void operator()(ssh_event_struct *event) const noexcept {
    ssh_event_free(event);
  }
};
using UniqueEvent = std::unique_ptr<ssh_event_struct, EventDeleter>;

struct AuthorizedKey {
  std::string user;
  UniqueKey key;
};

enum class RequestedOperation { none, shell, exec, subsystem };

struct SessionState {
  store::Store *identity_store{};
  std::string_view tos_version;
  SessionIdentity identity;
  ssh_channel channel{};
  unsigned int auth_attempts{};
  unsigned int max_auth_attempts{};
  int worker_report_descriptor{-1};
  bool authenticated{};
  bool auth_report_failed{};
  bool channel_callbacks_installed{};
  bool pty_requested{};
  bool input_eof{};
  bool close_requested{};
  int columns{80};
  int rows{24};
  int pixel_width{};
  int pixel_height{};
  std::string terminal_type;
  TerminalSession *terminal_session{};
  RequestedOperation operation{RequestedOperation::none};
  std::vector<std::byte> pending_input;
  Clock::time_point last_activity{Clock::now()};
  Clock::time_point authenticated_at{};
  Clock::time_point channel_opened_at{};
  bool idle_warning_sent{};
};

[[nodiscard]] auto valid_tos_version(std::string_view version) -> bool {
  if (version.empty() || version.size() > 128U ||
      !is_well_formed_utf8(version)) {
    return false;
  }
  for (std::size_t offset = 0; offset < version.size(); ++offset) {
    const auto byte = static_cast<unsigned char>(version[offset]);
    if (byte < 0x20U || byte == 0x7fU ||
        (byte == 0xc2U && offset + 1U < version.size() &&
         static_cast<unsigned char>(version[offset + 1U]) >= 0x80U &&
         static_cast<unsigned char>(version[offset + 1U]) <= 0x9fU)) {
      return false;
    }
  }
  return true;
}

enum class WorkerReportKind : std::uint16_t { denied_auth, telemetry };

struct WorkerReport {
  std::uint32_t magic{worker_report_magic};
  std::uint16_t version{worker_report_version};
  WorkerReportKind kind{};
  pid_t worker{};
  std::uint64_t session_id{};
  SessionTelemetry telemetry;
};

static_assert(std::is_trivially_copyable_v<WorkerReport>);

[[noreturn]] void throw_system_error(std::string_view operation) {
  throw std::system_error(errno, std::generic_category(),
                          std::string(operation));
}

[[nodiscard]] std::string
read_key_file(FileDescriptor file, const std::string &path, bool private_key) {
  struct stat metadata{};
  if (::fstat(file.get(), &metadata) != 0) {
    throw_system_error("cannot inspect key file '" + path + "'");
  }
  if (!S_ISREG(metadata.st_mode)) {
    throw std::runtime_error("key file is not a regular file: " + path);
  }
  if (private_key && (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    throw std::runtime_error(
        "host key must not be accessible by group or others: " + path);
  }
  if (metadata.st_size <= 0 ||
      static_cast<std::uintmax_t>(metadata.st_size) > max_key_file_size) {
    throw std::runtime_error("key file has an invalid size: " + path);
  }

  std::string contents;
  contents.resize(static_cast<std::size_t>(metadata.st_size));
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const auto count =
        ::read(file.get(), contents.data() + offset, contents.size() - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      throw_system_error("cannot read key file '" + path + "'");
    }
    if (count == 0) {
      throw std::runtime_error("key file changed while being read: " + path);
    }
    offset += static_cast<std::size_t>(count);
  }
  if (contents.find('\0') != std::string::npos) {
    throw std::runtime_error("key file contains a NUL byte: " + path);
  }
  return contents;
}

[[nodiscard]] std::string read_key_file(const std::string &path,
                                        bool private_key) {
  const auto descriptor =
      ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (descriptor < 0) {
    throw_system_error("cannot open key file '" + path + "'");
  }
  return read_key_file(FileDescriptor(descriptor), path, private_key);
}

[[nodiscard]] TosPolicy load_tos_policy(const Config &config) {
  if (!valid_tos_version(config.tos_version)) {
    throw std::runtime_error(
        "TOS version must contain 1 to 128 bytes of valid UTF-8 and no "
        "controls");
  }
  const auto descriptor = ::open(
      config.tos_file.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (descriptor < 0) {
    throw_system_error("cannot open TOS file '" + config.tos_file + "'");
  }
  FileDescriptor file(descriptor);
  struct stat metadata{};
  if (::fstat(file.get(), &metadata) != 0) {
    throw_system_error("cannot inspect TOS file '" + config.tos_file + "'");
  }
  if (!S_ISREG(metadata.st_mode)) {
    throw std::runtime_error("TOS file is not a regular file: " +
                             config.tos_file);
  }
  if (metadata.st_size <= 0 ||
      static_cast<std::uintmax_t>(metadata.st_size) > max_tos_file_size) {
    throw std::runtime_error("TOS file must contain 1 to 262144 bytes: " +
                             config.tos_file);
  }
  std::string contents(static_cast<std::size_t>(metadata.st_size), '\0');
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const auto count =
        ::read(file.get(), contents.data() + offset, contents.size() - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      throw_system_error("cannot read TOS file '" + config.tos_file + "'");
    }
    if (count == 0) {
      throw std::runtime_error("TOS file changed while being read: " +
                               config.tos_file);
    }
    offset += static_cast<std::size_t>(count);
  }
  char trailing{};
  ssize_t trailing_count = 0;
  do {
    trailing_count = ::read(file.get(), &trailing, 1);
  } while (trailing_count < 0 && errno == EINTR);
  if (trailing_count < 0) {
    throw_system_error("cannot finish reading TOS file '" + config.tos_file +
                       "'");
  }
  if (trailing_count != 0) {
    throw std::runtime_error("TOS file changed while being read: " +
                             config.tos_file);
  }
  if (contents.find('\0') != std::string::npos) {
    throw std::runtime_error("TOS file contains a NUL byte: " +
                             config.tos_file);
  }
  if (!is_well_formed_utf8(contents)) {
    throw std::runtime_error("TOS file is not valid UTF-8: " + config.tos_file);
  }
  const auto display = sanitize_prose_for_render(contents);
  const auto visible = std::ranges::any_of(display, [](const char value) {
    const auto byte = static_cast<unsigned char>(value);
    return byte > 0x20U && byte != 0x7fU;
  });
  if (!visible) {
    throw std::runtime_error("TOS file has no visible text: " +
                             config.tos_file);
  }
  return TosPolicy{.version = config.tos_version, .text = std::move(contents)};
}

[[nodiscard]] std::string read_host_key_at(int directory,
                                           const std::string &filename,
                                           const std::string &path) {
  const auto descriptor =
      ::openat(directory, filename.c_str(),
               O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (descriptor < 0) {
    throw_system_error("cannot open key file '" + path + "'");
  }
  return read_key_file(FileDescriptor(descriptor), path, true);
}

void write_all(int descriptor, std::string_view contents,
               std::string_view path) {
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const auto count =
        ::write(descriptor, contents.data() + offset, contents.size() - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      throw_system_error("cannot write host key '" + std::string(path) + "'");
    }
    if (count == 0) {
      throw std::runtime_error("short write while creating host key: " +
                               std::string(path));
    }
    offset += static_cast<std::size_t>(count);
  }
}

[[nodiscard]] std::string random_suffix() {
  std::array<unsigned char, 16> bytes{};
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count =
        ::getrandom(bytes.data() + offset, bytes.size() - offset, 0);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      throw_system_error("cannot obtain randomness for opaque identifier");
    }
    if (count == 0) {
      throw std::runtime_error("no randomness returned for opaque identifier");
    }
    offset += static_cast<std::size_t>(count);
  }

  constexpr std::string_view digits = "0123456789abcdef";
  std::string suffix;
  suffix.reserve(bytes.size() * 2U);
  for (const auto byte : bytes) {
    suffix.push_back(digits[byte >> 4U]);
    suffix.push_back(digits[byte & 0x0fU]);
  }
  return suffix;
}

[[nodiscard]] std::string random_uuid() {
  auto compact = random_suffix();
  compact[12] = '4';
  compact[16] = '8';
  std::string uuid;
  uuid.reserve(36);
  uuid.append(compact, 0, 8);
  uuid.push_back('-');
  uuid.append(compact, 8, 4);
  uuid.push_back('-');
  uuid.append(compact, 12, 4);
  uuid.push_back('-');
  uuid.append(compact, 16, 4);
  uuid.push_back('-');
  uuid.append(compact, 20, 12);
  return uuid;
}

[[nodiscard]] std::string generate_ed25519_host_key() {
  ssh_key raw_key = nullptr;
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 12, 0)
  const auto generated =
      ssh_pki_generate_key(SSH_KEYTYPE_ED25519, nullptr, &raw_key);
#else
  const auto generated = ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &raw_key);
#endif
  UniqueKey key(raw_key);
  if (generated != SSH_OK || !key) {
    throw std::runtime_error("cannot generate Ed25519 host key");
  }

  char *raw_export = nullptr;
  if (ssh_pki_export_privkey_base64(key.get(), nullptr, nullptr, nullptr,
                                    &raw_export) != SSH_OK ||
      raw_export == nullptr) {
    throw std::runtime_error("cannot export generated Ed25519 host key");
  }
  UniqueExportedKey exported(raw_export);
  return std::string(exported.get());
}

[[nodiscard]] std::string load_or_create_host_key(const std::string &path) {
  const std::filesystem::path key_path(path);
  const auto filename = key_path.filename().string();
  if (filename.empty() || filename == "." || filename == "..") {
    throw std::runtime_error("host key path must name a file: " + path);
  }
  auto parent = key_path.parent_path();
  if (parent.empty()) {
    parent = ".";
  }

  const auto directory_descriptor =
      ::open(parent.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY);
  if (directory_descriptor < 0) {
    throw_system_error("cannot open host key directory '" + parent.string() +
                       "'");
  }
  FileDescriptor directory(directory_descriptor);

  const auto existing =
      ::openat(directory.get(), filename.c_str(),
               O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (existing >= 0) {
    return read_key_file(FileDescriptor(existing), path, true);
  }
  if (errno != ENOENT) {
    throw_system_error("cannot open key file '" + path + "'");
  }

  auto generated = generate_ed25519_host_key();
  const auto temporary_name = "." + filename + ".tmp." + random_suffix();
  const auto temporary_descriptor = ::openat(
      directory.get(), temporary_name.c_str(),
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
  if (temporary_descriptor < 0) {
    clear_secret(generated.data(), generated.size());
    throw_system_error("cannot create temporary host key in '" +
                       parent.string() + "'");
  }
  FileDescriptor temporary(temporary_descriptor);
  TemporaryDirectoryEntry temporary_entry(directory.get(), temporary_name);

  try {
    if (::fchmod(temporary.get(), S_IRUSR | S_IWUSR) != 0) {
      throw_system_error("cannot set permissions on temporary host key");
    }
    write_all(temporary.get(), generated, path);
    if (::fsync(temporary.get()) != 0) {
      throw_system_error("cannot flush temporary host key");
    }

    if (::linkat(directory.get(), temporary_name.c_str(), directory.get(),
                 filename.c_str(), 0) != 0) {
      if (errno != EEXIST) {
        throw_system_error("cannot publish host key '" + path + "'");
      }
      temporary_entry.remove();
      clear_secret(generated.data(), generated.size());
      return read_host_key_at(directory.get(), filename, path);
    }

    temporary_entry.remove();
    if (::fsync(directory.get()) != 0) {
      throw_system_error("cannot flush host key directory '" + parent.string() +
                         "'");
    }
    return generated;
  } catch (...) {
    clear_secret(generated.data(), generated.size());
    throw;
  }
}

[[nodiscard]] std::pair<std::string_view, std::string_view>
public_key_tokens(const std::string &contents, const std::string &path) {
  const auto newline = contents.find('\n');
  const auto first_line = std::string_view(contents).substr(0, newline);
  if (newline != std::string::npos) {
    const auto remainder = std::string_view(contents).substr(newline + 1U);
    if (remainder.find_first_not_of(" \t\r\n") != std::string_view::npos) {
      throw std::runtime_error(
          "authorized key file must contain exactly one key: " + path);
    }
  }

  constexpr auto whitespace = " \t\r";
  const auto type_begin = first_line.find_first_not_of(whitespace);
  if (type_begin == std::string_view::npos) {
    throw std::runtime_error("authorized key file is empty: " + path);
  }
  const auto type_end = first_line.find_first_of(whitespace, type_begin);
  if (type_end == std::string_view::npos) {
    throw std::runtime_error("authorized key file is missing key data: " +
                             path);
  }
  const auto data_begin = first_line.find_first_not_of(whitespace, type_end);
  if (data_begin == std::string_view::npos) {
    throw std::runtime_error("authorized key file is missing key data: " +
                             path);
  }
  const auto data_end = first_line.find_first_of(whitespace, data_begin);
  return {first_line.substr(type_begin, type_end - type_begin),
          first_line.substr(data_begin, data_end - data_begin)};
}

[[nodiscard]] AuthorizedKey
load_authorized_key(const AuthorizedKeySpec &specification) {
  const auto contents = read_key_file(specification.path, false);
  const auto [type_name, encoded] =
      public_key_tokens(contents, specification.path);
  const std::string type_string(type_name);
  const auto type = ssh_key_type_from_name(type_string.c_str());
  if (type == SSH_KEYTYPE_UNKNOWN) {
    throw std::runtime_error("unsupported public key type in: " +
                             specification.path);
  }

  ssh_key raw_key = nullptr;
  const std::string encoded_string(encoded);
  if (ssh_pki_import_pubkey_base64(encoded_string.c_str(), type, &raw_key) !=
          SSH_OK ||
      raw_key == nullptr) {
    throw std::runtime_error("invalid public key in: " + specification.path);
  }
  return AuthorizedKey{specification.user, UniqueKey(raw_key)};
}

void report_denied_auth_attempt(SessionState &state) noexcept {
  ++state.auth_attempts;
  if (state.worker_report_descriptor < 0) {
    state.auth_report_failed = true;
    state.close_requested = true;
    return;
  }
  const WorkerReport event{.kind = WorkerReportKind::denied_auth,
                           .worker = ::getpid(),
                           .telemetry = {}};
  for (;;) {
    const auto count = ::send(state.worker_report_descriptor, &event,
                              sizeof(event), MSG_NOSIGNAL);
    if (count == static_cast<ssize_t>(sizeof(event))) {
      return;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    state.auth_report_failed = true;
    state.close_requested = true;
    return;
  }
}

int authenticate_none(ssh_session, const char *user, void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  const auto remote_user =
      RemoteBytes::from_bounded_c_string(user, max_remote_username_size);
  if (!remote_user || remote_user->text() != "guest") {
    // OpenSSH probes "none" before offering a legitimate public key. Treat it
    // as method discovery, not a failed credential attempt, so normal clients
    // do not consume the per-IP authentication budget.
    return SSH_AUTH_DENIED;
  }
  state.identity =
      SessionIdentity{.kind = IdentityKind::guest, .handle = {}, .key = {}};
  state.authenticated = true;
  state.authenticated_at = Clock::now();
  state.last_activity = state.authenticated_at;
  return SSH_AUTH_SUCCESS;
}

void report_telemetry(int descriptor, std::uint64_t session_id,
                      const SessionTelemetry &telemetry) noexcept {
  const WorkerReport report{.kind = WorkerReportKind::telemetry,
                            .worker = ::getpid(),
                            .session_id = session_id,
                            .telemetry = telemetry};
  ssize_t count = -1;
  do {
    count = ::send(descriptor, &report, sizeof(report), MSG_NOSIGNAL);
  } while (count < 0 && errno == EINTR);
}

int authenticate_public_key(ssh_session, const char *user, ssh_key offered_key,
                            char signature_state, void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  static_cast<void>(user);
  if (state.identity_store == nullptr) {
    state.close_requested = true;
    return SSH_AUTH_DENIED;
  }
  auto key = canonical_public_key(offered_key);
  if (!key) {
    report_denied_auth_attempt(state);
    return SSH_AUTH_DENIED;
  }
  auto identity =
      resolve_public_key(*state.identity_store, *key, state.tos_version);
  if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
    if (identity) {
      return SSH_AUTH_SUCCESS;
    }
    report_denied_auth_attempt(state);
    return SSH_AUTH_DENIED;
  }
  if (signature_state == SSH_PUBLICKEY_STATE_VALID && identity) {
    state.identity = std::move(*identity);
    state.authenticated = true;
    state.authenticated_at = Clock::now();
    state.last_activity = state.authenticated_at;
    return SSH_AUTH_SUCCESS;
  }
  report_denied_auth_attempt(state);
  return SSH_AUTH_DENIED;
}

ssh_channel open_session_channel(ssh_session session, void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  if (!state.authenticated || state.channel != nullptr) {
    return nullptr;
  }
  state.channel = ssh_channel_new(session);
  state.channel_opened_at = Clock::now();
  return state.channel;
}

int request_pty(ssh_session, ssh_channel, const char *terminal_type,
                int columns, int rows, int pixel_width, int pixel_height,
                void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  if (state.pty_requested) {
    const auto dimensions =
        normalize_resize_dimensions(columns, rows, pixel_width, pixel_height);
    if (dimensions) {
      state.columns = dimensions->columns;
      state.rows = dimensions->rows;
      state.pixel_width = dimensions->pixel_width;
      state.pixel_height = dimensions->pixel_height;
      if (state.terminal_session != nullptr) {
        state.terminal_session->post_resize(*dimensions);
      }
    }
    return SSH_OK;
  }
  const auto dimensions =
      normalize_initial_dimensions(columns, rows, pixel_width, pixel_height);
  state.pty_requested = true;
  state.columns = dimensions.columns;
  state.rows = dimensions.rows;
  state.pixel_width = dimensions.pixel_width;
  state.pixel_height = dimensions.pixel_height;
  const auto remote_terminal_type = RemoteBytes::from_bounded_c_string(
      terminal_type, max_remote_terminal_type_size);
  state.terminal_type = remote_terminal_type
                            ? normalize_terminal_type(*remote_terminal_type)
                            : std::string{};
  if (state.terminal_session != nullptr) {
    state.terminal_session->post_resize(dimensions);
  }
  return SSH_OK;
}

int resize_pty(ssh_session, ssh_channel, int columns, int rows, int pixel_width,
               int pixel_height, void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  const auto dimensions =
      normalize_resize_dimensions(columns, rows, pixel_width, pixel_height);
  if (!dimensions) {
    return SSH_OK;
  }
  state.columns = dimensions->columns;
  state.rows = dimensions->rows;
  state.pixel_width = dimensions->pixel_width;
  state.pixel_height = dimensions->pixel_height;
  if (state.terminal_session != nullptr) {
    state.terminal_session->post_resize(*dimensions);
  }
  return SSH_OK;
}

int request_shell(ssh_session, ssh_channel, void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  if (!state.authenticated || state.operation != RequestedOperation::none) {
    return SSH_ERROR;
  }
  state.operation = RequestedOperation::shell;
  state.last_activity = Clock::now();
  state.idle_warning_sent = false;
  return SSH_OK;
}

int request_exec(ssh_session, ssh_channel, const char *, void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  if (state.operation != RequestedOperation::none) {
    return SSH_ERROR;
  }
  state.operation = RequestedOperation::exec;
  // Accept the channel request only far enough to return Anvil's explicit
  // refusal and exit status. No command is parsed or executed.
  return SSH_OK;
}

int request_subsystem(ssh_session, ssh_channel, const char *, void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  if (state.operation != RequestedOperation::none) {
    return SSH_ERROR;
  }
  state.operation = RequestedOperation::subsystem;
  return SSH_OK;
}

int receive_data(ssh_session, ssh_channel, void *data, std::uint32_t length,
                 int is_stderr, void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  if (length > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) {
    state.close_requested = true;
    return SSH_ERROR;
  }
  if (is_stderr != 0 || state.operation != RequestedOperation::shell ||
      length == 0U) {
    return static_cast<int>(length);
  }
  const auto remote_input = RemoteBytes::from_raw(data, length);
  if (!remote_input || !append_remote_bytes(state.pending_input, *remote_input,
                                            max_pending_input)) {
    state.close_requested = true;
    return remote_input ? static_cast<int>(length) : SSH_ERROR;
  }
  state.last_activity = Clock::now();
  state.idle_warning_sent = false;
  if (state.terminal_session != nullptr) {
    state.terminal_session->post_notice({});
  }
  return static_cast<int>(length);
}

void receive_eof(ssh_session, ssh_channel, void *userdata) {
  static_cast<SessionState *>(userdata)->input_eof = true;
}

void receive_close(ssh_session, ssh_channel, void *userdata) {
  static_cast<SessionState *>(userdata)->close_requested = true;
}

[[nodiscard]] bool write_channel(ssh_channel channel, const void *data,
                                 std::size_t length,
                                 bool standard_error = false) {
  const auto *bytes = static_cast<const std::byte *>(data);
  std::size_t offset = 0;
  while (offset < length) {
    const auto chunk = static_cast<std::uint32_t>(std::min<std::size_t>(
        length - offset,
        static_cast<std::size_t>(std::numeric_limits<int>::max())));
    const int count =
        standard_error
            ? ssh_channel_write_stderr(channel, bytes + offset, chunk)
            : ssh_channel_write(channel, bytes + offset, chunk);
    if (count <= 0) {
      return false;
    }
    offset += static_cast<std::size_t>(count);
  }
  return true;
}

void close_channel(ssh_channel channel, int status) {
  if (channel == nullptr) {
    return;
  }
  static_cast<void>(ssh_channel_request_send_exit_status(channel, status));
  static_cast<void>(ssh_channel_send_eof(channel));
  static_cast<void>(ssh_channel_close(channel));
}

void await_peer_channel_close(ssh_event event, ssh_session session,
                              SessionState &state) {
  const auto deadline = Clock::now() + 500ms;
  while (!state.close_requested && ssh_is_connected(session) != 0 &&
         Clock::now() < deadline) {
    if (ssh_event_dopoll(event, 10) == SSH_ERROR) {
      break;
    }
  }
}

[[nodiscard]] bool forward_session_input(int descriptor,
                                         std::vector<std::byte> &pending) {
  while (!pending.empty()) {
    const auto count =
        ::send(descriptor, pending.data(), pending.size(), MSG_NOSIGNAL);
    if (count > 0) {
      pending.erase(pending.begin(), pending.begin() + count);
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return true;
    }
    return false;
  }
  return true;
}

[[nodiscard]] bool forward_session_output(int descriptor, ssh_channel channel,
                                          std::span<std::byte> buffer,
                                          bool discard = false) {
  for (;;) {
    const auto count = ::recv(descriptor, buffer.data(), buffer.size(), 0);
    if (count > 0) {
      if (!discard && !write_channel(channel, buffer.data(),
                                     static_cast<std::size_t>(count))) {
        return false;
      }
      continue;
    }
    if (count == 0) {
      return true;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return true;
    }
    return false;
  }
}

[[nodiscard]] bool worker_shutdown_requested(int signal_descriptor) {
  bool requested = false;
  for (;;) {
    signalfd_siginfo signal_info{};
    const auto count =
        ::read(signal_descriptor, &signal_info, sizeof(signal_info));
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return requested;
    }
    if (count != static_cast<ssize_t>(sizeof(signal_info))) {
      return true;
    }
    if (signal_info.ssi_signo == SIGINT || signal_info.ssi_signo == SIGTERM) {
      requested = true;
    }
  }
}

enum class SessionEnd { normal, idle_timeout, resource_limit, shutdown };

class CpuProgressWatchdog {
public:
  explicit CpuProgressWatchdog(std::chrono::nanoseconds burst)
      : burst_(burst) {}

  [[nodiscard]] bool exceeded(SessionCpuProgress progress) noexcept {
    if (!progress.ready) {
      return false;
    }
    if (!ready_ || progress.generation != generation_ ||
        progress.consumed < baseline_) {
      ready_ = true;
      generation_ = progress.generation;
      baseline_ = progress.consumed;
      return false;
    }
    return progress.consumed - baseline_ > burst_;
  }

private:
  std::chrono::nanoseconds burst_;
  std::chrono::nanoseconds baseline_{};
  std::uint64_t generation_{};
  bool ready_{};
};

[[nodiscard]] std::string_view
failure_reason_name(SessionFailureReason reason) noexcept {
  switch (reason) {
  case SessionFailureReason::none:
    return "none";
  case SessionFailureReason::app_returned_failure:
    return "terminal application returned failure";
  case SessionFailureReason::standard_exception:
    return "standard exception escaped terminal session";
  case SessionFailureReason::unknown_exception:
    return "unknown exception escaped terminal session";
  case SessionFailureReason::memory_limit:
    return "session memory limit exceeded";
  case SessionFailureReason::output_limit:
    return "session output limit exceeded";
  case SessionFailureReason::image_limit:
    return "session terminal image quota exceeded";
  }
  return "unknown terminal session failure";
}

int run_session(ssh_session session, store::Store &identity_store,
                const Config &config, const TosPolicy &tos_policy,
                int signal_descriptor, int worker_report_descriptor,
                int guest_report_permit_descriptor, std::uint64_t session_id) {
  SessionState state;
  state.identity_store = &identity_store;
  state.tos_version = tos_policy.version;
  state.max_auth_attempts = config.max_auth_attempts_per_session;
  state.worker_report_descriptor = worker_report_descriptor;
  state.pending_input.reserve(4096);

  ssh_server_callbacks_struct server_callbacks{};
  server_callbacks.userdata = &state;
  server_callbacks.auth_none_function = authenticate_none;
  server_callbacks.auth_pubkey_function = authenticate_public_key;
  server_callbacks.channel_open_request_session_function = open_session_channel;
  ssh_callbacks_init(&server_callbacks);

  if (ssh_set_server_callbacks(session, &server_callbacks) != SSH_OK) {
    std::cerr << "anvil: cannot install SSH server callbacks\n";
    return 1;
  }
  static_cast<void>(ssh_set_auth_methods(
      session, SSH_AUTH_METHOD_NONE | SSH_AUTH_METHOD_PUBLICKEY));

  timeval timeout{.tv_sec = authentication_timeout.count(), .tv_usec = 0};
  const auto socket = ssh_get_fd(session);
  static_cast<void>(
      ::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
  static_cast<void>(
      ::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));

  if (ssh_handle_key_exchange(session) != SSH_OK) {
    std::cerr << "anvil: key exchange failed: " << ssh_get_error(session)
              << '\n';
    return 1;
  }

  UniqueEvent event(ssh_event_new());
  if (!event || ssh_event_add_session(event.get(), session) != SSH_OK) {
    std::cerr << "anvil: cannot create session event loop\n";
    return 1;
  }

  ssh_channel_callbacks_struct channel_callbacks{};
  channel_callbacks.userdata = &state;
  channel_callbacks.channel_data_function = receive_data;
  channel_callbacks.channel_eof_function = receive_eof;
  channel_callbacks.channel_close_function = receive_close;
  channel_callbacks.channel_pty_request_function = request_pty;
  channel_callbacks.channel_pty_window_change_function = resize_pty;
  channel_callbacks.channel_shell_request_function = request_shell;
  channel_callbacks.channel_exec_request_function = request_exec;
  channel_callbacks.channel_subsystem_request_function = request_subsystem;
  ssh_callbacks_init(&channel_callbacks);

  const auto authentication_deadline = Clock::now() + authentication_timeout;
  bool denial_sent = false;
  bool application_failed = false;
  std::optional<Clock::time_point> input_eof_at;
  FileDescriptor application_descriptor;
  FileDescriptor server_descriptor;
  std::unique_ptr<TerminalSession> terminal_session;
  std::optional<WorkerMemoryGuard> memory_guard;
  CpuProgressWatchdog cpu_watchdog(config.session_resources.cpu_burst);
  std::vector<std::byte> session_output_buffer(16U * 1024U);
  SessionTelemetry reported_telemetry;
  auto session_end = SessionEnd::normal;
  auto resource_limit = ResourceLimitReason::none;
  bool force_worker_exit = false;

  while (ssh_is_connected(session) != 0 && !state.close_requested) {
    if (ssh_event_dopoll(event.get(), terminal_session ? 10 : 100) ==
        SSH_ERROR) {
      break;
    }
    if (worker_shutdown_requested(signal_descriptor)) {
      session_end = SessionEnd::shutdown;
      break;
    }
    const auto now = Clock::now();
    if (!state.authenticated &&
        (state.auth_attempts >= state.max_auth_attempts ||
         now >= authentication_deadline)) {
      break;
    }
    if (state.authenticated) {
      if (now - state.authenticated_at >= config.session_cap) {
        session_end = SessionEnd::resource_limit;
        resource_limit = ResourceLimitReason::duration;
        break;
      }
      if (now - state.last_activity >= config.idle_timeout) {
        session_end = SessionEnd::idle_timeout;
        break;
      }
    }

    if (state.channel != nullptr && !state.channel_callbacks_installed) {
      if (ssh_set_channel_callbacks(state.channel, &channel_callbacks) !=
          SSH_OK) {
        break;
      }
      state.channel_callbacks_installed = true;
    }
    if (state.channel == nullptr) {
      continue;
    }

    if ((state.operation == RequestedOperation::exec ||
         state.operation == RequestedOperation::subsystem) &&
        !denial_sent) {
      const std::string_view message =
          state.operation == RequestedOperation::exec
              ? "Anvil does not execute commands.\r\n"
              : "Anvil does not provide SSH subsystems.\r\n";
      static_cast<void>(
          write_channel(state.channel, message.data(), message.size(), true));
      close_channel(state.channel, 126);
      await_peer_channel_close(event.get(), session, state);
      denial_sent = true;
      break;
    }

    if (state.operation == RequestedOperation::shell && !state.pty_requested &&
        !denial_sent) {
      constexpr std::string_view message = "Anvil requires an interactive PTY; "
                                           "omit -T or reconnect with -t.\r\n";
      static_cast<void>(
          write_channel(state.channel, message.data(), message.size(), true));
      close_channel(state.channel, 126);
      await_peer_channel_close(event.get(), session, state);
      denial_sent = true;
      break;
    }

    if (state.operation == RequestedOperation::shell && !terminal_session) {
      std::array<int, 2> descriptors{};
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                       descriptors.data()) != 0) {
        std::cerr << "anvil: cannot create terminal session bridge: "
                  << std::strerror(errno) << '\n';
        break;
      }
      application_descriptor = FileDescriptor(descriptors[0]);
      server_descriptor = FileDescriptor(descriptors[1]);
      try {
        const TerminalDimensions dimensions{
            state.columns, state.rows, state.pixel_width, state.pixel_height};
        terminal_session = std::make_unique<TerminalSession>(
            application_descriptor.get(), state.terminal_type, dimensions,
            state.channel_opened_at, config.session_resources,
            config.registration_mode, config.invite_policy, tos_policy,
            state.identity, *state.identity_store,
            config.session_input_hook_for_testing,
            guest_report_permit_descriptor);
        state.terminal_session = terminal_session.get();
        auto armed =
            WorkerMemoryGuard::arm(config.session_resources.memory_bytes);
        if (!armed) {
          std::cerr << "anvil: cannot arm session memory limit: "
                    << armed.error() << '\n';
          session_end = SessionEnd::resource_limit;
          resource_limit = ResourceLimitReason::memory;
          terminal_session.reset();
          state.terminal_session = nullptr;
          break;
        }
        memory_guard.emplace(std::move(*armed));
        terminal_session->start();
      } catch (const std::exception &error) {
        std::cerr << "anvil: cannot start terminal session: " << error.what()
                  << '\n';
        terminal_session.reset();
        state.terminal_session = nullptr;
        application_descriptor = FileDescriptor();
        server_descriptor = FileDescriptor();
        application_failed = true;
        break;
      }
    }

    if (terminal_session) {
      if (memory_guard && memory_guard->exceeded()) {
        memory_guard->release_emergency_reserve();
        session_end = SessionEnd::resource_limit;
        resource_limit = ResourceLimitReason::memory;
        force_worker_exit = true;
        break;
      }
      if (cpu_watchdog.exceeded(terminal_session->cpu_progress())) {
        if (memory_guard) {
          memory_guard->release_emergency_reserve();
        }
        session_end = SessionEnd::resource_limit;
        resource_limit = ResourceLimitReason::cpu;
        force_worker_exit = true;
        break;
      }
      if (!forward_session_input(server_descriptor.get(),
                                 state.pending_input)) {
        application_failed = true;
        break;
      }
      if (!forward_session_output(server_descriptor.get(), state.channel,
                                  session_output_buffer)) {
        break;
      }
      if (terminal_session->finished()) {
        application_failed = terminal_session->failed();
        if (const auto limit = terminal_session->limit_reason();
            limit != ResourceLimitReason::none) {
          session_end = SessionEnd::resource_limit;
          resource_limit = limit;
        }
        break;
      }
      const auto telemetry = terminal_session->telemetry();
      if (telemetry != reported_telemetry) {
        report_telemetry(worker_report_descriptor, session_id, telemetry);
        reported_telemetry = telemetry;
      }
    }

    if (state.operation == RequestedOperation::shell &&
        !state.idle_warning_sent &&
        now - state.last_activity >=
            config.idle_timeout - config.idle_warning) {
      const auto seconds = config.idle_warning.count();
      const auto warning = "Anvil: idle session will close in " +
                           std::to_string(seconds) +
                           " seconds. Press any key to continue.";
      if (terminal_session) {
        terminal_session->post_notice(warning);
      } else if (!write_channel(state.channel, warning.data(),
                                warning.size())) {
        break;
      }
      state.idle_warning_sent = true;
    }
    if (state.operation == RequestedOperation::shell &&
        (state.input_eof || ssh_channel_is_eof(state.channel) != 0)) {
      if (!input_eof_at) {
        input_eof_at = now;
      }
      if (state.pending_input.empty() && now - *input_eof_at >= 100ms) {
        break;
      }
    }
    if (ssh_channel_is_open(state.channel) == 0) {
      break;
    }
  }

  if (force_worker_exit) {
    const auto telemetry =
        terminal_session ? terminal_session->telemetry() : SessionTelemetry{};
    report_telemetry(worker_report_descriptor, session_id, telemetry);
    std::cerr << "anvil: session " << ::getpid() << " exceeded its "
              << resource_limit_name(resource_limit) << " limit\n";
    if (state.channel != nullptr && ssh_channel_is_open(state.channel) != 0) {
      const auto message = resource_limit_message(resource_limit);
      static_cast<void>(
          write_channel(state.channel, message.data(), message.size()));
      static_cast<void>(ssh_blocking_flush(session, 500));
      close_channel(state.channel, 124);
      await_peer_channel_close(event.get(), session, state);
    }
    std::_Exit(124);
  }

  if (session_end == SessionEnd::resource_limit && memory_guard) {
    memory_guard->release_emergency_reserve();
  }

  if (terminal_session) {
    state.terminal_session = nullptr;
    terminal_session->request_stop();
    const auto drain_deadline = Clock::now() + 2s;
    while (!terminal_session->finished() && Clock::now() < drain_deadline) {
      static_cast<void>(ssh_event_dopoll(event.get(), 10));
      static_cast<void>(forward_session_output(
          server_descriptor.get(), state.channel, session_output_buffer,
          ssh_channel_is_open(state.channel) == 0));
    }
    if (!terminal_session->finished()) {
      server_descriptor = FileDescriptor();
    }
    terminal_session->join();
    if (server_descriptor.get() >= 0) {
      static_cast<void>(forward_session_output(
          server_descriptor.get(), state.channel, session_output_buffer,
          ssh_channel_is_open(state.channel) == 0));
    }
    application_failed = application_failed || terminal_session->failed();
    const auto failure_reason = terminal_session->failure_reason();
    if (failure_reason != SessionFailureReason::none) {
      std::cerr << "anvil: session " << ::getpid()
                << " failed: " << failure_reason_name(failure_reason) << '\n';
    }
    const auto telemetry = terminal_session->telemetry();
    report_telemetry(worker_report_descriptor, session_id, telemetry);
    std::cerr << "anvil: session " << ::getpid()
              << " frames=" << telemetry.frames
              << " accepted=" << telemetry.accepted_frames
              << " cells=" << telemetry.cell_bytes
              << " image-transmit=" << telemetry.image_transmit_bytes
              << " image-edit=" << telemetry.image_edit_bytes
              << " first-frame-ms=" << telemetry.first_frame_latency.count()
              << '\n';
  }

  if (session_end == SessionEnd::resource_limit) {
    std::cerr << "anvil: session " << ::getpid() << " exceeded its "
              << resource_limit_name(resource_limit) << " limit\n";
  }

  if (state.channel != nullptr && ssh_channel_is_open(state.channel) != 0) {
    std::string_view message;
    int status = 0;
    switch (session_end) {
    case SessionEnd::idle_timeout:
      message = "Anvil: session closed after the idle timeout.\r\n";
      status = 124;
      break;
    case SessionEnd::resource_limit:
      message = resource_limit_message(resource_limit);
      status = 124;
      break;
    case SessionEnd::shutdown:
      message = "Anvil: server is shutting down; closing this session.\r\n";
      break;
    case SessionEnd::normal:
      if (application_failed) {
        message =
            "Anvil: this session failed; the board remains available.\r\n";
        status = 1;
      } else {
        status = state.close_requested ? 1 : 0;
      }
      break;
    }
    if (!message.empty()) {
      static_cast<void>(
          write_channel(state.channel, message.data(), message.size()));
    }
    close_channel(state.channel, status);
    await_peer_channel_close(event.get(), session, state);
  }
  static_cast<void>(ssh_event_remove_session(event.get(), session));
  if (state.channel != nullptr) {
    ssh_channel_free(state.channel);
    state.channel = nullptr;
  }
  return state.auth_report_failed ? auth_report_failure_exit : 0;
}

struct ChildState {
  PeerAddress peer;
  std::uint64_t session_id{};
  FileDescriptor guest_report_permit;
};

using ChildMap = std::unordered_map<pid_t, ChildState>;

void service_guest_report_permits(ChildMap &children,
                                  AdmissionController &admission) noexcept {
  for (auto &[worker, child] : children) {
    static_cast<void>(worker);
    for (;;) {
      std::uint8_t request{};
      const auto received =
          ::recv(child.guest_report_permit.get(), &request, sizeof(request), 0);
      if (received < 0 && errno == EINTR) {
        continue;
      }
      if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
      }
      if (received != static_cast<ssize_t>(sizeof(request)) || request != 1U) {
        break;
      }
      const std::uint8_t allowed =
          admission.consume_guest_report(child.peer, Clock::now()) ? 1U : 0U;
      ssize_t sent{};
      do {
        sent = ::send(child.guest_report_permit.get(), &allowed,
                      sizeof(allowed), MSG_NOSIGNAL);
      } while (sent < 0 && errno == EINTR);
      if (sent != static_cast<ssize_t>(sizeof(allowed))) {
        break;
      }
    }
  }
}

void drain_worker_reports(int descriptor, const ChildMap &children,
                          AdmissionController &admission,
                          HealthMonitor &health) {
  for (;;) {
    WorkerReport event{};
    const auto count = ::recv(descriptor, &event, sizeof(event), 0);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return;
    }
    if (count != static_cast<ssize_t>(sizeof(event)) ||
        event.magic != worker_report_magic ||
        event.version != worker_report_version) {
      return;
    }
    const auto child = children.find(event.worker);
    if (child == children.end()) {
      continue;
    }
    if (event.kind == WorkerReportKind::denied_auth) {
      admission.denied_auth_attempt(child->second.peer, Clock::now());
    } else if (event.kind == WorkerReportKind::telemetry &&
               event.session_id == child->second.session_id) {
      health.session_updated(event.session_id, event.worker, event.telemetry);
    }
  }
}

void reap_children(ChildMap &children, AdmissionController &admission,
                   HealthMonitor &health) {
  for (auto iterator = children.begin(); iterator != children.end();) {
    int status = 0;
    const auto child = ::waitpid(iterator->first, &status, WNOHANG);
    if (child == iterator->first) {
      if (WIFSIGNALED(status)) {
        std::cerr << "anvil: session worker " << child
                  << " terminated by signal " << WTERMSIG(status) << '\n';
      }
      const auto now = Clock::now();
      if (WIFEXITED(status) &&
          WEXITSTATUS(status) == auth_report_failure_exit) {
        admission.exhaust_auth_attempts(iterator->second.peer, now);
      }
      admission.release(iterator->second.peer, now);
      health.session_finished(iterator->second.session_id);
      iterator = children.erase(iterator);
      continue;
    }
    if (child < 0 && errno == EINTR) {
      continue;
    }
    ++iterator;
  }
}

[[noreturn]] void
run_scheduled_backup(store::SqliteStore &database, const Config &config,
                     std::span<const int> descriptors_to_close,
                     HealthMonitor &health) {
  health.detach_in_worker();
  for (const auto descriptor : descriptors_to_close) {
    if (descriptor >= 0) {
      static_cast<void>(::close(descriptor));
    }
  }

  auto snapshot = backup::create_snapshot(database, config.host_key_path,
                                          config.backup_directory);
  if (!snapshot) {
    std::cerr << "anvil: scheduled backup failed: " << snapshot.error() << '\n';
    std::_Exit(1);
  }
  auto pruned =
      backup::prune_snapshots(config.backup_directory, config.backup_retention);
  if (!pruned) {
    std::cerr << "anvil: backup " << snapshot->path.string()
              << " succeeded but retention failed: " << pruned.error() << '\n';
    std::_Exit(1);
  }
  std::cerr << "anvil: created scheduled backup " << snapshot->path.string()
            << '\n';
  std::_Exit(0);
}

[[nodiscard]] auto
start_scheduled_backup(store::SqliteStore &database, const Config &config,
                       std::span<const int> descriptors_to_close,
                       HealthMonitor &health) -> pid_t {
  const auto child = ::fork();
  if (child == 0) {
    run_scheduled_backup(database, config, descriptors_to_close, health);
  }
  return child;
}

void reap_scheduled_backup(pid_t &child, HealthMonitor &health) {
  if (child < 0) {
    return;
  }
  int status = 0;
  const auto found = ::waitpid(child, &status, WNOHANG);
  if (found == 0 || (found < 0 && errno == EINTR)) {
    return;
  }
  if (found == child && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    health.set_component(ComponentStatus{
        ComponentKind::storage, ComponentState::ready, "backup", "1", {}});
  } else {
    health.set_component(ComponentStatus{ComponentKind::storage,
                                         ComponentState::failed, "backup", "1",
                                         "last scheduled backup failed"});
  }
  child = -1;
}

void stop_scheduled_backup(pid_t &child) noexcept {
  if (child < 0) {
    return;
  }
  if (::kill(child, SIGTERM) != 0 && errno != ESRCH) {
    std::cerr << "anvil: cannot stop backup worker " << child << ": "
              << std::strerror(errno) << '\n';
  }
  while (::waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
  }
  child = -1;
}

void terminate_children(const ChildMap &children, int signal_number) {
  for (const auto &[child, state] : children) {
    static_cast<void>(state);
    if (::kill(child, signal_number) != 0 && errno != ESRCH) {
      std::cerr << "anvil: cannot signal worker " << child << ": "
                << std::strerror(errno) << '\n';
    }
  }
}

void await_children(ChildMap &children, int signal_descriptor,
                    int worker_report_descriptor,
                    AdmissionController &admission, HealthMonitor &health) {
  terminate_children(children, SIGTERM);
  const auto deadline = Clock::now() + shutdown_timeout;
  while (!children.empty() && Clock::now() < deadline) {
    std::array<pollfd, 2> descriptors{{
        {.fd = signal_descriptor, .events = POLLIN, .revents = 0},
        {.fd = worker_report_descriptor, .events = POLLIN, .revents = 0},
    }};
    static_cast<void>(::poll(descriptors.data(), descriptors.size(), 100));
    if ((descriptors[1].revents & POLLIN) != 0) {
      drain_worker_reports(worker_report_descriptor, children, admission,
                           health);
    }
    if ((descriptors[0].revents & POLLIN) != 0) {
      signalfd_siginfo signal_info{};
      const auto count =
          ::read(signal_descriptor, &signal_info, sizeof(signal_info));
      if (count < 0 && errno != EINTR && errno != EAGAIN &&
          errno != EWOULDBLOCK) {
        std::cerr << "anvil: cannot read child signal: " << std::strerror(errno)
                  << '\n';
      }
    }
    reap_children(children, admission, health);
  }
  if (!children.empty()) {
    terminate_children(children, SIGKILL);
    while (!children.empty()) {
      const auto found = children.begin();
      const auto child = ::waitpid(found->first, nullptr, 0);
      if (child == found->first || (child < 0 && errno == ECHILD)) {
        admission.release(found->second.peer, Clock::now());
        health.session_finished(found->second.session_id);
        children.erase(found);
      } else if (child < 0 && errno != EINTR) {
        break;
      }
    }
  }
}

[[nodiscard]] std::uint16_t parse_port(std::string_view text) {
  if (text.empty()) {
    throw std::runtime_error("port must not be empty");
  }
  unsigned long value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      throw std::runtime_error("port must be a decimal number");
    }
    value = value * 10UL + static_cast<unsigned long>(character - '0');
    if (value > 65535UL) {
      throw std::runtime_error("port must be between 1 and 65535");
    }
  }
  if (value == 0UL) {
    throw std::runtime_error("port must be between 1 and 65535");
  }
  return static_cast<std::uint16_t>(value);
}

[[nodiscard]] std::uint32_t parse_bounded_count(std::string_view text,
                                                std::string_view name,
                                                std::uint32_t maximum) {
  if (text.empty()) {
    throw std::runtime_error(std::string(name) + " must not be empty");
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      throw std::runtime_error(std::string(name) + " must be a decimal number");
    }
    const auto digit = static_cast<std::uint64_t>(character - '0');
    if (value > (maximum - digit) / 10U) {
      throw std::runtime_error(std::string(name) + " must be between 1 and " +
                               std::to_string(maximum));
    }
    value = value * 10U + digit;
  }
  if (value == 0U) {
    throw std::runtime_error(std::string(name) + " must be between 1 and " +
                             std::to_string(maximum));
  }
  return static_cast<std::uint32_t>(value);
}

[[nodiscard]] std::uint32_t parse_session_limit(std::string_view text) {
  return parse_bounded_count(text, "session limit", 4096);
}

[[nodiscard]] std::uint32_t parse_invite_count(std::string_view text) {
  if (text.empty()) {
    throw std::runtime_error("invites per user must not be empty");
  }
  std::uint64_t value = 0;
  constexpr std::uint64_t maximum = 1'000'000;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      throw std::runtime_error("invites per user must be a decimal number");
    }
    const auto digit = static_cast<std::uint64_t>(character - '0');
    if (value > (maximum - digit) / 10U) {
      throw std::runtime_error(
          "invites per user must be between 0 and 1000000");
    }
    value = value * 10U + digit;
  }
  return static_cast<std::uint32_t>(value);
}

[[nodiscard]] std::uint64_t parse_bounded_bytes(std::string_view text,
                                                std::string_view name,
                                                std::uint64_t maximum) {
  if (text.empty()) {
    throw std::runtime_error(std::string(name) + " must not be empty");
  }
  std::uint64_t value = 0U;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      throw std::runtime_error(std::string(name) +
                               " must be a decimal byte count");
    }
    const auto digit = static_cast<std::uint64_t>(character - '0');
    if (value > (maximum - digit) / 10U) {
      throw std::runtime_error(std::string(name) + " must be between 1 and " +
                               std::to_string(maximum));
    }
    value = value * 10U + digit;
  }
  if (value == 0U) {
    throw std::runtime_error(std::string(name) + " must be between 1 and " +
                             std::to_string(maximum));
  }
  return value;
}

[[nodiscard]] std::chrono::seconds parse_duration(std::string_view text,
                                                  std::string_view name);

[[nodiscard]] RateLimit parse_rate_limit(std::string_view text,
                                         std::string_view name) {
  const auto separator = text.find('/');
  if (separator == std::string_view::npos || separator == 0U ||
      separator + 1U >= text.size() ||
      text.find('/', separator + 1U) != std::string_view::npos) {
    throw std::runtime_error(std::string(name) +
                             " must have the form COUNT/PERIOD_SECONDS");
  }
  const auto count = parse_bounded_count(
      text.substr(0, separator), std::string(name) + " count", 1'000'000);
  const auto period = parse_duration(text.substr(separator + 1U),
                                     std::string(name) + " period");
  return RateLimit{count, period};
}

[[nodiscard]] std::chrono::seconds parse_duration(std::string_view text,
                                                  std::string_view name) {
  if (text.empty()) {
    throw std::runtime_error(std::string(name) + " must not be empty");
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      throw std::runtime_error(std::string(name) +
                               " must be a decimal number of seconds");
    }
    value = value * 10U + static_cast<std::uint64_t>(character - '0');
    if (value > std::numeric_limits<std::uint32_t>::max()) {
      throw std::runtime_error(std::string(name) + " is too large");
    }
  }
  if (value == 0U) {
    throw std::runtime_error(std::string(name) + " must be positive");
  }
  return std::chrono::seconds(value);
}

[[nodiscard]] BoardDeclaration parse_board_declaration(std::string_view text,
                                                       bool registered_only) {
  const auto separator = text.find('=');
  if (separator == std::string_view::npos || separator == 0U ||
      separator + 1U >= text.size()) {
    throw std::runtime_error("board declaration must have the form NAME=TITLE");
  }
  const auto name = text.substr(0, separator);
  if (name.size() > 64U) {
    throw std::runtime_error(
        "board name must be a 1 to 64 byte lowercase ASCII slug");
  }
  for (const auto character : name) {
    if (!((character >= 'a' && character <= 'z') ||
          (character >= '0' && character <= '9') || character == '-')) {
      throw std::runtime_error(
          "board name must be a 1 to 64 byte lowercase ASCII slug");
    }
  }
  const auto raw_title = text.substr(separator + 1U);
  if (raw_title.find('\n') != std::string_view::npos ||
      raw_title.find('\r') != std::string_view::npos) {
    throw std::runtime_error("board title must be one line");
  }
  auto title = prepare_user_text_for_ingest(UserTextField::subject,
                                            RemoteBytes::from_text(raw_title));
  if (!title || title->empty()) {
    throw std::runtime_error(
        "board title must contain 1 to 120 graphemes of valid UTF-8");
  }
  return BoardDeclaration{.name = std::string(name),
                          .title = std::move(*title),
                          .registered_only = registered_only};
}

void reconcile_boards(store::Store &database, const Config &config,
                      store::UtcEpochSeconds now) {
  std::vector<BoardDeclaration> declarations = config.boards;
  for (std::size_t index = 0; index < declarations.size(); ++index) {
    for (std::size_t other = index + 1U; other < declarations.size(); ++other) {
      if (declarations[index].name == declarations[other].name) {
        throw std::runtime_error("duplicate board declaration: " +
                                 declarations[index].name);
      }
    }
  }
  if (declarations.empty()) {
    auto read = database.begin(store::TransactionMode::read_only);
    if (!read) {
      throw std::runtime_error("cannot inspect configured boards: " +
                               read.error().detail);
    }
    auto existing = database.list_boards(
        *read, store::BoardReader{.handle = std::nullopt,
                                  .may_read_registered = true});
    if (!existing) {
      throw std::runtime_error("cannot inspect configured boards: " +
                               existing.error().detail);
    }
    if (auto committed = read->commit(); !committed) {
      throw std::runtime_error("cannot finish board inspection: " +
                               committed.error().detail);
    }
    if (!existing->empty()) {
      return;
    }
    declarations.push_back(
        BoardDeclaration{.name = "general", .title = "General"});
  }

  auto write = database.begin(store::TransactionMode::read_write);
  if (!write) {
    throw std::runtime_error("cannot begin board reconciliation: " +
                             write.error().detail);
  }
  for (const auto &declaration : declarations) {
    auto reconciled = database.reconcile_board(
        *write, store::BoardProvision{
                    .board_id = random_uuid(),
                    .name = declaration.name,
                    .title = declaration.title,
                    .visibility = declaration.registered_only
                                      ? store::BoardVisibility::registered_only
                                      : store::BoardVisibility::public_read,
                    .created_at = now});
    if (!reconciled) {
      throw std::runtime_error("cannot reconcile board '" + declaration.name +
                               "': " + reconciled.error().detail);
    }
  }
  if (auto committed = write->commit(); !committed) {
    throw std::runtime_error("cannot commit board reconciliation: " +
                             committed.error().detail);
  }
}

} // namespace

std::string_view usage() noexcept {
  return "usage: anvil --host-key PATH [options]\n"
         "\n"
         "options:\n"
         "  --bind-address ADDRESS   address to listen on (default 127.0.0.1)\n"
         "  --port PORT             TCP port to listen on (default 2222)\n"
         "  --health-bind-address A private HTTP address (default 127.0.0.1)\n"
         "  --health-port PORT      private HTTP port (default 8080)\n"
         "  --database PATH        SQLite database (default anvil.db)\n"
         "  --registration-mode M  open, invite, or closed (default open)\n"
         "  --invites-per-user N   invite balance cap (default 5; 0 disables)\n"
         "  --invite-regeneration-seconds S\n"
         "                          one-credit period (default 2592000)\n"
         "  --invite-expiration-seconds S\n"
         "                          bearer-code lifetime (default 604800)\n"
         "  --notify-inviters-on-moderation on|off (default off)\n"
         "  --tos-version VERSION  opaque current TOS version (required)\n"
         "  --tos-file PATH        UTF-8 TOS text file (required)\n"
         "  --board NAME=TITLE    public board declaration; repeatable\n"
         "  --member-board N=T    registered-only board; repeatable\n"
         "  --backup-directory P  enable snapshots in directory P\n"
         "  --backup-interval-seconds S\n"
         "                          snapshot period (default 86400)\n"
         "  --backup-retention-seconds S\n"
         "                          rolling window (default 604800)\n"
         "  --backup-now PATH      create one snapshot and exit\n"
         "  --restore-backup PATH restore one snapshot and exit\n"
         "  --max-sessions COUNT    concurrent worker limit (default 64)\n"
         "  --max-sessions-per-ip N concurrent worker limit per IP (default "
         "4)\n"
         "  --connection-rate-limit C/S\n"
         "                          connection burst C per S seconds (default "
         "10/10)\n"
         "  --auth-attempt-rate-limit C/S\n"
         "                          denied-auth burst C per S seconds (default "
         "6/60)\n"
         "  --guest-report-rate-limit C/S\n"
         "                          anonymous report burst (default 5/3600)\n"
         "  --max-auth-attempts-per-session N\n"
         "                          denied-auth limit per connection (default "
         "6)\n"
         "  --max-tracked-ips N     bounded limiter state (default 4096)\n"
         "  --idle-timeout-seconds S\n"
         "                          idle limit in seconds (default 300)\n"
         "  --idle-warning-seconds S\n"
         "                          warning lead time in seconds (default 30)\n"
         "  --session-cap-seconds S absolute session limit in seconds (default "
         "86400)\n"
         "  --session-memory-bytes B\n"
         "                          allocation headroom per worker (default "
         "67108864)\n"
         "  --session-cpu-burst-ms M\n"
         "                          uninterrupted CPU burst (default 250)\n"
         "  --session-output-bytes-per-second B\n"
         "                          output rate and one-second burst (default "
         "1000000)\n"
         "  --session-image-bytes B\n"
         "                          resident image payload quota (default "
         "33554432)\n"
         "  --host-key PATH         unencrypted OpenSSH private host key\n"
         "  --authorized-key U=P    bootstrap active user U from public key P; "
         "optional, repeatable\n"
         "  --help                  show this help\n";
}

ParseResult parse_arguments(std::span<const std::string_view> arguments) {
  ParseResult result;
  bool database_explicit = false;
  bool host_key_explicit = false;
  bool backup_interval_explicit = false;
  bool backup_retention_explicit = false;
  bool backup_directory_explicit = false;
  bool registration_mode_explicit = false;
  bool invite_policy_explicit = false;
  bool tos_explicit = false;
  bool board_policy_explicit = false;
  for (std::size_t index = 0; index < arguments.size(); ++index) {
    const auto argument = arguments[index];
    if (argument == "--help") {
      result.show_help = true;
      continue;
    }
    if (argument != "--bind-address" && argument != "--port" &&
        argument != "--health-bind-address" && argument != "--health-port" &&
        argument != "--database" && argument != "--registration-mode" &&
        argument != "--invites-per-user" &&
        argument != "--invite-regeneration-seconds" &&
        argument != "--invite-expiration-seconds" &&
        argument != "--notify-inviters-on-moderation" &&
        argument != "--tos-version" && argument != "--tos-file" &&
        argument != "--board" && argument != "--member-board" &&
        argument != "--backup-directory" &&
        argument != "--backup-interval-seconds" &&
        argument != "--backup-retention-seconds" &&
        argument != "--backup-now" && argument != "--restore-backup" &&
        argument != "--max-sessions" && argument != "--max-sessions-per-ip" &&
        argument != "--connection-rate-limit" &&
        argument != "--auth-attempt-rate-limit" &&
        argument != "--guest-report-rate-limit" &&
        argument != "--max-auth-attempts-per-session" &&
        argument != "--max-tracked-ips" &&
        argument != "--idle-timeout-seconds" &&
        argument != "--idle-warning-seconds" &&
        argument != "--session-cap-seconds" &&
        argument != "--session-memory-bytes" &&
        argument != "--session-cpu-burst-ms" &&
        argument != "--session-output-bytes-per-second" &&
        argument != "--session-image-bytes" && argument != "--host-key" &&
        argument != "--authorized-key") {
      throw std::runtime_error("unknown option: " + std::string(argument));
    }
    if (++index >= arguments.size()) {
      throw std::runtime_error("missing value for " + std::string(argument));
    }
    const auto value = arguments[index];
    if (value.empty()) {
      throw std::runtime_error("empty value for " + std::string(argument));
    }
    if (argument == "--bind-address") {
      result.config.bind_address = value;
    } else if (argument == "--port") {
      result.config.port = parse_port(value);
    } else if (argument == "--health-bind-address") {
      result.config.health_bind_address = value;
    } else if (argument == "--health-port") {
      result.config.health_port = parse_port(value);
    } else if (argument == "--database") {
      result.config.database_path = value;
      database_explicit = true;
    } else if (argument == "--registration-mode") {
      if (value == "open") {
        result.config.registration_mode = RegistrationMode::open;
      } else if (value == "invite") {
        result.config.registration_mode = RegistrationMode::invite;
      } else if (value == "closed") {
        result.config.registration_mode = RegistrationMode::closed;
      } else {
        throw std::runtime_error(
            "registration mode must be open, invite, or closed");
      }
      registration_mode_explicit = true;
    } else if (argument == "--invites-per-user") {
      result.config.invite_policy.per_user = parse_invite_count(value);
      invite_policy_explicit = true;
    } else if (argument == "--invite-regeneration-seconds") {
      result.config.invite_policy.regeneration =
          parse_duration(value, "invite regeneration period");
      invite_policy_explicit = true;
    } else if (argument == "--invite-expiration-seconds") {
      result.config.invite_policy.expiration =
          parse_duration(value, "invite expiration");
      invite_policy_explicit = true;
    } else if (argument == "--notify-inviters-on-moderation") {
      if (value == "on") {
        result.config.invite_policy.notify_inviters_on_moderation = true;
      } else if (value == "off") {
        result.config.invite_policy.notify_inviters_on_moderation = false;
      } else {
        throw std::runtime_error(
            "notify inviters on moderation must be on or off");
      }
      invite_policy_explicit = true;
    } else if (argument == "--tos-version") {
      if (!valid_tos_version(value)) {
        throw std::runtime_error("TOS version must contain 1 to 128 bytes of "
                                 "valid UTF-8 and no controls");
      }
      result.config.tos_version = value;
      tos_explicit = true;
    } else if (argument == "--tos-file") {
      result.config.tos_file = value;
      tos_explicit = true;
    } else if (argument == "--board" || argument == "--member-board") {
      auto declaration =
          parse_board_declaration(value, argument == "--member-board");
      if (std::ranges::any_of(result.config.boards,
                              [&](const BoardDeclaration &existing) {
                                return existing.name == declaration.name;
                              })) {
        throw std::runtime_error("duplicate board declaration: " +
                                 declaration.name);
      }
      result.config.boards.push_back(std::move(declaration));
      board_policy_explicit = true;
    } else if (argument == "--backup-directory") {
      result.config.backup_directory = value;
      backup_directory_explicit = true;
    } else if (argument == "--backup-interval-seconds") {
      result.config.backup_interval = parse_duration(value, "backup interval");
      backup_interval_explicit = true;
    } else if (argument == "--backup-retention-seconds") {
      result.config.backup_retention =
          parse_duration(value, "backup retention");
      backup_retention_explicit = true;
    } else if (argument == "--backup-now") {
      if (result.config.operation != Operation::serve) {
        throw std::runtime_error(
            "backup and restore modes are mutually exclusive");
      }
      result.config.operation = Operation::backup_once;
      result.config.backup_directory = value;
    } else if (argument == "--restore-backup") {
      if (result.config.operation != Operation::serve) {
        throw std::runtime_error(
            "backup and restore modes are mutually exclusive");
      }
      result.config.operation = Operation::restore;
      result.config.restore_snapshot = value;
    } else if (argument == "--max-sessions") {
      result.config.max_sessions = parse_session_limit(value);
    } else if (argument == "--max-sessions-per-ip") {
      result.config.max_sessions_per_ip = parse_session_limit(value);
    } else if (argument == "--connection-rate-limit") {
      result.config.connection_rate =
          parse_rate_limit(value, "connection rate limit");
    } else if (argument == "--auth-attempt-rate-limit") {
      result.config.auth_attempt_rate =
          parse_rate_limit(value, "auth attempt rate limit");
    } else if (argument == "--guest-report-rate-limit") {
      result.config.guest_report_rate =
          parse_rate_limit(value, "guest report rate limit");
      board_policy_explicit = true;
    } else if (argument == "--max-auth-attempts-per-session") {
      result.config.max_auth_attempts_per_session =
          parse_bounded_count(value, "auth attempts per session", 4096);
    } else if (argument == "--max-tracked-ips") {
      result.config.max_tracked_ips =
          parse_bounded_count(value, "tracked IP limit", 65'536);
    } else if (argument == "--idle-timeout-seconds") {
      result.config.idle_timeout = parse_duration(value, "idle timeout");
    } else if (argument == "--idle-warning-seconds") {
      result.config.idle_warning = parse_duration(value, "idle warning");
    } else if (argument == "--session-cap-seconds") {
      result.config.session_cap = parse_duration(value, "session cap");
    } else if (argument == "--session-memory-bytes") {
      result.config.session_resources.memory_bytes =
          parse_bounded_bytes(value, "session memory limit", 1ULL << 40U);
    } else if (argument == "--session-cpu-burst-ms") {
      const auto milliseconds =
          parse_bounded_count(value, "session CPU burst", 60'000U);
      result.config.session_resources.cpu_burst =
          std::chrono::milliseconds(milliseconds);
    } else if (argument == "--session-output-bytes-per-second") {
      result.config.session_resources.output_bytes_per_second =
          parse_bounded_bytes(value, "session output rate", 1'000'000'000U);
    } else if (argument == "--session-image-bytes") {
      result.config.session_resources.image_bytes =
          parse_bounded_bytes(value, "session image quota", 1ULL << 40U);
    } else if (argument == "--host-key") {
      result.config.host_key_path = value;
      host_key_explicit = true;
    } else {
      const auto separator = value.find('=');
      if (separator == std::string_view::npos || separator == 0U ||
          separator + 1U >= value.size()) {
        throw std::runtime_error("authorized key must have the form USER=PATH");
      }
      result.config.authorized_keys.push_back(
          {std::string(value.substr(0, separator)),
           std::string(value.substr(separator + 1U))});
    }
  }
  if (!result.show_help) {
    if (result.config.operation != Operation::serve) {
      if (!database_explicit || !host_key_explicit) {
        throw std::runtime_error("maintenance mode requires explicit "
                                 "--database and --host-key paths");
      }
      if (!result.config.authorized_keys.empty()) {
        throw std::runtime_error(
            "--authorized-key is not valid in backup or restore mode");
      }
      if (registration_mode_explicit) {
        throw std::runtime_error(
            "--registration-mode is not valid in backup or restore mode");
      }
      if (invite_policy_explicit) {
        throw std::runtime_error(
            "invite policy options are not valid in backup or restore mode");
      }
      if (tos_explicit) {
        throw std::runtime_error(
            "TOS options are not valid in backup or restore mode");
      }
      if (board_policy_explicit) {
        throw std::runtime_error(
            "board options are not valid in backup or restore mode");
      }
      if (backup_directory_explicit || backup_interval_explicit ||
          backup_retention_explicit) {
        throw std::runtime_error(
            "scheduled backup options are not valid in maintenance mode");
      }
      return result;
    }
    if ((backup_interval_explicit || backup_retention_explicit) &&
        result.config.backup_directory.empty()) {
      throw std::runtime_error(
          "scheduled backup options require --backup-directory");
    }
    if (result.config.max_sessions_per_ip > result.config.max_sessions) {
      throw std::runtime_error(
          "per-IP session limit must not exceed global session limit");
    }
    if (result.config.max_tracked_ips < result.config.max_sessions) {
      throw std::runtime_error(
          "tracked IP limit must be at least the global session limit");
    }
    if (result.config.idle_warning >= result.config.idle_timeout) {
      throw std::runtime_error(
          "idle warning must be shorter than idle timeout");
    }
    if (result.config.health_port == result.config.port) {
      throw std::runtime_error(
          "health endpoint must use a separate port from SSH");
    }
    if (result.config.host_key_path.empty()) {
      throw std::runtime_error("--host-key is required");
    }
    if (result.config.tos_version.empty() || result.config.tos_file.empty()) {
      throw std::runtime_error(
          "--tos-version and --tos-file are required in serve mode");
    }
  }
  return result;
}

int run(const Config &config) {
  if (config.operation == Operation::restore) {
    auto restored = backup::restore_snapshot(
        config.restore_snapshot, config.database_path, config.host_key_path);
    if (!restored) {
      throw std::runtime_error("cannot restore backup: " + restored.error());
    }
    std::cout << "anvil: restored " << config.restore_snapshot << " to "
              << config.database_path << " with host key "
              << config.host_key_path << '\n';
    return 0;
  }

  if (config.operation == Operation::backup_once) {
    std::error_code status_error;
    if (!std::filesystem::is_regular_file(config.database_path, status_error) ||
        status_error) {
      throw std::runtime_error("database does not exist as a regular file: " +
                               config.database_path);
    }
    auto database = store::SqliteStore::open(config.database_path);
    if (!database) {
      throw std::runtime_error("cannot open database '" + config.database_path +
                               "': " + database.error().detail);
    }
    auto snapshot = backup::create_snapshot(**database, config.host_key_path,
                                            config.backup_directory);
    if (!snapshot) {
      throw std::runtime_error("cannot create backup: " + snapshot.error());
    }
    std::cout << "anvil: created backup " << snapshot->path.string() << '\n';
    return 0;
  }

  const auto tos_policy = load_tos_policy(config);

  auto database = store::SqliteStore::open(config.database_path);
  if (!database) {
    throw std::runtime_error("cannot initialize database '" +
                             config.database_path +
                             "': " + database.error().detail);
  }

  if (ssh_init() != SSH_OK) {
    throw std::runtime_error("libssh initialization failed");
  }
  struct FinalizeSsh {
    ~FinalizeSsh() { ssh_finalize(); }
  } finalize_ssh;

  std::vector<AuthorizedKey> authorized_keys;
  authorized_keys.reserve(config.authorized_keys.size());
  for (const auto &specification : config.authorized_keys) {
    authorized_keys.push_back(load_authorized_key(specification));
  }
  const auto identity_time = store::UtcEpochSeconds{
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count()};
  for (const auto &authorized_key : authorized_keys) {
    auto key = canonical_public_key(authorized_key.key.get());
    if (!key || !bootstrap_active_identity(**database, authorized_key.user,
                                           *key, identity_time)) {
      throw std::runtime_error(
          "cannot import --authorized-key into the identity store");
    }
  }
  reconcile_boards(**database, config, identity_time);
  auto host_key = load_or_create_host_key(config.host_key_path);

  UniqueBind bind(ssh_bind_new());
  if (!bind) {
    throw std::runtime_error("cannot allocate SSH listener");
  }
  const auto port = std::to_string(config.port);
  const bool configured =
      ssh_bind_options_set(bind.get(), SSH_BIND_OPTIONS_BINDADDR,
                           config.bind_address.c_str()) == SSH_OK &&
      ssh_bind_options_set(bind.get(), SSH_BIND_OPTIONS_BINDPORT_STR,
                           port.c_str()) == SSH_OK &&
      ssh_bind_options_set(bind.get(), SSH_BIND_OPTIONS_IMPORT_KEY_STR,
                           host_key.c_str()) == SSH_OK;
  clear_secret(host_key.data(), host_key.size());
  if (!configured) {
    throw std::runtime_error("cannot configure SSH listener: " +
                             std::string(ssh_get_error(bind.get())));
  }
  if (ssh_bind_listen(bind.get()) != SSH_OK) {
    throw std::runtime_error("cannot listen on " + config.bind_address + ':' +
                             port + ": " +
                             std::string(ssh_get_error(bind.get())));
  }

  sigset_t signal_mask;
  if (::sigemptyset(&signal_mask) != 0 ||
      ::sigaddset(&signal_mask, SIGCHLD) != 0 ||
      ::sigaddset(&signal_mask, SIGINT) != 0 ||
      ::sigaddset(&signal_mask, SIGTERM) != 0 ||
      ::sigprocmask(SIG_BLOCK, &signal_mask, nullptr) != 0) {
    throw_system_error("cannot block supervisor signals");
  }
  FileDescriptor signal_descriptor(
      ::signalfd(-1, &signal_mask, SFD_CLOEXEC | SFD_NONBLOCK));
  if (signal_descriptor.get() < 0) {
    throw_system_error("cannot create signal descriptor");
  }

  std::array<int, 2> worker_report_descriptors{};
  if (::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                   worker_report_descriptors.data()) != 0) {
    throw_system_error("cannot create worker-report channel");
  }
  FileDescriptor worker_report_receiver(worker_report_descriptors[0]);
  FileDescriptor worker_report_sender(worker_report_descriptors[1]);

  auto health = HealthMonitor::start(HealthMonitor::Config{
      config.health_bind_address,
      config.health_port,
      config.max_sessions,
      {ssh_bind_get_fd(bind.get()), signal_descriptor.get(),
       worker_report_receiver.get(), worker_report_sender.get()},
  });
  health->set_component(
      ComponentStatus{ComponentKind::storage,
                      ComponentState::ready,
                      "database",
                      std::to_string((*database)->schema_version()),
                      {}});
  if (!config.backup_directory.empty()) {
    health->set_component(ComponentStatus{ComponentKind::storage,
                                          ComponentState::not_configured,
                                          "backup",
                                          "1",
                                          {}});
  }
  health->heartbeat(true);

  AdmissionController admission(
      config.max_sessions, config.max_sessions_per_ip, config.connection_rate,
      config.auth_attempt_rate, config.max_tracked_ips,
      config.guest_report_rate);
  ChildMap children;
  children.reserve(config.max_sessions);
  std::uint64_t next_session_id = 1U;
  pid_t backup_child = -1;
  auto next_backup = Clock::now();

  bool stopping = false;
  bool health_failed = false;
  std::cout << "anvil: listening on " << config.bind_address << ':'
            << config.port << '\n';
  std::cout << "anvil: health listening on " << config.health_bind_address
            << ':' << config.health_port << '\n';
  if (!config.backup_directory.empty()) {
    std::cout << "anvil: backups enabled in " << config.backup_directory
              << " every " << config.backup_interval.count() << " seconds with "
              << config.backup_retention.count()
              << " seconds retention; snapshots contain user content and the "
                 "private host key\n";
  }
  std::cout.flush();

  while (!stopping) {
    reap_scheduled_backup(backup_child, *health);
    const auto now = Clock::now();
    if (!config.backup_directory.empty() && backup_child < 0 &&
        now >= next_backup) {
      const std::array descriptors_to_close{
          ssh_bind_get_fd(bind.get()), signal_descriptor.get(),
          worker_report_receiver.get(), worker_report_sender.get()};
      backup_child = start_scheduled_backup(**database, config,
                                            descriptors_to_close, *health);
      next_backup = now + config.backup_interval;
      if (backup_child < 0) {
        std::cerr << "anvil: cannot start scheduled backup: "
                  << std::strerror(errno) << '\n';
        health->set_component(
            ComponentStatus{ComponentKind::storage, ComponentState::failed,
                            "backup", "1", "cannot start scheduled backup"});
      }
    }
    std::array<pollfd, 3> descriptors{{
        {.fd = ssh_bind_get_fd(bind.get()), .events = POLLIN, .revents = 0},
        {.fd = worker_report_receiver.get(), .events = POLLIN, .revents = 0},
        {.fd = signal_descriptor.get(), .events = POLLIN, .revents = 0},
    }};
    const auto ready = ::poll(descriptors.data(), descriptors.size(), 1000);
    if (ready < 0 && errno == EINTR) {
      continue;
    }
    if (ready < 0) {
      throw_system_error("listener poll failed");
    }

    service_guest_report_permits(children, admission);
    health->heartbeat(!stopping);
    if (!health->alive()) {
      std::cerr << "anvil: health process exited unexpectedly\n";
      health_failed = true;
      stopping = true;
    }

    if ((descriptors[1].revents & POLLIN) != 0) {
      drain_worker_reports(worker_report_receiver.get(), children, admission,
                           *health);
    }
    if ((descriptors[2].revents & POLLIN) != 0) {
      for (;;) {
        signalfd_siginfo signal_info{};
        const auto count =
            ::read(signal_descriptor.get(), &signal_info, sizeof(signal_info));
        if (count < 0 && errno == EINTR) {
          continue;
        }
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          break;
        }
        if (count != static_cast<ssize_t>(sizeof(signal_info))) {
          throw std::runtime_error("short read from signal descriptor");
        }
        if (signal_info.ssi_signo == SIGINT ||
            signal_info.ssi_signo == SIGTERM) {
          stopping = true;
        }
      }
      drain_worker_reports(worker_report_receiver.get(), children, admission,
                           *health);
      reap_children(children, admission, *health);
    }
    if (stopping || (descriptors[0].revents & POLLIN) == 0) {
      continue;
    }

    sockaddr_storage raw_peer{};
    socklen_t raw_peer_size = sizeof(raw_peer);
    FileDescriptor connection(::accept4(ssh_bind_get_fd(bind.get()),
                                        reinterpret_cast<sockaddr *>(&raw_peer),
                                        &raw_peer_size, SOCK_CLOEXEC));
    if (connection.get() < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      std::cerr << "anvil: accept failed: " << std::strerror(errno) << '\n';
      continue;
    }
    const auto raw_peer_bytes = std::as_bytes(std::span{&raw_peer, 1U});
    const auto peer =
        raw_peer_size <= raw_peer_bytes.size()
            ? PeerAddress::from_remote_bytes(
                  RemoteBytes::from_span(raw_peer_bytes.first(raw_peer_size)))
            : std::nullopt;
    if (!peer ||
        admission.admit(*peer, Clock::now()) != AdmissionDecision::allowed) {
      continue;
    }

    UniqueSession session(ssh_new());
    if (!session) {
      std::cerr << "anvil: cannot allocate SSH session\n";
      admission.release(*peer, Clock::now());
      continue;
    }
    const auto accepted_descriptor = connection.release();
    if (ssh_bind_accept_fd(bind.get(), session.get(), accepted_descriptor) !=
        SSH_OK) {
      std::cerr << "anvil: accept failed: " << ssh_get_error(bind.get())
                << '\n';
      if (ssh_get_fd(session.get()) != accepted_descriptor) {
        static_cast<void>(::close(accepted_descriptor));
      }
      admission.release(*peer, Clock::now());
      continue;
    }

    const auto session_id = next_session_id;
    std::array<int, 2> guest_report_descriptors{};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                     guest_report_descriptors.data()) != 0) {
      std::cerr << "anvil: cannot create guest-report permit channel: "
                << std::strerror(errno) << '\n';
      ssh_disconnect(session.get());
      admission.release(*peer, Clock::now());
      continue;
    }
    FileDescriptor guest_report_supervisor(guest_report_descriptors[0]);
    FileDescriptor guest_report_worker(guest_report_descriptors[1]);
    const auto child = ::fork();
    if (child < 0) {
      std::cerr << "anvil: fork failed: " << std::strerror(errno) << '\n';
      ssh_disconnect(session.get());
      admission.release(*peer, Clock::now());
      continue;
    }
    if (child == 0) {
      health->detach_in_worker();
      guest_report_supervisor = FileDescriptor();
      for (auto &[existing_worker, existing] : children) {
        static_cast<void>(existing_worker);
        existing.guest_report_permit = FileDescriptor();
      }
      static_cast<void>(::close(signal_descriptor.get()));
      static_cast<void>(::close(worker_report_receiver.get()));
      bind.reset();
      sigset_t worker_mask;
      if (::sigemptyset(&worker_mask) != 0 ||
          ::sigaddset(&worker_mask, SIGINT) != 0 ||
          ::sigaddset(&worker_mask, SIGTERM) != 0 ||
          ::sigprocmask(SIG_SETMASK, &worker_mask, nullptr) != 0) {
        std::cerr << "anvil: cannot configure worker signals\n";
        std::_Exit(1);
      }
      FileDescriptor worker_signal_descriptor(
          ::signalfd(-1, &worker_mask, SFD_CLOEXEC | SFD_NONBLOCK));
      if (worker_signal_descriptor.get() < 0) {
        std::cerr << "anvil: cannot create worker signal descriptor\n";
        std::_Exit(1);
      }
      const auto exit_status = run_session(
          session.get(), **database, config, tos_policy,
          worker_signal_descriptor.get(), worker_report_sender.get(),
          guest_report_worker.get(), session_id);
      ssh_disconnect(session.get());
      session.reset();
      std::_Exit(exit_status);
    }
    guest_report_worker = FileDescriptor();
    children.emplace(child, ChildState{*peer, session_id,
                                       std::move(guest_report_supervisor)});
    health->session_started(session_id, child);
    ++next_session_id;
    if (next_session_id == 0U) {
      next_session_id = 1U;
    }
    session.reset();
  }

  health->heartbeat(false);
  bind.reset();
  stop_scheduled_backup(backup_child);
  await_children(children, signal_descriptor.get(),
                 worker_report_receiver.get(), admission, *health);
  health->shutdown();
  return health_failed ? 1 : 0;
}

} // namespace anvil::server
