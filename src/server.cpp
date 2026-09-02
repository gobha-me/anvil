#include "server.hpp"

#include <fcntl.h>
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/libssh_version.h>
#include <libssh/server.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/eventfd.h>
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
#include <expected>
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
constexpr int oneliner_retention_changed_exit = 10;
constexpr std::uint32_t worker_report_magic = 0x414E5657U;
constexpr std::uint16_t worker_report_version = 3U;

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

enum class WorkerReportKind : std::uint16_t {
  denied_auth,
  telemetry,
  oneliner_published,
};

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

[[nodiscard]] FileDescriptor open_tos_file(const std::string &path) {
  const auto descriptor =
      ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (descriptor < 0) {
    throw_system_error("cannot open TOS file '" + path + "'");
  }
  return FileDescriptor(descriptor);
}

[[nodiscard]] std::size_t tos_file_size(const FileDescriptor &file,
                                        const std::string &path) {
  struct stat metadata{};
  if (::fstat(file.get(), &metadata) != 0) {
    throw_system_error("cannot inspect TOS file '" + path + "'");
  }
  if (!S_ISREG(metadata.st_mode)) {
    throw std::runtime_error("TOS file is not a regular file: " + path);
  }
  if (metadata.st_size <= 0 ||
      static_cast<std::uintmax_t>(metadata.st_size) > max_tos_file_size) {
    throw std::runtime_error("TOS file must contain 1 to 262144 bytes: " +
                             path);
  }
  return static_cast<std::size_t>(metadata.st_size);
}

[[nodiscard]] std::string read_exact_tos_file(const FileDescriptor &file,
                                              const std::string &path,
                                              std::size_t size) {
  std::string contents(size, '\0');
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const auto count =
        ::read(file.get(), contents.data() + offset, contents.size() - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      throw_system_error("cannot read TOS file '" + path + "'");
    }
    if (count == 0) {
      throw std::runtime_error("TOS file changed while being read: " + path);
    }
    offset += static_cast<std::size_t>(count);
  }
  return contents;
}

void require_tos_eof(const FileDescriptor &file, const std::string &path) {
  char trailing{};
  ssize_t trailing_count = 0;
  do {
    trailing_count = ::read(file.get(), &trailing, 1);
  } while (trailing_count < 0 && errno == EINTR);
  if (trailing_count < 0) {
    throw_system_error("cannot finish reading TOS file '" + path + "'");
  }
  if (trailing_count != 0) {
    throw std::runtime_error("TOS file changed while being read: " + path);
  }
}

void validate_tos_contents(std::string_view contents, const std::string &path) {
  if (contents.find('\0') != std::string::npos) {
    throw std::runtime_error("TOS file contains a NUL byte: " + path);
  }
  if (!is_well_formed_utf8(contents)) {
    throw std::runtime_error("TOS file is not valid UTF-8: " + path);
  }
  const auto display = sanitize_prose_for_render(contents);
  const auto visible = std::ranges::any_of(display, [](const char value) {
    const auto byte = static_cast<unsigned char>(value);
    return byte > 0x20U && byte != 0x7fU;
  });
  if (!visible) {
    throw std::runtime_error("TOS file has no visible text: " + path);
  }
}

[[nodiscard]] TosPolicy load_tos_policy(const Config &config) {
  if (!valid_tos_version(config.tos_version)) {
    throw std::runtime_error(
        "TOS version must contain 1 to 128 bytes of valid UTF-8 and no "
        "controls");
  }
  const auto file = open_tos_file(config.tos_file);
  auto contents = read_exact_tos_file(file, config.tos_file,
                                      tos_file_size(file, config.tos_file));
  require_tos_eof(file, config.tos_file);
  validate_tos_contents(contents, config.tos_file);
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

[[nodiscard]] bool
report_oneliner_published(int descriptor, std::uint64_t session_id) noexcept {
  if (descriptor < 0) {
    return false;
  }
  const WorkerReport report{.kind = WorkerReportKind::oneliner_published,
                            .worker = ::getpid(),
                            .session_id = session_id,
                            .telemetry = {}};
  ssize_t count = -1;
  do {
    count = ::send(descriptor, &report, sizeof(report), MSG_NOSIGNAL);
  } while (count < 0 && errno == EINTR);
  return count == static_cast<ssize_t>(sizeof(report));
}

[[nodiscard]] bool consume_oneliner_notifications(int descriptor) noexcept {
  bool changed = false;
  for (;;) {
    std::uint64_t count{};
    const auto received = ::read(descriptor, &count, sizeof(count));
    if (received == static_cast<ssize_t>(sizeof(count))) {
      changed = true;
      continue;
    }
    if (received < 0 && errno == EINTR) {
      continue;
    }
    return changed;
  }
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

struct SessionOutcome {
  SessionEnd end{SessionEnd::normal};
  ResourceLimitReason resource_limit{ResourceLimitReason::none};
  bool application_failed{};
  bool force_worker_exit{};
};

struct SessionDescriptors {
  int signal;
  int worker_report;
  int guest_report_permit;
  int oneliner_event;
};

class SessionProtocol {
public:
  SessionProtocol(ssh_session session, store::Store &identity_store,
                  const Config &config, const TosPolicy &tos_policy,
                  SessionDescriptors descriptors, std::uint64_t session_id)
      : session_(session), config_(config), tos_policy_(tos_policy),
        descriptors_(descriptors), session_id_(session_id),
        cpu_watchdog_(config.session_resources.cpu_burst),
        session_output_buffer_(std::size_t{16U} * 1024U) {
    state_.identity_store = &identity_store;
    state_.tos_version = tos_policy.version;
    state_.max_auth_attempts = config.max_auth_attempts_per_session;
    state_.worker_report_descriptor = descriptors.worker_report;
    state_.pending_input.reserve(4096);
  }

  ~SessionProtocol() { release_libssh_resources(); }

  SessionProtocol(const SessionProtocol &) = delete;
  auto operator=(const SessionProtocol &) -> SessionProtocol & = delete;

  [[nodiscard]] int run() {
    if (!initialize()) {
      return 1;
    }
    while (session_is_active() && poll_once()) {
    }
    if (outcome_.force_worker_exit) {
      force_worker_exit();
    }
    finish_terminal_session();
    report_resource_limit();
    finish_channel();
    release_libssh_resources();
    return state_.auth_report_failed ? auth_report_failure_exit : 0;
  }

private:
  [[nodiscard]] bool initialize() {
    initialize_server_callbacks();
    if (ssh_set_server_callbacks(session_, &server_callbacks_) != SSH_OK) {
      std::cerr << "anvil: cannot install SSH server callbacks\n";
      return false;
    }
    ssh_set_auth_methods(session_,
                         SSH_AUTH_METHOD_NONE | SSH_AUTH_METHOD_PUBLICKEY);
    configure_authentication_socket_timeout();
    if (ssh_handle_key_exchange(session_) != SSH_OK) {
      std::cerr << "anvil: key exchange failed: " << ssh_get_error(session_)
                << '\n';
      return false;
    }
    event_.reset(ssh_event_new());
    if (!event_ || ssh_event_add_session(event_.get(), session_) != SSH_OK) {
      std::cerr << "anvil: cannot create session event loop\n";
      return false;
    }
    event_registered_ = true;
    initialize_channel_callbacks();
    authentication_deadline_ = Clock::now() + authentication_timeout;
    return true;
  }

  void initialize_server_callbacks() {
    server_callbacks_.userdata = &state_;
    server_callbacks_.auth_none_function = authenticate_none;
    server_callbacks_.auth_pubkey_function = authenticate_public_key;
    server_callbacks_.channel_open_request_session_function =
        open_session_channel;
    server_callbacks_.size = sizeof(server_callbacks_);
  }

  void initialize_channel_callbacks() {
    channel_callbacks_.userdata = &state_;
    channel_callbacks_.channel_data_function = receive_data;
    channel_callbacks_.channel_eof_function = receive_eof;
    channel_callbacks_.channel_close_function = receive_close;
    channel_callbacks_.channel_pty_request_function = request_pty;
    channel_callbacks_.channel_pty_window_change_function = resize_pty;
    channel_callbacks_.channel_shell_request_function = request_shell;
    channel_callbacks_.channel_exec_request_function = request_exec;
    channel_callbacks_.channel_subsystem_request_function = request_subsystem;
    channel_callbacks_.size = sizeof(channel_callbacks_);
  }

  void configure_authentication_socket_timeout() const {
    timeval timeout{.tv_sec = authentication_timeout.count(), .tv_usec = 0};
    const auto socket = ssh_get_fd(session_);
    static_cast<void>(::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                                   sizeof(timeout)));
    static_cast<void>(::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                                   sizeof(timeout)));
  }

  [[nodiscard]] bool session_is_active() const {
    return ssh_is_connected(session_) != 0 && !state_.close_requested;
  }

  [[nodiscard]] bool poll_once() {
    if (ssh_event_dopoll(event_.get(), terminal_session_ ? 10 : 100) ==
        SSH_ERROR) {
      return false;
    }
    if (worker_shutdown_requested(descriptors_.signal)) {
      outcome_.end = SessionEnd::shutdown;
      return false;
    }
    consume_application_notifications();
    const auto now = Clock::now();
    if (!within_lifecycle_limits(now) || !install_channel_callbacks()) {
      return false;
    }
    if (state_.channel == nullptr) {
      return true;
    }
    if (reject_unsupported_operation() || !start_terminal_if_requested() ||
        !service_terminal_session() || !send_idle_warning(now) ||
        input_eof_drained(now)) {
      return false;
    }
    return ssh_channel_is_open(state_.channel) != 0;
  }

  void consume_application_notifications() const {
    if (terminal_session_ &&
        consume_oneliner_notifications(descriptors_.oneliner_event)) {
      terminal_session_->post_oneliners_changed();
    }
  }

  [[nodiscard]] bool within_lifecycle_limits(Clock::time_point now) {
    if (!state_.authenticated) {
      return state_.auth_attempts < state_.max_auth_attempts &&
             now < authentication_deadline_;
    }
    if (now - state_.authenticated_at >= config_.session_cap) {
      set_resource_limit(ResourceLimitReason::duration);
      return false;
    }
    if (now - state_.last_activity >= config_.idle_timeout) {
      outcome_.end = SessionEnd::idle_timeout;
      return false;
    }
    return true;
  }

  [[nodiscard]] bool install_channel_callbacks() {
    if (state_.channel == nullptr || state_.channel_callbacks_installed) {
      return true;
    }
    if (ssh_set_channel_callbacks(state_.channel, &channel_callbacks_) !=
        SSH_OK) {
      return false;
    }
    state_.channel_callbacks_installed = true;
    return true;
  }

  [[nodiscard]] bool reject_unsupported_operation() {
    switch (state_.operation) {
    case RequestedOperation::exec:
      refuse_channel("Anvil does not execute commands.\r\n");
      return true;
    case RequestedOperation::subsystem:
      refuse_channel("Anvil does not provide SSH subsystems.\r\n");
      return true;
    case RequestedOperation::shell:
      if (!state_.pty_requested) {
        refuse_channel("Anvil requires an interactive PTY; omit -T or "
                       "reconnect with -t.\r\n");
        return true;
      }
      return false;
    case RequestedOperation::none:
      return false;
    }
    return false;
  }

  void refuse_channel(std::string_view message) {
    static_cast<void>(
        write_channel(state_.channel, message.data(), message.size(), true));
    close_channel(state_.channel, 126);
    await_peer_channel_close(event_.get(), session_, state_);
  }

  [[nodiscard]] bool start_terminal_if_requested() {
    if (state_.operation != RequestedOperation::shell || terminal_session_) {
      return true;
    }
    std::array<int, 2> descriptors{};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                     descriptors.data()) != 0) {
      const std::error_code error(errno, std::generic_category());
      std::cerr << "anvil: cannot create terminal session bridge: "
                << error.message() << '\n';
      return false;
    }
    application_descriptor_ = FileDescriptor(descriptors[0]);
    server_descriptor_ = FileDescriptor(descriptors[1]);
    return construct_terminal_session();
  }

  [[nodiscard]] bool construct_terminal_session() {
    try {
      const TerminalDimensions dimensions{
          state_.columns, state_.rows, state_.pixel_width, state_.pixel_height};
      terminal_session_ = std::make_unique<TerminalSession>(
          application_descriptor_.get(), state_.terminal_type, dimensions,
          state_.channel_opened_at, config_.session_resources,
          config_.registration_mode, config_.invite_policy, tos_policy_,
          state_.identity, *state_.identity_store, config_.oneliner_policy,
          config_.session_input_hook_for_testing,
          descriptors_.guest_report_permit, report_oneliner_published,
          descriptors_.worker_report, session_id_);
      state_.terminal_session = terminal_session_.get();
      auto armed =
          WorkerMemoryGuard::arm(config_.session_resources.memory_bytes);
      if (!armed) {
        std::cerr << "anvil: cannot arm session memory limit: " << armed.error()
                  << '\n';
        set_resource_limit(ResourceLimitReason::memory);
        terminal_session_.reset();
        state_.terminal_session = nullptr;
        return false;
      }
      memory_guard_.emplace(std::move(*armed));
      terminal_session_->start();
      return true;
    } catch (const std::exception &error) {
      std::cerr << "anvil: cannot start terminal session: " << error.what()
                << '\n';
      terminal_session_.reset();
      state_.terminal_session = nullptr;
      application_descriptor_ = FileDescriptor();
      server_descriptor_ = FileDescriptor();
      outcome_.application_failed = true;
      return false;
    }
  }

  [[nodiscard]] bool service_terminal_session() {
    if (!terminal_session_) {
      return true;
    }
    if (memory_guard_ && memory_guard_->exceeded()) {
      set_forced_resource_limit(ResourceLimitReason::memory);
      return false;
    }
    if (cpu_watchdog_.exceeded(terminal_session_->cpu_progress())) {
      set_forced_resource_limit(ResourceLimitReason::cpu);
      return false;
    }
    if (!forward_session_input(server_descriptor_.get(),
                               state_.pending_input)) {
      outcome_.application_failed = true;
      return false;
    }
    if (!forward_session_output(server_descriptor_.get(), state_.channel,
                                session_output_buffer_)) {
      return false;
    }
    if (terminal_session_->finished()) {
      record_terminal_completion();
      return false;
    }
    report_changed_telemetry();
    return true;
  }

  void record_terminal_completion() {
    outcome_.application_failed = terminal_session_->failed();
    const auto limit = terminal_session_->limit_reason();
    if (limit != ResourceLimitReason::none) {
      set_resource_limit(limit);
    }
  }

  void report_changed_telemetry() {
    const auto telemetry = terminal_session_->telemetry();
    if (telemetry == reported_telemetry_) {
      return;
    }
    report_telemetry(descriptors_.worker_report, session_id_, telemetry);
    reported_telemetry_ = telemetry;
  }

  void set_resource_limit(ResourceLimitReason limit) {
    outcome_.end = SessionEnd::resource_limit;
    outcome_.resource_limit = limit;
  }

  void set_forced_resource_limit(ResourceLimitReason limit) {
    if (memory_guard_) {
      memory_guard_->release_emergency_reserve();
    }
    set_resource_limit(limit);
    outcome_.force_worker_exit = true;
  }

  [[nodiscard]] bool send_idle_warning(Clock::time_point now) {
    if (state_.operation != RequestedOperation::shell ||
        state_.idle_warning_sent ||
        now - state_.last_activity <
            config_.idle_timeout - config_.idle_warning) {
      return true;
    }
    const auto warning = "Anvil: idle session will close in " +
                         std::to_string(config_.idle_warning.count()) +
                         " seconds. Press any key to continue.";
    if (terminal_session_) {
      terminal_session_->post_notice(warning);
    } else if (!write_channel(state_.channel, warning.data(), warning.size())) {
      return false;
    }
    state_.idle_warning_sent = true;
    return true;
  }

  [[nodiscard]] bool input_eof_drained(Clock::time_point now) {
    if (state_.operation != RequestedOperation::shell ||
        (!state_.input_eof && ssh_channel_is_eof(state_.channel) == 0)) {
      return false;
    }
    if (!input_eof_at_) {
      input_eof_at_ = now;
    }
    return state_.pending_input.empty() && now - *input_eof_at_ >= 100ms;
  }

  [[noreturn]] void force_worker_exit() {
    const auto telemetry =
        terminal_session_ ? terminal_session_->telemetry() : SessionTelemetry{};
    report_telemetry(descriptors_.worker_report, session_id_, telemetry);
    std::cerr << "anvil: session " << ::getpid() << " exceeded its "
              << resource_limit_name(outcome_.resource_limit) << " limit\n";
    if (state_.channel != nullptr && ssh_channel_is_open(state_.channel) != 0) {
      const auto message = resource_limit_message(outcome_.resource_limit);
      static_cast<void>(
          write_channel(state_.channel, message.data(), message.size()));
      static_cast<void>(ssh_blocking_flush(session_, 500));
      close_channel(state_.channel, 124);
      await_peer_channel_close(event_.get(), session_, state_);
    }
    std::_Exit(124);
  }

  void finish_terminal_session() {
    if (outcome_.end == SessionEnd::resource_limit && memory_guard_) {
      memory_guard_->release_emergency_reserve();
    }
    if (!terminal_session_) {
      return;
    }
    state_.terminal_session = nullptr;
    terminal_session_->request_stop();
    drain_terminal_output();
    terminal_session_->join();
    forward_final_terminal_output();
    outcome_.application_failed =
        outcome_.application_failed || terminal_session_->failed();
    log_terminal_failure();
    log_final_telemetry();
  }

  void drain_terminal_output() {
    const auto drain_deadline = Clock::now() + 2s;
    while (!terminal_session_->finished() && Clock::now() < drain_deadline) {
      static_cast<void>(ssh_event_dopoll(event_.get(), 10));
      static_cast<void>(forward_session_output(
          server_descriptor_.get(), state_.channel, session_output_buffer_,
          ssh_channel_is_open(state_.channel) == 0));
    }
    if (!terminal_session_->finished()) {
      server_descriptor_ = FileDescriptor();
    }
  }

  void forward_final_terminal_output() {
    if (server_descriptor_.get() < 0) {
      return;
    }
    static_cast<void>(forward_session_output(
        server_descriptor_.get(), state_.channel, session_output_buffer_,
        ssh_channel_is_open(state_.channel) == 0));
  }

  void log_terminal_failure() const {
    const auto reason = terminal_session_->failure_reason();
    if (reason != SessionFailureReason::none) {
      std::cerr << "anvil: session " << ::getpid()
                << " failed: " << failure_reason_name(reason) << '\n';
    }
  }

  void log_final_telemetry() const {
    const auto telemetry = terminal_session_->telemetry();
    report_telemetry(descriptors_.worker_report, session_id_, telemetry);
    std::cerr << "anvil: session " << ::getpid()
              << " frames=" << telemetry.frames
              << " accepted=" << telemetry.accepted_frames
              << " cells=" << telemetry.cell_bytes
              << " image-transmit=" << telemetry.image_transmit_bytes
              << " image-edit=" << telemetry.image_edit_bytes
              << " first-frame-ms=" << telemetry.first_frame_latency.count()
              << '\n';
  }

  void report_resource_limit() const {
    if (outcome_.end == SessionEnd::resource_limit) {
      std::cerr << "anvil: session " << ::getpid() << " exceeded its "
                << resource_limit_name(outcome_.resource_limit) << " limit\n";
    }
  }

  void finish_channel() {
    if (state_.channel == nullptr || ssh_channel_is_open(state_.channel) == 0) {
      return;
    }
    const auto [message, status] = channel_close_result();
    if (!message.empty()) {
      static_cast<void>(
          write_channel(state_.channel, message.data(), message.size()));
    }
    close_channel(state_.channel, status);
    await_peer_channel_close(event_.get(), session_, state_);
  }

  [[nodiscard]] auto channel_close_result() const
      -> std::pair<std::string_view, int> {
    switch (outcome_.end) {
    case SessionEnd::idle_timeout:
      return {"Anvil: session closed after the idle timeout.\r\n", 124};
    case SessionEnd::resource_limit:
      return {resource_limit_message(outcome_.resource_limit), 124};
    case SessionEnd::shutdown:
      return {"Anvil: server is shutting down; closing this session.\r\n", 0};
    case SessionEnd::normal:
      if (outcome_.application_failed) {
        return {"Anvil: this session failed; the board remains available.\r\n",
                1};
      }
      return {{}, state_.close_requested ? 1 : 0};
    }
    return {{}, 1};
  }

  void release_libssh_resources() {
    if (event_registered_) {
      ssh_event_remove_session(event_.get(), session_);
      event_registered_ = false;
    }
    if (state_.channel != nullptr) {
      ssh_channel_free(state_.channel);
      state_.channel = nullptr;
    }
  }

  ssh_session session_;
  const Config &config_;
  const TosPolicy &tos_policy_;
  SessionDescriptors descriptors_;
  std::uint64_t session_id_;
  SessionState state_;
  ssh_server_callbacks_struct server_callbacks_{};
  ssh_channel_callbacks_struct channel_callbacks_{};
  UniqueEvent event_;
  bool event_registered_{};
  Clock::time_point authentication_deadline_{};
  std::optional<Clock::time_point> input_eof_at_;
  FileDescriptor application_descriptor_;
  FileDescriptor server_descriptor_;
  std::unique_ptr<TerminalSession> terminal_session_;
  std::optional<WorkerMemoryGuard> memory_guard_;
  CpuProgressWatchdog cpu_watchdog_;
  std::vector<std::byte> session_output_buffer_;
  SessionTelemetry reported_telemetry_;
  SessionOutcome outcome_;
};

[[gnu::noinline]] int
run_session(ssh_session session, store::Store &identity_store,
            const Config &config, const TosPolicy &tos_policy,
            int signal_descriptor, int worker_report_descriptor,
            int guest_report_permit_descriptor, int oneliner_event_descriptor,
            std::uint64_t session_id) {
  auto protocol = std::make_unique<SessionProtocol>(
      session, identity_store, config, tos_policy,
      SessionDescriptors{signal_descriptor, worker_report_descriptor,
                         guest_report_permit_descriptor,
                         oneliner_event_descriptor},
      session_id);
  return protocol->run();
}

struct ChildState {
  PeerAddress peer;
  std::uint64_t session_id{};
  FileDescriptor guest_report_permit;
  FileDescriptor oneliner_event;
};

using ChildMap = std::unordered_map<pid_t, ChildState>;

struct SupervisorState {
  std::uint64_t next_session_id{1U};
  pid_t backup_child{-1};
  pid_t oneliner_retention_child{-1};
  Clock::time_point next_backup{Clock::now()};
  Clock::time_point next_oneliner_retention{Clock::now() + 60s};
  bool stopping{};
  bool health_failed{};
};

[[nodiscard]] bool receive_guest_report_request(int descriptor) noexcept {
  std::uint8_t request{};
  ssize_t received = -1;
  for (;;) {
    received = ::recv(descriptor, &request, sizeof(request), 0);
    if (received >= 0 || errno != EINTR) {
      break;
    }
  }
  return std::cmp_equal(received, sizeof(request)) && request == 1U;
}

[[nodiscard]] bool send_guest_report_permit(int descriptor,
                                            bool permitted) noexcept {
  const std::uint8_t response = permitted ? 1U : 0U;
  ssize_t sent = -1;
  for (;;) {
    sent = ::send(descriptor, &response, sizeof(response), MSG_NOSIGNAL);
    if (sent >= 0 || errno != EINTR) {
      break;
    }
  }
  return std::cmp_equal(sent, sizeof(response));
}

void service_guest_report_permits(ChildState &child,
                                  AdmissionController &admission) noexcept {
  while (receive_guest_report_request(child.guest_report_permit.get())) {
    if (!send_guest_report_permit(
            child.guest_report_permit.get(),
            admission.consume_guest_report(child.peer, Clock::now()))) {
      return;
    }
  }
}

void service_guest_report_permits(ChildMap &children,
                                  AdmissionController &admission) noexcept {
  for (auto &[worker, child] : children) {
    static_cast<void>(worker);
    service_guest_report_permits(child, admission);
  }
}

void notify_oneliner_workers(ChildMap &children,
                             std::optional<pid_t> excluded = std::nullopt) {
  constexpr std::uint64_t changed = 1U;
  for (auto &[worker, recipient] : children) {
    if (excluded && worker == *excluded) {
      continue;
    }
    ssize_t written = -1;
    do {
      written =
          ::write(recipient.oneliner_event.get(), &changed, sizeof(changed));
    } while (written < 0 && errno == EINTR);
    if (written < 0 && errno == EAGAIN) {
      continue;
    }
    if (written != static_cast<ssize_t>(sizeof(changed))) {
      std::cerr << "anvil: cannot notify session worker " << worker
                << " of a one-liner change\n";
    }
  }
}

void drain_worker_reports(int descriptor, ChildMap &children,
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
    } else if (event.kind == WorkerReportKind::oneliner_published &&
               event.session_id == child->second.session_id) {
      notify_oneliner_workers(children, event.worker);
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

[[nodiscard]] auto purge_expired_oneliners(store::Store &database,
                                           const store::OnelinerPolicy &policy,
                                           store::UtcEpochSeconds now)
    -> std::expected<std::uint64_t, store::Error> {
  auto write = database.begin(store::TransactionMode::read_write);
  if (!write) {
    return std::unexpected(write.error());
  }
  auto purged = database.purge_expired_oneliners(*write, now, policy);
  if (!purged) {
    return std::unexpected(purged.error());
  }
  auto committed = write->commit();
  if (!committed) {
    return std::unexpected(committed.error());
  }
  return *purged;
}

[[gnu::noinline]] void
purge_expired_oneliners_at_startup(store::Store &database,
                                   const store::OnelinerPolicy &policy) {
  const auto now = store::UtcEpochSeconds{
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count()};
  auto purged = purge_expired_oneliners(database, policy, now);
  if (!purged) {
    throw std::runtime_error("cannot purge expired one-liners: " +
                             purged.error().detail);
  }
}

[[gnu::noinline]] void import_authorized_keys(store::Store &database,
                                              const Config &config,
                                              store::UtcEpochSeconds now) {
  std::vector<AuthorizedKey> authorized_keys;
  authorized_keys.reserve(config.authorized_keys.size());
  for (const auto &specification : config.authorized_keys) {
    authorized_keys.push_back(load_authorized_key(specification));
  }
  for (const auto &authorized_key : authorized_keys) {
    auto key = canonical_public_key(authorized_key.key.get());
    if (!key ||
        !bootstrap_active_identity(database, authorized_key.user, *key, now)) {
      throw std::runtime_error(
          "cannot import --authorized-key into the identity store");
    }
  }
}

[[noreturn]] void
run_oneliner_retention(const Config &config,
                       std::span<const int> descriptors_to_close,
                       const ChildMap &children, HealthMonitor &health) {
  health.detach_in_worker();
  for (const auto descriptor : descriptors_to_close) {
    if (descriptor >= 0) {
      static_cast<void>(::close(descriptor));
    }
  }
  for (const auto &[worker, child] : children) {
    static_cast<void>(worker);
    static_cast<void>(::close(child.guest_report_permit.get()));
    static_cast<void>(::close(child.oneliner_event.get()));
  }
  auto database = store::SqliteStore::open(config.database_path);
  if (!database) {
    std::cerr << "anvil: one-liner retention cannot open database: "
              << database.error().detail << '\n';
    std::_Exit(1);
  }
  const auto now = store::UtcEpochSeconds{
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count()};
  auto purged =
      purge_expired_oneliners(**database, config.oneliner_policy, now);
  if (!purged) {
    std::cerr << "anvil: one-liner retention failed: " << purged.error().detail
              << '\n';
    std::_Exit(1);
  }
  std::_Exit(*purged == 0U ? 0 : oneliner_retention_changed_exit);
}

[[nodiscard]] auto start_oneliner_retention(
    const Config &config, std::span<const int> descriptors_to_close,
    const ChildMap &children, HealthMonitor &health) -> pid_t {
  const auto child = ::fork();
  if (child == 0) {
    run_oneliner_retention(config, descriptors_to_close, children, health);
  }
  return child;
}

[[gnu::noinline]] void reap_oneliner_retention(pid_t &child, ChildMap &children,
                                               HealthMonitor &health) {
  if (child < 0) {
    return;
  }
  int status = 0;
  const auto found = ::waitpid(child, &status, WNOHANG);
  if (found == 0 || (found < 0 && errno == EINTR)) {
    return;
  }
  const auto completed = found == child && WIFEXITED(status);
  const auto exit_status = completed ? WEXITSTATUS(status) : -1;
  if (exit_status == 0 || exit_status == oneliner_retention_changed_exit) {
    if (exit_status == oneliner_retention_changed_exit) {
      notify_oneliner_workers(children);
    }
    health.set_component(ComponentStatus{
        ComponentKind::storage, ComponentState::ready, "oneliners", "1", {}});
  } else {
    health.set_component(ComponentStatus{
        ComponentKind::storage, ComponentState::failed, "oneliners", "1",
        "last one-liner retention pass failed"});
  }
  child = -1;
}

void stop_oneliner_retention(pid_t &child) noexcept {
  if (child < 0) {
    return;
  }
  if (::kill(child, SIGTERM) != 0 && errno != ESRCH) {
    std::cerr << "anvil: cannot stop one-liner retention worker " << child
              << ": " << std::strerror(errno) << '\n';
  }
  while (::waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
  }
  child = -1;
}

[[gnu::noinline]] bool consume_supervisor_signals(int descriptor) {
  bool stopping = false;
  for (;;) {
    signalfd_siginfo signal_info{};
    const auto count = ::read(descriptor, &signal_info, sizeof(signal_info));
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return stopping;
    }
    if (count != static_cast<ssize_t>(sizeof(signal_info))) {
      throw std::runtime_error("short read from signal descriptor");
    }
    if (signal_info.ssi_signo == SIGINT || signal_info.ssi_signo == SIGTERM) {
      stopping = true;
    }
  }
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

[[gnu::noinline]] void await_children(ChildMap &children, int signal_descriptor,
                                      int worker_report_descriptor,
                                      AdmissionController &admission,
                                      HealthMonitor &health) {
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

[[gnu::noinline]] auto configure_supervisor_signals() -> FileDescriptor {
  sigset_t signal_mask;
  if (::sigemptyset(&signal_mask) != 0 ||
      ::sigaddset(&signal_mask, SIGCHLD) != 0 ||
      ::sigaddset(&signal_mask, SIGINT) != 0 ||
      ::sigaddset(&signal_mask, SIGTERM) != 0 ||
      ::sigprocmask(SIG_BLOCK, &signal_mask, nullptr) != 0) {
    throw_system_error("cannot block supervisor signals");
  }
  FileDescriptor descriptor(
      ::signalfd(-1, &signal_mask, SFD_CLOEXEC | SFD_NONBLOCK));
  if (descriptor.get() < 0) {
    throw_system_error("cannot create signal descriptor");
  }
  return descriptor;
}

[[gnu::noinline]] auto configure_worker_signals() noexcept -> FileDescriptor {
  sigset_t worker_mask;
  if (::sigemptyset(&worker_mask) != 0 ||
      ::sigaddset(&worker_mask, SIGINT) != 0 ||
      ::sigaddset(&worker_mask, SIGTERM) != 0 ||
      ::sigprocmask(SIG_SETMASK, &worker_mask, nullptr) != 0) {
    std::cerr << "anvil: cannot configure worker signals\n";
    return FileDescriptor(-1);
  }
  FileDescriptor descriptor(
      ::signalfd(-1, &worker_mask, SFD_CLOEXEC | SFD_NONBLOCK));
  if (descriptor.get() < 0) {
    std::cerr << "anvil: cannot create worker signal descriptor\n";
  }
  return descriptor;
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
    const auto digit = static_cast<std::uint64_t>(character - '0');
    constexpr auto maximum =
        static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max());
    if (value > (maximum - digit) / 10U) {
      throw std::runtime_error(std::string(name) + " is too large");
    }
    value = value * 10U + digit;
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

struct ExplicitOptions {
  bool database{};
  bool host_key{};
  bool backup_interval{};
  bool backup_retention{};
  bool backup_directory{};
  bool registration_mode{};
  bool invite_policy{};
  bool tos{};
  bool board_policy{};
};

struct ArgumentParseState {
  ParseResult result;
  ExplicitOptions explicit_options;
};

enum class OptionId : std::uint8_t {
  help,
  bind_address,
  port,
  health_bind_address,
  health_port,
  database,
  registration_mode,
  invites_per_user,
  invite_regeneration,
  invite_expiration,
  notify_inviters,
  tos_version,
  tos_file,
  board,
  member_board,
  backup_directory,
  backup_interval,
  backup_retention,
  backup_now,
  restore_backup,
  max_sessions,
  max_sessions_per_ip,
  connection_rate_limit,
  auth_attempt_rate_limit,
  guest_report_rate_limit,
  oneliner_rate_limit,
  oneliner_retention,
  max_auth_attempts,
  max_tracked_ips,
  idle_timeout,
  idle_warning,
  session_cap,
  session_memory,
  session_cpu_burst,
  session_output_rate,
  session_image_quota,
  host_key,
  authorized_key,
};

using OptionApplier = void (*)(ArgumentParseState &, OptionId,
                               std::string_view);

struct OptionSpec {
  std::string_view name;
  OptionId id;
  bool takes_value;
  OptionApplier apply;
};

[[nodiscard]] RegistrationMode parse_registration_mode(std::string_view value) {
  if (value == "open") {
    return RegistrationMode::open;
  }
  if (value == "invite") {
    return RegistrationMode::invite;
  }
  if (value == "closed") {
    return RegistrationMode::closed;
  }
  throw std::runtime_error("registration mode must be open, invite, or closed");
}

[[nodiscard]] bool parse_notify_inviters(std::string_view value) {
  if (value == "on") {
    return true;
  }
  if (value == "off") {
    return false;
  }
  throw std::runtime_error("notify inviters on moderation must be on or off");
}

void append_authorized_key(Config &config, std::string_view value) {
  const auto separator = value.find('=');
  if (separator == std::string_view::npos || separator == 0U ||
      separator + 1U >= value.size()) {
    throw std::runtime_error("authorized key must have the form USER=PATH");
  }
  config.authorized_keys.push_back({std::string(value.substr(0, separator)),
                                    std::string(value.substr(separator + 1U))});
}

void append_board(Config &config, std::string_view value,
                  bool registered_only) {
  auto declaration = parse_board_declaration(value, registered_only);
  if (std::ranges::any_of(config.boards, [&](const BoardDeclaration &existing) {
        return existing.name == declaration.name;
      })) {
    throw std::runtime_error("duplicate board declaration: " +
                             declaration.name);
  }
  config.boards.push_back(std::move(declaration));
}

void select_maintenance_operation(Config &config, Operation operation,
                                  std::string_view value) {
  if (config.operation != Operation::serve) {
    throw std::runtime_error("backup and restore modes are mutually exclusive");
  }
  config.operation = operation;
  if (operation == Operation::backup_once) {
    config.backup_directory = value;
    return;
  }
  config.restore_snapshot = value;
}

void apply_help_option(ArgumentParseState &state, OptionId, std::string_view) {
  state.result.show_help = true;
}

void apply_server_option(ArgumentParseState &state, OptionId option,
                         std::string_view value) {
  auto &config = state.result.config;
  switch (option) {
  case OptionId::bind_address:
    config.bind_address = value;
    return;
  case OptionId::port:
    config.port = parse_port(value);
    return;
  case OptionId::health_bind_address:
    config.health_bind_address = value;
    return;
  case OptionId::health_port:
    config.health_port = parse_port(value);
    return;
  case OptionId::database:
    config.database_path = value;
    state.explicit_options.database = true;
    return;
  case OptionId::registration_mode:
    config.registration_mode = parse_registration_mode(value);
    state.explicit_options.registration_mode = true;
    return;
  default:
    std::unreachable();
  }
}

void apply_identity_option(ArgumentParseState &state, OptionId option,
                           std::string_view value) {
  auto &config = state.result.config;
  switch (option) {
  case OptionId::invites_per_user:
    config.invite_policy.per_user = parse_invite_count(value);
    state.explicit_options.invite_policy = true;
    return;
  case OptionId::invite_regeneration:
    config.invite_policy.regeneration =
        parse_duration(value, "invite regeneration period");
    state.explicit_options.invite_policy = true;
    return;
  case OptionId::invite_expiration:
    config.invite_policy.expiration =
        parse_duration(value, "invite expiration");
    state.explicit_options.invite_policy = true;
    return;
  case OptionId::notify_inviters:
    config.invite_policy.notify_inviters_on_moderation =
        parse_notify_inviters(value);
    state.explicit_options.invite_policy = true;
    return;
  case OptionId::tos_version:
    if (!valid_tos_version(value)) {
      throw std::runtime_error("TOS version must contain 1 to 128 bytes of "
                               "valid UTF-8 and no controls");
    }
    config.tos_version = value;
    state.explicit_options.tos = true;
    return;
  case OptionId::tos_file:
    config.tos_file = value;
    state.explicit_options.tos = true;
    return;
  case OptionId::host_key:
    config.host_key_path = value;
    state.explicit_options.host_key = true;
    return;
  case OptionId::authorized_key:
    append_authorized_key(config, value);
    return;
  default:
    std::unreachable();
  }
}

void apply_board_option(ArgumentParseState &state, OptionId option,
                        std::string_view value) {
  auto &config = state.result.config;
  switch (option) {
  case OptionId::board:
  case OptionId::member_board:
    append_board(config, value, option == OptionId::member_board);
    state.explicit_options.board_policy = true;
    return;
  case OptionId::guest_report_rate_limit:
    config.guest_report_rate =
        parse_rate_limit(value, "guest report rate limit");
    state.explicit_options.board_policy = true;
    return;
  case OptionId::oneliner_rate_limit: {
    const auto limit = parse_rate_limit(value, "one-liner rate limit");
    config.oneliner_policy.max_posts = limit.count;
    config.oneliner_policy.window_seconds =
        static_cast<std::uint32_t>(limit.period.count());
    state.explicit_options.board_policy = true;
    return;
  }
  case OptionId::oneliner_retention:
    config.oneliner_policy.retention_seconds = static_cast<std::uint32_t>(
        parse_duration(value, "one-liner retention").count());
    state.explicit_options.board_policy = true;
    return;
  default:
    std::unreachable();
  }
}

void apply_backup_option(ArgumentParseState &state, OptionId option,
                         std::string_view value) {
  auto &config = state.result.config;
  switch (option) {
  case OptionId::backup_directory:
    config.backup_directory = value;
    state.explicit_options.backup_directory = true;
    return;
  case OptionId::backup_interval:
    config.backup_interval = parse_duration(value, "backup interval");
    state.explicit_options.backup_interval = true;
    return;
  case OptionId::backup_retention:
    config.backup_retention = parse_duration(value, "backup retention");
    state.explicit_options.backup_retention = true;
    return;
  case OptionId::backup_now:
    select_maintenance_operation(config, Operation::backup_once, value);
    return;
  case OptionId::restore_backup:
    select_maintenance_operation(config, Operation::restore, value);
    return;
  default:
    std::unreachable();
  }
}

void apply_session_option(ArgumentParseState &state, OptionId option,
                          std::string_view value) {
  auto &config = state.result.config;
  switch (option) {
  case OptionId::max_sessions:
    config.max_sessions = parse_session_limit(value);
    return;
  case OptionId::max_sessions_per_ip:
    config.max_sessions_per_ip = parse_session_limit(value);
    return;
  case OptionId::connection_rate_limit:
    config.connection_rate = parse_rate_limit(value, "connection rate limit");
    return;
  case OptionId::auth_attempt_rate_limit:
    config.auth_attempt_rate =
        parse_rate_limit(value, "auth attempt rate limit");
    return;
  case OptionId::max_auth_attempts:
    config.max_auth_attempts_per_session =
        parse_bounded_count(value, "auth attempts per session", 4096);
    return;
  case OptionId::max_tracked_ips:
    config.max_tracked_ips =
        parse_bounded_count(value, "tracked IP limit", 65'536);
    return;
  case OptionId::idle_timeout:
    config.idle_timeout = parse_duration(value, "idle timeout");
    return;
  case OptionId::idle_warning:
    config.idle_warning = parse_duration(value, "idle warning");
    return;
  case OptionId::session_cap:
    config.session_cap = parse_duration(value, "session cap");
    return;
  default:
    std::unreachable();
  }
}

void apply_resource_option(ArgumentParseState &state, OptionId option,
                           std::string_view value) {
  auto &resources = state.result.config.session_resources;
  switch (option) {
  case OptionId::session_memory:
    resources.memory_bytes =
        parse_bounded_bytes(value, "session memory limit", 1ULL << 40U);
    return;
  case OptionId::session_cpu_burst:
    resources.cpu_burst = std::chrono::milliseconds(
        parse_bounded_count(value, "session CPU burst", 60'000U));
    return;
  case OptionId::session_output_rate:
    resources.output_bytes_per_second =
        parse_bounded_bytes(value, "session output rate", 1'000'000'000U);
    return;
  case OptionId::session_image_quota:
    resources.image_bytes =
        parse_bounded_bytes(value, "session image quota", 1ULL << 40U);
    return;
  default:
    std::unreachable();
  }
}

constexpr std::array option_specs{
    OptionSpec{"--help", OptionId::help, false, apply_help_option},
    OptionSpec{"--bind-address", OptionId::bind_address, true,
               apply_server_option},
    OptionSpec{"--port", OptionId::port, true, apply_server_option},
    OptionSpec{"--health-bind-address", OptionId::health_bind_address, true,
               apply_server_option},
    OptionSpec{"--health-port", OptionId::health_port, true,
               apply_server_option},
    OptionSpec{"--database", OptionId::database, true, apply_server_option},
    OptionSpec{"--registration-mode", OptionId::registration_mode, true,
               apply_server_option},
    OptionSpec{"--invites-per-user", OptionId::invites_per_user, true,
               apply_identity_option},
    OptionSpec{"--invite-regeneration-seconds", OptionId::invite_regeneration,
               true, apply_identity_option},
    OptionSpec{"--invite-expiration-seconds", OptionId::invite_expiration, true,
               apply_identity_option},
    OptionSpec{"--notify-inviters-on-moderation", OptionId::notify_inviters,
               true, apply_identity_option},
    OptionSpec{"--tos-version", OptionId::tos_version, true,
               apply_identity_option},
    OptionSpec{"--tos-file", OptionId::tos_file, true, apply_identity_option},
    OptionSpec{"--board", OptionId::board, true, apply_board_option},
    OptionSpec{"--member-board", OptionId::member_board, true,
               apply_board_option},
    OptionSpec{"--backup-directory", OptionId::backup_directory, true,
               apply_backup_option},
    OptionSpec{"--backup-interval-seconds", OptionId::backup_interval, true,
               apply_backup_option},
    OptionSpec{"--backup-retention-seconds", OptionId::backup_retention, true,
               apply_backup_option},
    OptionSpec{"--backup-now", OptionId::backup_now, true, apply_backup_option},
    OptionSpec{"--restore-backup", OptionId::restore_backup, true,
               apply_backup_option},
    OptionSpec{"--max-sessions", OptionId::max_sessions, true,
               apply_session_option},
    OptionSpec{"--max-sessions-per-ip", OptionId::max_sessions_per_ip, true,
               apply_session_option},
    OptionSpec{"--connection-rate-limit", OptionId::connection_rate_limit, true,
               apply_session_option},
    OptionSpec{"--auth-attempt-rate-limit", OptionId::auth_attempt_rate_limit,
               true, apply_session_option},
    OptionSpec{"--guest-report-rate-limit", OptionId::guest_report_rate_limit,
               true, apply_board_option},
    OptionSpec{"--oneliner-rate-limit", OptionId::oneliner_rate_limit, true,
               apply_board_option},
    OptionSpec{"--oneliner-retention-seconds", OptionId::oneliner_retention,
               true, apply_board_option},
    OptionSpec{"--max-auth-attempts-per-session", OptionId::max_auth_attempts,
               true, apply_session_option},
    OptionSpec{"--max-tracked-ips", OptionId::max_tracked_ips, true,
               apply_session_option},
    OptionSpec{"--idle-timeout-seconds", OptionId::idle_timeout, true,
               apply_session_option},
    OptionSpec{"--idle-warning-seconds", OptionId::idle_warning, true,
               apply_session_option},
    OptionSpec{"--session-cap-seconds", OptionId::session_cap, true,
               apply_session_option},
    OptionSpec{"--session-memory-bytes", OptionId::session_memory, true,
               apply_resource_option},
    OptionSpec{"--session-cpu-burst-ms", OptionId::session_cpu_burst, true,
               apply_resource_option},
    OptionSpec{"--session-output-bytes-per-second",
               OptionId::session_output_rate, true, apply_resource_option},
    OptionSpec{"--session-image-bytes", OptionId::session_image_quota, true,
               apply_resource_option},
    OptionSpec{"--host-key", OptionId::host_key, true, apply_identity_option},
    OptionSpec{"--authorized-key", OptionId::authorized_key, true,
               apply_identity_option},
};

[[nodiscard]] const OptionSpec *find_option(std::string_view name) noexcept {
  const auto found = std::ranges::find(option_specs, name, &OptionSpec::name);
  return found == option_specs.end() ? nullptr : &*found;
}

[[nodiscard]] std::string_view
consume_option_value(std::span<const std::string_view> arguments,
                     std::size_t &index, std::string_view option) {
  if (++index >= arguments.size()) {
    throw std::runtime_error("missing value for " + std::string(option));
  }
  const auto value = arguments[index];
  if (value.empty()) {
    throw std::runtime_error("empty value for " + std::string(option));
  }
  return value;
}

void parse_argument_tokens(ArgumentParseState &state,
                           std::span<const std::string_view> arguments) {
  for (std::size_t index = 0; index < arguments.size(); ++index) {
    const auto argument = arguments[index];
    const auto *spec = find_option(argument);
    if (spec == nullptr) {
      throw std::runtime_error("unknown option: " + std::string(argument));
    }
    if (!spec->takes_value) {
      spec->apply(state, spec->id, {});
      continue;
    }
    spec->apply(state, spec->id,
                consume_option_value(arguments, index, argument));
  }
}

void validate_maintenance_options(const ArgumentParseState &state) {
  const auto &config = state.result.config;
  const auto &explicit_options = state.explicit_options;
  if (!explicit_options.database || !explicit_options.host_key) {
    throw std::runtime_error("maintenance mode requires explicit "
                             "--database and --host-key paths");
  }
  if (!config.authorized_keys.empty()) {
    throw std::runtime_error(
        "--authorized-key is not valid in backup or restore mode");
  }
  if (explicit_options.registration_mode) {
    throw std::runtime_error(
        "--registration-mode is not valid in backup or restore mode");
  }
  if (explicit_options.invite_policy) {
    throw std::runtime_error(
        "invite policy options are not valid in backup or restore mode");
  }
  if (explicit_options.tos) {
    throw std::runtime_error(
        "TOS options are not valid in backup or restore mode");
  }
  if (explicit_options.board_policy) {
    throw std::runtime_error(
        "board options are not valid in backup or restore mode");
  }
  if (explicit_options.backup_directory || explicit_options.backup_interval ||
      explicit_options.backup_retention) {
    throw std::runtime_error(
        "scheduled backup options are not valid in maintenance mode");
  }
}

void validate_serve_options(const ArgumentParseState &state) {
  const auto &config = state.result.config;
  const auto &explicit_options = state.explicit_options;
  if ((explicit_options.backup_interval || explicit_options.backup_retention) &&
      config.backup_directory.empty()) {
    throw std::runtime_error(
        "scheduled backup options require --backup-directory");
  }
  if (config.max_sessions_per_ip > config.max_sessions) {
    throw std::runtime_error(
        "per-IP session limit must not exceed global session limit");
  }
  if (config.max_tracked_ips < config.max_sessions) {
    throw std::runtime_error(
        "tracked IP limit must be at least the global session limit");
  }
  if (config.idle_warning >= config.idle_timeout) {
    throw std::runtime_error("idle warning must be shorter than idle timeout");
  }
  if (config.health_port == config.port) {
    throw std::runtime_error(
        "health endpoint must use a separate port from SSH");
  }
  if (config.host_key_path.empty()) {
    throw std::runtime_error("--host-key is required");
  }
  if (config.tos_version.empty() || config.tos_file.empty()) {
    throw std::runtime_error(
        "--tos-version and --tos-file are required in serve mode");
  }
}

[[nodiscard]] ParseResult finish_argument_parsing(ArgumentParseState state) {
  if (state.result.show_help) {
    return std::move(state.result);
  }
  if (state.result.config.operation == Operation::serve) {
    validate_serve_options(state);
  } else {
    validate_maintenance_options(state);
  }
  return std::move(state.result);
}

void require_unique_board_declarations(
    const std::vector<BoardDeclaration> &declarations) {
  for (std::size_t index = 0; index < declarations.size(); ++index) {
    for (std::size_t other = index + 1U; other < declarations.size(); ++other) {
      if (declarations[index].name == declarations[other].name) {
        throw std::runtime_error("duplicate board declaration: " +
                                 declarations[index].name);
      }
    }
  }
}

[[nodiscard]] bool has_existing_boards(store::Store &database) {
  auto read = database.begin(store::TransactionMode::read_only);
  if (!read) {
    throw std::runtime_error("cannot inspect configured boards: " +
                             read.error().detail);
  }
  auto existing = database.list_boards(
      *read,
      store::BoardReader{.handle = std::nullopt, .may_read_registered = true});
  if (!existing) {
    throw std::runtime_error("cannot inspect configured boards: " +
                             existing.error().detail);
  }
  if (auto committed = read->commit(); !committed) {
    throw std::runtime_error("cannot finish board inspection: " +
                             committed.error().detail);
  }
  return !existing->empty();
}

void write_board_declarations(store::Store &database,
                              const std::vector<BoardDeclaration> &declarations,
                              store::UtcEpochSeconds now) {
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

void reconcile_boards(store::Store &database, const Config &config,
                      store::UtcEpochSeconds now) {
  require_unique_board_declarations(config.boards);
  if (!config.boards.empty()) {
    write_board_declarations(database, config.boards, now);
    return;
  }
  if (has_existing_boards(database)) {
    return;
  }
  const std::vector declarations{
      BoardDeclaration{.name = "general", .title = "General"}};
  write_board_declarations(database, declarations, now);
}

class SshLibrary {
public:
  ~SshLibrary() {
    if (initialized_) {
      ssh_finalize();
    }
  }

  SshLibrary() = default;
  SshLibrary(const SshLibrary &) = delete;
  auto operator=(const SshLibrary &) -> SshLibrary & = delete;

  void initialize() {
    if (ssh_init() != SSH_OK) {
      throw std::runtime_error("libssh initialization failed");
    }
    initialized_ = true;
  }

private:
  bool initialized_{};
};

[[nodiscard]] std::unique_ptr<store::SqliteStore>
open_server_database(const Config &config) {
  auto database = store::SqliteStore::open(config.database_path);
  if (!database) {
    throw std::runtime_error("cannot initialize database '" +
                             config.database_path +
                             "': " + database.error().detail);
  }
  return std::move(*database);
}

[[nodiscard]] UniqueBind create_ssh_listener(const Config &config,
                                             std::string host_key) {
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
  return bind;
}

[[nodiscard]] std::array<FileDescriptor, 2> create_worker_report_channel() {
  std::array<int, 2> descriptors{};
  if (::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                   descriptors.data()) != 0) {
    throw_system_error("cannot create worker-report channel");
  }
  return {FileDescriptor(descriptors[0]), FileDescriptor(descriptors[1])};
}

[[nodiscard]] store::UtcEpochSeconds current_identity_time() {
  return store::UtcEpochSeconds{
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count()};
}

class SupervisorRuntime {
public:
  explicit SupervisorRuntime(const Config &config)
      : config_(config), tos_policy_(load_tos_policy(config)),
        database_(open_server_database(config)),
        admission_(config.max_sessions, config.max_sessions_per_ip,
                   config.connection_rate, config.auth_attempt_rate,
                   config.max_tracked_ips, config.guest_report_rate) {
    initialize();
  }

  ~SupervisorRuntime() { shutdown_noexcept(); }

  SupervisorRuntime(const SupervisorRuntime &) = delete;
  auto operator=(const SupervisorRuntime &) -> SupervisorRuntime & = delete;

  [[nodiscard]] int execute() {
    announce();
    while (!state_.stopping) {
      run_iteration();
    }
    const auto result = state_.health_failed ? 1 : 0;
    shutdown();
    return result;
  }

private:
  void initialize() {
    purge_expired_oneliners_at_startup(*database_, config_.oneliner_policy);
    ssh_.initialize();
    const auto identity_time = current_identity_time();
    import_authorized_keys(*database_, config_, identity_time);
    reconcile_boards(*database_, config_, identity_time);
    bind_ = create_ssh_listener(config_,
                                load_or_create_host_key(config_.host_key_path));
    signal_descriptor_ = configure_supervisor_signals();
    auto worker_reports = create_worker_report_channel();
    worker_report_receiver_ = std::move(worker_reports[0]);
    worker_report_sender_ = std::move(worker_reports[1]);
    initialize_health();
    children_.reserve(config_.max_sessions);
    scheduled_child_descriptors_ = {
        ssh_bind_get_fd(bind_.get()), signal_descriptor_.get(),
        worker_report_receiver_.get(), worker_report_sender_.get()};
  }

  void initialize_health() {
    health_ = HealthMonitor::start({
        .bind_address = config_.health_bind_address,
        .port = config_.health_port,
        .max_sessions = config_.max_sessions,
        .close_in_child = {ssh_bind_get_fd(bind_.get()),
                           signal_descriptor_.get(),
                           worker_report_receiver_.get(),
                           worker_report_sender_.get()},
    });
    health_->set_component(
        ComponentStatus{ComponentKind::storage,
                        ComponentState::ready,
                        "database",
                        std::to_string(database_->schema_version()),
                        {}});
    health_->set_component(ComponentStatus{
        ComponentKind::storage, ComponentState::ready, "oneliners", "1", {}});
    if (!config_.backup_directory.empty()) {
      health_->set_component(ComponentStatus{ComponentKind::storage,
                                             ComponentState::not_configured,
                                             "backup",
                                             "1",
                                             {}});
    }
    health_->heartbeat(true);
  }

  void announce() const {
    std::cout << "anvil: listening on " << config_.bind_address << ':'
              << config_.port << '\n';
    std::cout << "anvil: health listening on " << config_.health_bind_address
              << ':' << config_.health_port << '\n';
    if (!config_.backup_directory.empty()) {
      std::cout << "anvil: backups enabled in " << config_.backup_directory
                << " every " << config_.backup_interval.count()
                << " seconds with " << config_.backup_retention.count()
                << " seconds retention; snapshots contain user content and "
                   "the private host key\n";
    }
    std::cout.flush();
  }

  void run_iteration() {
    reap_scheduled_children();
    start_due_children(Clock::now());
    std::array<pollfd, 3> descriptors{{
        {.fd = ssh_bind_get_fd(bind_.get()), .events = POLLIN, .revents = 0},
        {.fd = worker_report_receiver_.get(), .events = POLLIN, .revents = 0},
        {.fd = signal_descriptor_.get(), .events = POLLIN, .revents = 0},
    }};
    if (!poll_supervisor(descriptors)) {
      return;
    }
    service_runtime_events(descriptors);
    if (!state_.stopping && (descriptors[0].revents & POLLIN) != 0) {
      accept_session();
    }
  }

  [[nodiscard]] bool poll_supervisor(std::span<pollfd> descriptors) const {
    const auto ready = ::poll(descriptors.data(), descriptors.size(), 1000);
    if (ready < 0 && errno == EINTR) {
      return false;
    }
    if (ready < 0) {
      throw_system_error("listener poll failed");
    }
    return true;
  }

  void service_runtime_events(const std::array<pollfd, 3> &descriptors) {
    service_guest_report_permits(children_, admission_);
    health_->heartbeat(!state_.stopping);
    if (!health_->alive()) {
      std::cerr << "anvil: health process exited unexpectedly\n";
      state_.health_failed = true;
      state_.stopping = true;
    }
    if ((descriptors[1].revents & POLLIN) != 0) {
      drain_worker_reports(worker_report_receiver_.get(), children_, admission_,
                           *health_);
    }
    if ((descriptors[2].revents & POLLIN) != 0) {
      service_signal_events();
    }
  }

  void service_signal_events() {
    if (consume_supervisor_signals(signal_descriptor_.get())) {
      state_.stopping = true;
    }
    drain_worker_reports(worker_report_receiver_.get(), children_, admission_,
                         *health_);
    reap_children(children_, admission_, *health_);
  }

  void reap_scheduled_children() {
    reap_scheduled_backup(state_.backup_child, *health_);
    reap_oneliner_retention(state_.oneliner_retention_child, children_,
                            *health_);
  }

  void start_due_children(Clock::time_point now) {
    if (!config_.backup_directory.empty() && state_.backup_child < 0 &&
        now >= state_.next_backup) {
      start_backup(now);
    }
    if (state_.oneliner_retention_child < 0 &&
        now >= state_.next_oneliner_retention) {
      start_retention(now);
    }
  }

  void start_backup(Clock::time_point now) {
    state_.backup_child = start_scheduled_backup(
        *database_, config_, scheduled_child_descriptors_, *health_);
    state_.next_backup = now + config_.backup_interval;
    if (state_.backup_child < 0) {
      std::cerr << "anvil: cannot start scheduled backup: "
                << std::error_code(errno, std::generic_category()).message()
                << '\n';
      health_->set_component(
          ComponentStatus{ComponentKind::storage, ComponentState::failed,
                          "backup", "1", "cannot start scheduled backup"});
    }
  }

  void start_retention(Clock::time_point now) {
    state_.oneliner_retention_child = start_oneliner_retention(
        config_, scheduled_child_descriptors_, children_, *health_);
    state_.next_oneliner_retention = now + 60s;
    if (state_.oneliner_retention_child < 0) {
      std::cerr << "anvil: cannot start one-liner retention: "
                << std::error_code(errno, std::generic_category()).message()
                << '\n';
      health_->set_component(ComponentStatus{
          ComponentKind::storage, ComponentState::failed, "oneliners", "1",
          "cannot start one-liner retention"});
    }
  }

  void accept_session() {
    sockaddr_storage raw_peer{};
    socklen_t raw_peer_size = sizeof(raw_peer);
    auto *const raw_address = static_cast<void *>(&raw_peer);
    FileDescriptor connection(::accept4(ssh_bind_get_fd(bind_.get()),
                                        static_cast<sockaddr *>(raw_address),
                                        &raw_peer_size, SOCK_CLOEXEC));
    if (connection.get() < 0) {
      report_accept_failure();
      return;
    }
    const auto peer = parse_peer(raw_peer, raw_peer_size);
    if (!peer ||
        admission_.admit(*peer, Clock::now()) != AdmissionDecision::allowed) {
      return;
    }
    prepare_session(std::move(connection), *peer);
  }

  static void report_accept_failure() {
    if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
      std::cerr << "anvil: accept failed: "
                << std::error_code(errno, std::generic_category()).message()
                << '\n';
    }
  }

  [[nodiscard]] static std::optional<PeerAddress>
  parse_peer(const sockaddr_storage &raw_peer, socklen_t raw_peer_size) {
    const auto raw_peer_bytes = std::as_bytes(std::span{&raw_peer, 1U});
    if (std::cmp_greater(raw_peer_size, raw_peer_bytes.size())) {
      return std::nullopt;
    }
    return PeerAddress::from_remote_bytes(
        RemoteBytes::from_span(raw_peer_bytes.first(raw_peer_size)));
  }

  void prepare_session(FileDescriptor connection, const PeerAddress &peer) {
    UniqueSession session(ssh_new());
    if (!session) {
      std::cerr << "anvil: cannot allocate SSH session\n";
      admission_.release(peer, Clock::now());
      return;
    }
    if (!accept_connection(std::move(connection), session, peer)) {
      return;
    }
    spawn_session(std::move(session), peer);
  }

  [[nodiscard]] bool accept_connection(FileDescriptor connection,
                                       const UniqueSession &session,
                                       const PeerAddress &peer) {
    const auto accepted_descriptor = connection.release();
    if (ssh_bind_accept_fd(bind_.get(), session.get(), accepted_descriptor) ==
        SSH_OK) {
      return true;
    }
    std::cerr << "anvil: accept failed: " << ssh_get_error(bind_.get()) << '\n';
    if (ssh_get_fd(session.get()) != accepted_descriptor) {
      static_cast<void>(::close(accepted_descriptor));
    }
    admission_.release(peer, Clock::now());
    return false;
  }

  void spawn_session(UniqueSession session, const PeerAddress &peer) {
    std::array<int, 2> guest_report_descriptors{};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                     guest_report_descriptors.data()) != 0) {
      reject_session(session, peer,
                     "cannot create guest-report permit channel");
      return;
    }
    FileDescriptor guest_report_supervisor(guest_report_descriptors[0]);
    FileDescriptor guest_report_worker(guest_report_descriptors[1]);
    FileDescriptor oneliner_event(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (oneliner_event.get() < 0) {
      reject_session(session, peer, "cannot create one-liner event channel");
      return;
    }
    fork_session(std::move(session), peer, std::move(guest_report_supervisor),
                 std::move(guest_report_worker), std::move(oneliner_event));
  }

  void reject_session(const UniqueSession &session, const PeerAddress &peer,
                      std::string_view operation) {
    std::cerr << "anvil: " << operation << ": "
              << std::error_code(errno, std::generic_category()).message()
              << '\n';
    ssh_disconnect(session.get());
    admission_.release(peer, Clock::now());
  }

  void fork_session(UniqueSession session, const PeerAddress &peer,
                    FileDescriptor guest_report_supervisor,
                    FileDescriptor guest_report_worker,
                    FileDescriptor oneliner_event) {
    const auto session_id = state_.next_session_id;
    const auto child = ::fork();
    if (child < 0) {
      reject_session(session, peer, "fork failed");
      return;
    }
    if (child == 0) {
      run_session_child(std::move(session), std::move(guest_report_supervisor),
                        std::move(guest_report_worker),
                        std::move(oneliner_event), session_id);
    }
    register_session_child(std::move(session), peer, child, session_id,
                           std::move(guest_report_supervisor),
                           std::move(oneliner_event));
  }

  [[noreturn]] void run_session_child(UniqueSession session,
                                      FileDescriptor guest_report_supervisor,
                                      FileDescriptor guest_report_worker,
                                      FileDescriptor oneliner_event,
                                      std::uint64_t session_id) {
    health_->detach_in_worker();
    guest_report_supervisor = FileDescriptor();
    for (auto &[existing_worker, existing] : children_) {
      static_cast<void>(existing_worker);
      existing.guest_report_permit = FileDescriptor();
      existing.oneliner_event = FileDescriptor();
    }
    static_cast<void>(::close(signal_descriptor_.get()));
    static_cast<void>(::close(worker_report_receiver_.get()));
    bind_.reset();
    auto worker_signal_descriptor = configure_worker_signals();
    if (worker_signal_descriptor.get() < 0) {
      std::_Exit(1);
    }
    const auto exit_status = run_session(
        session.get(), *database_, config_, tos_policy_,
        worker_signal_descriptor.get(), worker_report_sender_.get(),
        guest_report_worker.get(), oneliner_event.get(), session_id);
    ssh_disconnect(session.get());
    session.reset();
    std::_Exit(exit_status);
  }

  void register_session_child(UniqueSession session, const PeerAddress &peer,
                              pid_t child, std::uint64_t session_id,
                              FileDescriptor guest_report_supervisor,
                              FileDescriptor oneliner_event) {
    children_.emplace(child, ChildState{peer, session_id,
                                        std::move(guest_report_supervisor),
                                        std::move(oneliner_event)});
    health_->session_started(session_id, child);
    advance_session_id();
    session.reset();
  }

  void advance_session_id() noexcept {
    ++state_.next_session_id;
    if (state_.next_session_id == 0U) {
      state_.next_session_id = 1U;
    }
  }

  void shutdown() noexcept {
    if (std::exchange(shutdown_, true)) {
      return;
    }
    try {
      health_->heartbeat(false);
    } catch (const std::exception &error) {
      std::cerr << "anvil: cannot mark health unavailable during shutdown: "
                << error.what() << '\n';
    }
    bind_.reset();
    stop_scheduled_backup(state_.backup_child);
    stop_oneliner_retention(state_.oneliner_retention_child);
    try {
      await_children(children_, signal_descriptor_.get(),
                     worker_report_receiver_.get(), admission_, *health_);
    } catch (const std::exception &error) {
      std::cerr << "anvil: graceful session cleanup failed: " << error.what()
                << '\n';
      terminate_children(children_, SIGKILL);
      reap_remaining_children();
    }
    health_->shutdown();
  }

  void reap_remaining_children() noexcept {
    for (const auto &[child, state] : children_) {
      static_cast<void>(state);
      while (::waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
      }
    }
    children_.clear();
  }

  void shutdown_noexcept() noexcept {
    if (health_) {
      shutdown();
    }
  }

  const Config &config_;
  TosPolicy tos_policy_;
  std::unique_ptr<store::SqliteStore> database_;
  SshLibrary ssh_;
  UniqueBind bind_;
  FileDescriptor signal_descriptor_;
  FileDescriptor worker_report_receiver_;
  FileDescriptor worker_report_sender_;
  std::unique_ptr<HealthMonitor> health_;
  AdmissionController admission_;
  ChildMap children_;
  SupervisorState state_;
  std::array<int, 4> scheduled_child_descriptors_{};
  bool shutdown_{};
};

[[nodiscard]] int restore_server(const Config &config) {
  auto restored = backup::restore_snapshot(
      config.restore_snapshot, config.database_path, config.host_key_path);
  if (!restored) {
    throw std::runtime_error("cannot restore backup: " + restored.error());
  }
  std::cout << "anvil: restored " << config.restore_snapshot << " to "
            << config.database_path << " with host key " << config.host_key_path
            << '\n';
  return 0;
}

[[nodiscard]] int create_server_backup(const Config &config) {
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

} // namespace

void reconcile_configured_boards(store::Store &database, const Config &config,
                                 store::UtcEpochSeconds now) {
  reconcile_boards(database, config, now);
}

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
         "  --oneliner-rate-limit C/S\n"
         "                          per-user posting burst (default 3/300)\n"
         "  --oneliner-retention-seconds S\n"
         "                          live-database lifetime (default 1209600)\n"
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
  ArgumentParseState state;
  parse_argument_tokens(state, arguments);
  return finish_argument_parsing(std::move(state));
}

int run(const Config &config) {
  if (config.operation == Operation::restore) {
    return restore_server(config);
  }
  if (config.operation == Operation::backup_once) {
    return create_server_backup(config);
  }
  SupervisorRuntime supervisor(config);
  return supervisor.execute();
}

} // namespace anvil::server
