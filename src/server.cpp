#include "server.hpp"

#include <fcntl.h>
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/libssh_version.h>
#include <libssh/server.h>
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
#include <unordered_set>
#include <utility>
#include <vector>

#include "terminal_session.hpp"

namespace anvil::server {
namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

constexpr std::size_t max_key_file_size = 64U * 1024U;
constexpr std::size_t max_pending_input = 64U * 1024U;
constexpr auto authentication_timeout = 15s;
constexpr auto shutdown_timeout = 5s;

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
  explicit FileDescriptor(int descriptor = -1) noexcept : descriptor_(descriptor) {}
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
  void operator()(ssh_session_struct *session) const noexcept { ssh_free(session); }
};
using UniqueSession = std::unique_ptr<ssh_session_struct, SessionDeleter>;

struct EventDeleter {
  void operator()(ssh_event_struct *event) const noexcept { ssh_event_free(event); }
};
using UniqueEvent = std::unique_ptr<ssh_event_struct, EventDeleter>;

struct AuthorizedKey {
  std::string user;
  UniqueKey key;
};

enum class RequestedOperation { none, shell, exec, subsystem };

struct SessionState {
  const std::vector<AuthorizedKey> *authorized_keys{};
  ssh_channel channel{};
  unsigned int auth_attempts{};
  bool authenticated{};
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

[[noreturn]] void throw_system_error(std::string_view operation) {
  throw std::system_error(errno, std::generic_category(), std::string(operation));
}

[[nodiscard]] std::string read_key_file(FileDescriptor file, const std::string &path,
                                        bool private_key) {
  struct stat metadata{};
  if (::fstat(file.get(), &metadata) != 0) {
    throw_system_error("cannot inspect key file '" + path + "'");
  }
  if (!S_ISREG(metadata.st_mode)) {
    throw std::runtime_error("key file is not a regular file: " + path);
  }
  if (private_key && (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    throw std::runtime_error("host key must not be accessible by group or others: " + path);
  }
  if (metadata.st_size <= 0 || static_cast<std::uintmax_t>(metadata.st_size) > max_key_file_size) {
    throw std::runtime_error("key file has an invalid size: " + path);
  }

  std::string contents;
  contents.resize(static_cast<std::size_t>(metadata.st_size));
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const auto count = ::read(file.get(), contents.data() + offset, contents.size() - offset);
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

[[nodiscard]] std::string read_key_file(const std::string &path, bool private_key) {
  const auto descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (descriptor < 0) {
    throw_system_error("cannot open key file '" + path + "'");
  }
  return read_key_file(FileDescriptor(descriptor), path, private_key);
}

[[nodiscard]] std::string read_host_key_at(int directory, const std::string &filename,
                                           const std::string &path) {
  const auto descriptor =
      ::openat(directory, filename.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (descriptor < 0) {
    throw_system_error("cannot open key file '" + path + "'");
  }
  return read_key_file(FileDescriptor(descriptor), path, true);
}

void write_all(int descriptor, std::string_view contents, std::string_view path) {
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const auto count = ::write(descriptor, contents.data() + offset, contents.size() - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      throw_system_error("cannot write host key '" + std::string(path) + "'");
    }
    if (count == 0) {
      throw std::runtime_error("short write while creating host key: " + std::string(path));
    }
    offset += static_cast<std::size_t>(count);
  }
}

[[nodiscard]] std::string random_suffix() {
  std::array<unsigned char, 16> bytes{};
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count = ::getrandom(bytes.data() + offset, bytes.size() - offset, 0);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      throw_system_error("cannot obtain randomness for temporary host key name");
    }
    if (count == 0) {
      throw std::runtime_error("no randomness returned for temporary host key name");
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

[[nodiscard]] std::string generate_ed25519_host_key() {
  ssh_key raw_key = nullptr;
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 12, 0)
  const auto generated = ssh_pki_generate_key(SSH_KEYTYPE_ED25519, nullptr, &raw_key);
#else
  const auto generated = ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &raw_key);
#endif
  UniqueKey key(raw_key);
  if (generated != SSH_OK || !key) {
    throw std::runtime_error("cannot generate Ed25519 host key");
  }

  char *raw_export = nullptr;
  if (ssh_pki_export_privkey_base64(key.get(), nullptr, nullptr, nullptr, &raw_export) != SSH_OK ||
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

  const auto directory_descriptor = ::open(parent.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY);
  if (directory_descriptor < 0) {
    throw_system_error("cannot open host key directory '" + parent.string() + "'");
  }
  FileDescriptor directory(directory_descriptor);

  const auto existing =
      ::openat(directory.get(), filename.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (existing >= 0) {
    return read_key_file(FileDescriptor(existing), path, true);
  }
  if (errno != ENOENT) {
    throw_system_error("cannot open key file '" + path + "'");
  }

  auto generated = generate_ed25519_host_key();
  const auto temporary_name = "." + filename + ".tmp." + random_suffix();
  const auto temporary_descriptor =
      ::openat(directory.get(), temporary_name.c_str(),
               O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
  if (temporary_descriptor < 0) {
    clear_secret(generated.data(), generated.size());
    throw_system_error("cannot create temporary host key in '" + parent.string() + "'");
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

    if (::linkat(directory.get(), temporary_name.c_str(), directory.get(), filename.c_str(), 0) !=
        0) {
      if (errno != EEXIST) {
        throw_system_error("cannot publish host key '" + path + "'");
      }
      temporary_entry.remove();
      clear_secret(generated.data(), generated.size());
      return read_host_key_at(directory.get(), filename, path);
    }

    temporary_entry.remove();
    if (::fsync(directory.get()) != 0) {
      throw_system_error("cannot flush host key directory '" + parent.string() + "'");
    }
    return generated;
  } catch (...) {
    clear_secret(generated.data(), generated.size());
    throw;
  }
}

[[nodiscard]] std::pair<std::string_view, std::string_view> public_key_tokens(
    const std::string &contents, const std::string &path) {
  const auto newline = contents.find('\n');
  const auto first_line = std::string_view(contents).substr(0, newline);
  if (newline != std::string::npos) {
    const auto remainder = std::string_view(contents).substr(newline + 1U);
    if (remainder.find_first_not_of(" \t\r\n") != std::string_view::npos) {
      throw std::runtime_error("authorized key file must contain exactly one key: " + path);
    }
  }

  constexpr auto whitespace = " \t\r";
  const auto type_begin = first_line.find_first_not_of(whitespace);
  if (type_begin == std::string_view::npos) {
    throw std::runtime_error("authorized key file is empty: " + path);
  }
  const auto type_end = first_line.find_first_of(whitespace, type_begin);
  if (type_end == std::string_view::npos) {
    throw std::runtime_error("authorized key file is missing key data: " + path);
  }
  const auto data_begin = first_line.find_first_not_of(whitespace, type_end);
  if (data_begin == std::string_view::npos) {
    throw std::runtime_error("authorized key file is missing key data: " + path);
  }
  const auto data_end = first_line.find_first_of(whitespace, data_begin);
  return {first_line.substr(type_begin, type_end - type_begin),
          first_line.substr(data_begin, data_end - data_begin)};
}

[[nodiscard]] AuthorizedKey load_authorized_key(const AuthorizedKeySpec &specification) {
  const auto contents = read_key_file(specification.path, false);
  const auto [type_name, encoded] = public_key_tokens(contents, specification.path);
  const std::string type_string(type_name);
  const auto type = ssh_key_type_from_name(type_string.c_str());
  if (type == SSH_KEYTYPE_UNKNOWN) {
    throw std::runtime_error("unsupported public key type in: " + specification.path);
  }

  ssh_key raw_key = nullptr;
  const std::string encoded_string(encoded);
  if (ssh_pki_import_pubkey_base64(encoded_string.c_str(), type, &raw_key) != SSH_OK ||
      raw_key == nullptr) {
    throw std::runtime_error("invalid public key in: " + specification.path);
  }
  return AuthorizedKey{specification.user, UniqueKey(raw_key)};
}

[[nodiscard]] bool key_is_authorized(const SessionState &state, const char *user,
                                     ssh_key offered_key) {
  if (user == nullptr || offered_key == nullptr || state.authorized_keys == nullptr) {
    return false;
  }
  return std::ranges::any_of(*state.authorized_keys, [&](const AuthorizedKey &candidate) {
    return candidate.user == user &&
           ssh_key_cmp(candidate.key.get(), offered_key, SSH_KEY_CMP_PUBLIC) == 0;
  });
}

int authenticate_public_key(ssh_session, const char *user, ssh_key offered_key,
                            char signature_state, void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  const bool authorized = key_is_authorized(state, user, offered_key);
  if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
    return authorized ? SSH_AUTH_SUCCESS : SSH_AUTH_DENIED;
  }
  if (signature_state == SSH_PUBLICKEY_STATE_VALID && authorized) {
    state.authenticated = true;
    state.authenticated_at = Clock::now();
    state.last_activity = state.authenticated_at;
    return SSH_AUTH_SUCCESS;
  }
  ++state.auth_attempts;
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

int request_pty(ssh_session, ssh_channel, const char *terminal_type, int columns, int rows,
                int pixel_width, int pixel_height, void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  if (state.pty_requested) {
    const auto dimensions = normalize_resize_dimensions(columns, rows, pixel_width, pixel_height);
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
  const auto dimensions = normalize_initial_dimensions(columns, rows, pixel_width, pixel_height);
  state.pty_requested = true;
  state.columns = dimensions.columns;
  state.rows = dimensions.rows;
  state.pixel_width = dimensions.pixel_width;
  state.pixel_height = dimensions.pixel_height;
  state.terminal_type = normalize_terminal_type(terminal_type);
  if (state.terminal_session != nullptr) {
    state.terminal_session->post_resize(dimensions);
  }
  return SSH_OK;
}

int resize_pty(ssh_session, ssh_channel, int columns, int rows, int pixel_width, int pixel_height,
               void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  const auto dimensions = normalize_resize_dimensions(columns, rows, pixel_width, pixel_height);
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

int receive_data(ssh_session, ssh_channel, void *data, std::uint32_t length, int is_stderr,
                 void *userdata) {
  auto &state = *static_cast<SessionState *>(userdata);
  if (length > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) {
    state.close_requested = true;
    return SSH_ERROR;
  }
  if (is_stderr != 0 || state.operation != RequestedOperation::shell || length == 0U) {
    return static_cast<int>(length);
  }
  if (length > max_pending_input - state.pending_input.size()) {
    state.close_requested = true;
    return static_cast<int>(length);
  }
  const auto *first = static_cast<const std::byte *>(data);
  state.pending_input.insert(state.pending_input.end(), first, first + length);
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

[[nodiscard]] bool write_channel(ssh_channel channel, const void *data, std::size_t length,
                                 bool standard_error = false) {
  const auto *bytes = static_cast<const std::byte *>(data);
  std::size_t offset = 0;
  while (offset < length) {
    const auto chunk = static_cast<std::uint32_t>(std::min<std::size_t>(
        length - offset, static_cast<std::size_t>(std::numeric_limits<int>::max())));
    const int count = standard_error ? ssh_channel_write_stderr(channel, bytes + offset, chunk)
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

void await_peer_channel_close(ssh_event event, ssh_session session, SessionState &state) {
  const auto deadline = Clock::now() + 500ms;
  while (!state.close_requested && ssh_is_connected(session) != 0 && Clock::now() < deadline) {
    if (ssh_event_dopoll(event, 10) == SSH_ERROR) {
      break;
    }
  }
}

[[nodiscard]] bool forward_session_input(int descriptor, std::vector<std::byte> &pending) {
  while (!pending.empty()) {
    const auto count = ::send(descriptor, pending.data(), pending.size(), MSG_NOSIGNAL);
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
                                          bool discard = false) {
  std::array<std::byte, 16U * 1024U> buffer{};
  for (;;) {
    const auto count = ::recv(descriptor, buffer.data(), buffer.size(), 0);
    if (count > 0) {
      if (!discard && !write_channel(channel, buffer.data(), static_cast<std::size_t>(count))) {
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
    const auto count = ::read(signal_descriptor, &signal_info, sizeof(signal_info));
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

enum class SessionEnd { normal, idle_timeout, session_cap, shutdown };

int run_session(ssh_session session, const std::vector<AuthorizedKey> &authorized_keys,
                const Config &config, int signal_descriptor) {
  SessionState state;
  state.authorized_keys = &authorized_keys;
  state.pending_input.reserve(4096);

  ssh_server_callbacks_struct server_callbacks{};
  server_callbacks.userdata = &state;
  server_callbacks.auth_pubkey_function = authenticate_public_key;
  server_callbacks.channel_open_request_session_function = open_session_channel;
  ssh_callbacks_init(&server_callbacks);

  if (ssh_set_server_callbacks(session, &server_callbacks) != SSH_OK) {
    std::cerr << "anvil: cannot install SSH server callbacks\n";
    return 1;
  }
  static_cast<void>(ssh_set_auth_methods(session, SSH_AUTH_METHOD_PUBLICKEY));

  timeval timeout{.tv_sec = authentication_timeout.count(), .tv_usec = 0};
  const auto socket = ssh_get_fd(session);
  static_cast<void>(::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
  static_cast<void>(::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));

  if (ssh_handle_key_exchange(session) != SSH_OK) {
    std::cerr << "anvil: key exchange failed: " << ssh_get_error(session) << '\n';
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
  auto session_end = SessionEnd::normal;

  while (ssh_is_connected(session) != 0 && !state.close_requested) {
    if (ssh_event_dopoll(event.get(), terminal_session ? 10 : 100) == SSH_ERROR) {
      break;
    }
    if (worker_shutdown_requested(signal_descriptor)) {
      session_end = SessionEnd::shutdown;
      break;
    }
    const auto now = Clock::now();
    if (!state.authenticated && (state.auth_attempts >= 6U || now >= authentication_deadline)) {
      break;
    }
    if (state.authenticated) {
      if (now - state.authenticated_at >= config.session_cap) {
        session_end = SessionEnd::session_cap;
        break;
      }
      if (now - state.last_activity >= config.idle_timeout) {
        session_end = SessionEnd::idle_timeout;
        break;
      }
    }

    if (state.channel != nullptr && !state.channel_callbacks_installed) {
      if (ssh_set_channel_callbacks(state.channel, &channel_callbacks) != SSH_OK) {
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
      const std::string_view message = state.operation == RequestedOperation::exec
                                           ? "Anvil does not execute commands.\r\n"
                                           : "Anvil does not provide SSH subsystems.\r\n";
      static_cast<void>(write_channel(state.channel, message.data(), message.size(), true));
      close_channel(state.channel, 126);
      await_peer_channel_close(event.get(), session, state);
      denial_sent = true;
      break;
    }

    if (state.operation == RequestedOperation::shell && !state.pty_requested && !denial_sent) {
      constexpr std::string_view message =
          "Anvil requires an interactive PTY; "
          "omit -T or reconnect with -t.\r\n";
      static_cast<void>(write_channel(state.channel, message.data(), message.size(), true));
      close_channel(state.channel, 126);
      await_peer_channel_close(event.get(), session, state);
      denial_sent = true;
      break;
    }

    if (state.operation == RequestedOperation::shell && !terminal_session) {
      std::array<int, 2> descriptors{};
      if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                       descriptors.data()) != 0) {
        std::cerr << "anvil: cannot create terminal session bridge: " << std::strerror(errno)
                  << '\n';
        break;
      }
      application_descriptor = FileDescriptor(descriptors[0]);
      server_descriptor = FileDescriptor(descriptors[1]);
      try {
        const TerminalDimensions dimensions{state.columns, state.rows, state.pixel_width,
                                            state.pixel_height};
        terminal_session = std::make_unique<TerminalSession>(
            application_descriptor.get(), state.terminal_type, dimensions, state.channel_opened_at);
        state.terminal_session = terminal_session.get();
        terminal_session->start();
      } catch (const std::exception &error) {
        std::cerr << "anvil: cannot start terminal session: " << error.what() << '\n';
        terminal_session.reset();
        state.terminal_session = nullptr;
        application_descriptor = FileDescriptor();
        server_descriptor = FileDescriptor();
        application_failed = true;
        break;
      }
    }

    if (terminal_session) {
      if (!forward_session_input(server_descriptor.get(), state.pending_input)) {
        application_failed = true;
        break;
      }
      if (!forward_session_output(server_descriptor.get(), state.channel)) {
        break;
      }
      if (terminal_session->finished()) {
        application_failed = terminal_session->failed();
        break;
      }
    }

    if (state.operation == RequestedOperation::shell && !state.idle_warning_sent &&
        now - state.last_activity >= config.idle_timeout - config.idle_warning) {
      const auto seconds = config.idle_warning.count();
      const auto warning = "Anvil: idle session will close in " + std::to_string(seconds) +
                           " seconds. Press any key to continue.";
      if (terminal_session) {
        terminal_session->post_notice(warning);
      } else if (!write_channel(state.channel, warning.data(), warning.size())) {
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

  if (terminal_session) {
    state.terminal_session = nullptr;
    terminal_session->request_stop();
    const auto drain_deadline = Clock::now() + 2s;
    while (!terminal_session->finished() && Clock::now() < drain_deadline) {
      static_cast<void>(ssh_event_dopoll(event.get(), 10));
      static_cast<void>(forward_session_output(server_descriptor.get(), state.channel,
                                               ssh_channel_is_open(state.channel) == 0));
    }
    if (!terminal_session->finished()) {
      server_descriptor = FileDescriptor();
    }
    terminal_session->join();
    if (server_descriptor.get() >= 0) {
      static_cast<void>(forward_session_output(server_descriptor.get(), state.channel,
                                               ssh_channel_is_open(state.channel) == 0));
    }
    application_failed = application_failed || terminal_session->failed();
    const auto telemetry = terminal_session->telemetry();
    std::cerr << "anvil: session " << ::getpid() << " frames=" << telemetry.frames
              << " accepted=" << telemetry.accepted_frames << " cells=" << telemetry.cell_bytes
              << " image-transmit=" << telemetry.image_transmit_bytes
              << " image-edit=" << telemetry.image_edit_bytes
              << " first-frame-ms=" << telemetry.first_frame_latency.count() << '\n';
  }

  if (state.channel != nullptr && ssh_channel_is_open(state.channel) != 0) {
    std::string_view message;
    int status = 0;
    switch (session_end) {
      case SessionEnd::idle_timeout:
        message = "Anvil: session closed after the idle timeout.\r\n";
        status = 124;
        break;
      case SessionEnd::session_cap:
        message = "Anvil: maximum session duration reached; closing.\r\n";
        status = 124;
        break;
      case SessionEnd::shutdown:
        message = "Anvil: server is shutting down; closing this session.\r\n";
        break;
      case SessionEnd::normal:
        if (application_failed) {
          message = "Anvil: this session failed; the board remains available.\r\n";
          status = 1;
        } else {
          status = state.close_requested ? 1 : 0;
        }
        break;
    }
    if (!message.empty()) {
      static_cast<void>(write_channel(state.channel, message.data(), message.size()));
    }
    close_channel(state.channel, status);
    await_peer_channel_close(event.get(), session, state);
  }
  static_cast<void>(ssh_event_remove_session(event.get(), session));
  if (state.channel != nullptr) {
    ssh_channel_free(state.channel);
    state.channel = nullptr;
  }
  return 0;
}

void reap_children(std::unordered_set<pid_t> &children) {
  for (;;) {
    int status = 0;
    const auto child = ::waitpid(-1, &status, WNOHANG);
    if (child > 0) {
      children.erase(child);
      continue;
    }
    if (child < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
}

void terminate_children(std::unordered_set<pid_t> &children, int signal_number) {
  for (const auto child : children) {
    if (::kill(child, signal_number) != 0 && errno != ESRCH) {
      std::cerr << "anvil: cannot signal worker " << child << ": " << std::strerror(errno) << '\n';
    }
  }
}

void await_children(std::unordered_set<pid_t> &children, int signal_descriptor) {
  terminate_children(children, SIGTERM);
  const auto deadline = Clock::now() + shutdown_timeout;
  while (!children.empty() && Clock::now() < deadline) {
    pollfd descriptor{.fd = signal_descriptor, .events = POLLIN, .revents = 0};
    static_cast<void>(::poll(&descriptor, 1, 100));
    if ((descriptor.revents & POLLIN) != 0) {
      signalfd_siginfo signal_info{};
      const auto count = ::read(signal_descriptor, &signal_info, sizeof(signal_info));
      if (count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
        std::cerr << "anvil: cannot read child signal: " << std::strerror(errno) << '\n';
      }
    }
    reap_children(children);
  }
  if (!children.empty()) {
    terminate_children(children, SIGKILL);
    while (!children.empty()) {
      const auto child = ::waitpid(-1, nullptr, 0);
      if (child > 0) {
        children.erase(child);
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

[[nodiscard]] std::uint32_t parse_session_limit(std::string_view text) {
  if (text.empty()) {
    throw std::runtime_error("session limit must not be empty");
  }
  unsigned long value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      throw std::runtime_error("session limit must be a decimal number");
    }
    value = value * 10UL + static_cast<unsigned long>(character - '0');
    if (value > 4096UL) {
      throw std::runtime_error("session limit must be between 1 and 4096");
    }
  }
  if (value == 0UL) {
    throw std::runtime_error("session limit must be between 1 and 4096");
  }
  return static_cast<std::uint32_t>(value);
}

[[nodiscard]] std::chrono::seconds parse_duration(std::string_view text, std::string_view name) {
  if (text.empty()) {
    throw std::runtime_error(std::string(name) + " must not be empty");
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      throw std::runtime_error(std::string(name) + " must be a decimal number of seconds");
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

}  // namespace

std::string_view usage() noexcept {
  return "usage: anvil --host-key PATH --authorized-key USER=PATH [options]\n"
         "\n"
         "options:\n"
         "  --bind-address ADDRESS   address to listen on (default 127.0.0.1)\n"
         "  --port PORT             TCP port to listen on (default 2222)\n"
         "  --max-sessions COUNT    concurrent worker limit (default 64)\n"
         "  --idle-timeout-seconds S\n"
         "                          idle limit in seconds (default 300)\n"
         "  --idle-warning-seconds S\n"
         "                          warning lead time in seconds (default 30)\n"
         "  --session-cap-seconds S absolute session limit in seconds (default "
         "86400)\n"
         "  --host-key PATH         unencrypted OpenSSH private host key\n"
         "  --authorized-key U=P    authorize public key file P for user U; "
         "repeatable\n"
         "  --help                  show this help\n";
}

ParseResult parse_arguments(std::span<const std::string_view> arguments) {
  ParseResult result;
  for (std::size_t index = 0; index < arguments.size(); ++index) {
    const auto argument = arguments[index];
    if (argument == "--help") {
      result.show_help = true;
      continue;
    }
    if (argument != "--bind-address" && argument != "--port" && argument != "--max-sessions" &&
        argument != "--idle-timeout-seconds" && argument != "--idle-warning-seconds" &&
        argument != "--session-cap-seconds" && argument != "--host-key" &&
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
    } else if (argument == "--max-sessions") {
      result.config.max_sessions = parse_session_limit(value);
    } else if (argument == "--idle-timeout-seconds") {
      result.config.idle_timeout = parse_duration(value, "idle timeout");
    } else if (argument == "--idle-warning-seconds") {
      result.config.idle_warning = parse_duration(value, "idle warning");
    } else if (argument == "--session-cap-seconds") {
      result.config.session_cap = parse_duration(value, "session cap");
    } else if (argument == "--host-key") {
      result.config.host_key_path = value;
    } else {
      const auto separator = value.find('=');
      if (separator == std::string_view::npos || separator == 0U ||
          separator + 1U >= value.size()) {
        throw std::runtime_error("authorized key must have the form USER=PATH");
      }
      result.config.authorized_keys.push_back(
          {std::string(value.substr(0, separator)), std::string(value.substr(separator + 1U))});
    }
  }
  if (!result.show_help) {
    if (result.config.idle_warning >= result.config.idle_timeout) {
      throw std::runtime_error("idle warning must be shorter than idle timeout");
    }
    if (result.config.host_key_path.empty()) {
      throw std::runtime_error("--host-key is required");
    }
    if (result.config.authorized_keys.empty()) {
      throw std::runtime_error("at least one --authorized-key is required");
    }
  }
  return result;
}

int run(const Config &config) {
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
  auto host_key = load_or_create_host_key(config.host_key_path);

  UniqueBind bind(ssh_bind_new());
  if (!bind) {
    throw std::runtime_error("cannot allocate SSH listener");
  }
  const auto port = std::to_string(config.port);
  const bool configured =
      ssh_bind_options_set(bind.get(), SSH_BIND_OPTIONS_BINDADDR, config.bind_address.c_str()) ==
          SSH_OK &&
      ssh_bind_options_set(bind.get(), SSH_BIND_OPTIONS_BINDPORT_STR, port.c_str()) == SSH_OK &&
      ssh_bind_options_set(bind.get(), SSH_BIND_OPTIONS_IMPORT_KEY_STR, host_key.c_str()) == SSH_OK;
  clear_secret(host_key.data(), host_key.size());
  if (!configured) {
    throw std::runtime_error("cannot configure SSH listener: " +
                             std::string(ssh_get_error(bind.get())));
  }
  if (ssh_bind_listen(bind.get()) != SSH_OK) {
    throw std::runtime_error("cannot listen on " + config.bind_address + ':' + port + ": " +
                             std::string(ssh_get_error(bind.get())));
  }

  sigset_t signal_mask;
  if (::sigemptyset(&signal_mask) != 0 || ::sigaddset(&signal_mask, SIGCHLD) != 0 ||
      ::sigaddset(&signal_mask, SIGINT) != 0 || ::sigaddset(&signal_mask, SIGTERM) != 0 ||
      ::sigprocmask(SIG_BLOCK, &signal_mask, nullptr) != 0) {
    throw_system_error("cannot block supervisor signals");
  }
  FileDescriptor signal_descriptor(::signalfd(-1, &signal_mask, SFD_CLOEXEC | SFD_NONBLOCK));
  if (signal_descriptor.get() < 0) {
    throw_system_error("cannot create signal descriptor");
  }

  std::unordered_set<pid_t> children;
  bool stopping = false;
  std::cout << "anvil: listening on " << config.bind_address << ':' << config.port << '\n';
  std::cout.flush();

  while (!stopping) {
    std::array<pollfd, 2> descriptors{{
        {.fd = ssh_bind_get_fd(bind.get()),
         .events = static_cast<short>(children.size() < config.max_sessions ? POLLIN : 0),
         .revents = 0},
        {.fd = signal_descriptor.get(), .events = POLLIN, .revents = 0},
    }};
    const auto ready = ::poll(descriptors.data(), descriptors.size(), -1);
    if (ready < 0 && errno == EINTR) {
      continue;
    }
    if (ready < 0) {
      throw_system_error("listener poll failed");
    }

    if ((descriptors[1].revents & POLLIN) != 0) {
      for (;;) {
        signalfd_siginfo signal_info{};
        const auto count = ::read(signal_descriptor.get(), &signal_info, sizeof(signal_info));
        if (count < 0 && errno == EINTR) {
          continue;
        }
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          break;
        }
        if (count != static_cast<ssize_t>(sizeof(signal_info))) {
          throw std::runtime_error("short read from signal descriptor");
        }
        if (signal_info.ssi_signo == SIGINT || signal_info.ssi_signo == SIGTERM) {
          stopping = true;
        }
      }
      reap_children(children);
    }
    if (stopping || (descriptors[0].revents & POLLIN) == 0) {
      continue;
    }

    UniqueSession session(ssh_new());
    if (!session) {
      std::cerr << "anvil: cannot allocate SSH session\n";
      continue;
    }
    if (ssh_bind_accept(bind.get(), session.get()) != SSH_OK) {
      std::cerr << "anvil: accept failed: " << ssh_get_error(bind.get()) << '\n';
      continue;
    }

    const auto child = ::fork();
    if (child < 0) {
      std::cerr << "anvil: fork failed: " << std::strerror(errno) << '\n';
      ssh_disconnect(session.get());
      continue;
    }
    if (child == 0) {
      static_cast<void>(::close(signal_descriptor.get()));
      bind.reset();
      sigset_t worker_mask;
      if (::sigemptyset(&worker_mask) != 0 || ::sigaddset(&worker_mask, SIGINT) != 0 ||
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
      const auto exit_status =
          run_session(session.get(), authorized_keys, config, worker_signal_descriptor.get());
      ssh_disconnect(session.get());
      session.reset();
      std::_Exit(exit_status);
    }
    children.insert(child);
    session.reset();
  }

  bind.reset();
  await_children(children, signal_descriptor.get());
  return 0;
}

}  // namespace anvil::server
