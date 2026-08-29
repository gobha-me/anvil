#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <string_view>

namespace {

constexpr auto connect_timeout = std::chrono::seconds(3);

[[nodiscard]] int parse_port(std::string_view text) {
  if (text.empty()) {
    return -1;
  }
  int value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return -1;
    }
    const int digit = character - '0';
    if (value > (std::numeric_limits<int>::max() - digit) / 10) {
      return -1;
    }
    value = value * 10 + digit;
  }
  return value > 0 && value <= 65'535 ? value : -1;
}

[[nodiscard]] int probe_write(const char *path) {
  const int descriptor = ::open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (descriptor < 0) {
    std::cerr << "write refused: " << std::strerror(errno) << '\n';
    return 10;
  }
  static_cast<void>(::close(descriptor));
  if (::unlink(path) != 0) {
    std::cerr << "cleanup failed: " << std::strerror(errno) << '\n';
    return 11;
  }
  return 0;
}

[[nodiscard]] int probe_file(const char *path) {
  struct stat metadata {};
  if (::stat(path, &metadata) != 0) {
    std::cerr << "file unavailable: " << std::strerror(errno) << '\n';
    return 12;
  }
  if (!S_ISREG(metadata.st_mode) || metadata.st_size <= 0) {
    std::cerr << "path is not a non-empty regular file\n";
    return 13;
  }
  return 0;
}

[[nodiscard]] int probe_backup_directory(const char *path) {
  const int raw_directory =
      ::open(path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
  if (raw_directory < 0) {
    std::cerr << "backup directory unavailable: " << std::strerror(errno)
              << '\n';
    return 14;
  }
  DIR *directory = ::fdopendir(raw_directory);
  if (directory == nullptr) {
    static_cast<void>(::close(raw_directory));
    std::cerr << "backup directory unreadable: " << std::strerror(errno)
              << '\n';
    return 15;
  }
  int result = 16;
  while (const auto *entry = ::readdir(directory)) {
    const std::string_view name(entry->d_name);
    if (!name.starts_with("anvil-backup-")) {
      continue;
    }
    const int snapshot =
        ::openat(raw_directory, entry->d_name,
                 O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (snapshot < 0) {
      continue;
    }
    bool complete = true;
    for (const auto *filename : {"anvil.db", "host_key", "manifest"}) {
      struct stat metadata{};
      if (::fstatat(snapshot, filename, &metadata, AT_SYMLINK_NOFOLLOW) != 0 ||
          !S_ISREG(metadata.st_mode) || metadata.st_size <= 0) {
        complete = false;
      }
    }
    static_cast<void>(::close(snapshot));
    if (complete) {
      result = 0;
      break;
    }
  }
  static_cast<void>(::closedir(directory));
  if (result != 0) {
    std::cerr << "no complete backup snapshot found\n";
  }
  return result;
}

[[nodiscard]] bool connect_one(const addrinfo &address) {
  const int descriptor =
      ::socket(address.ai_family, address.ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK,
               address.ai_protocol);
  if (descriptor < 0) {
    return false;
  }

  bool connected = false;
  if (::connect(descriptor, address.ai_addr, address.ai_addrlen) == 0) {
    connected = true;
  } else if (errno == EINPROGRESS) {
    pollfd pending{.fd = descriptor, .events = POLLOUT, .revents = 0};
    const auto timeout =
        std::chrono::duration_cast<std::chrono::milliseconds>(connect_timeout).count();
    if (::poll(&pending, 1, static_cast<int>(timeout)) > 0) {
      int socket_error = 0;
      socklen_t size = sizeof(socket_error);
      connected = ::getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socket_error, &size) == 0 &&
                  socket_error == 0;
    }
  }

  static_cast<void>(::close(descriptor));
  return connected;
}

[[nodiscard]] int probe_connect(const char *host, std::string_view port_text) {
  const int port = parse_port(port_text);
  if (port < 0) {
    std::cerr << "invalid port\n";
    return 20;
  }

  const auto service = std::to_string(port);
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *addresses = nullptr;
  const int resolved = ::getaddrinfo(host, service.c_str(), &hints, &addresses);
  if (resolved != 0) {
    std::cerr << "resolution failed: " << ::gai_strerror(resolved) << '\n';
    return 21;
  }

  bool connected = false;
  for (const addrinfo *address = addresses; address != nullptr; address = address->ai_next) {
    if (connect_one(*address)) {
      connected = true;
      break;
    }
  }
  ::freeaddrinfo(addresses);

  if (!connected) {
    std::cerr << "connection refused or unreachable\n";
    return 22;
  }
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc == 3 && std::string_view{argv[1]} == "write") {
    return probe_write(argv[2]);
  }
  if (argc == 3 && std::string_view{argv[1]} == "file") {
    return probe_file(argv[2]);
  }
  if (argc == 3 && std::string_view{argv[1]} == "backup-directory") {
    return probe_backup_directory(argv[2]);
  }
  if (argc == 4 && std::string_view{argv[1]} == "connect") {
    return probe_connect(argv[2], argv[3]);
  }
  std::cerr << "usage: container-probe write PATH | file PATH | "
               "backup-directory PATH | connect HOST PORT\n";
  return EXIT_FAILURE;
}
