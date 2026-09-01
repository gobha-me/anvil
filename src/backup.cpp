#include "backup.hpp"

#include "sqlite_store.hpp"

#include <libssh/libssh.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <sys/random.h>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>

namespace anvil::server::backup {
namespace {

constexpr std::string_view snapshot_prefix = "anvil-backup-";
constexpr std::string_view temporary_prefix = ".anvil-backup-tmp-";
constexpr std::string_view database_name = "anvil.db";
constexpr std::string_view host_key_name = "host_key";
constexpr std::string_view manifest_name = "manifest";
constexpr std::size_t max_host_key_size = 64U * 1024U;
constexpr std::size_t max_manifest_size = 256U;

class Descriptor {
public:
  explicit Descriptor(int value = -1) noexcept : value_(value) {}
  ~Descriptor() {
    if (value_ >= 0) {
      static_cast<void>(::close(value_));
    }
  }
  Descriptor(const Descriptor &) = delete;
  auto operator=(const Descriptor &) -> Descriptor & = delete;
  Descriptor(Descriptor &&other) noexcept
      : value_(std::exchange(other.value_, -1)) {}
  auto operator=(Descriptor &&other) noexcept -> Descriptor & {
    if (this != &other) {
      if (value_ >= 0) {
        static_cast<void>(::close(value_));
      }
      value_ = std::exchange(other.value_, -1);
    }
    return *this;
  }
  [[nodiscard]] auto get() const noexcept -> int { return value_; }
  [[nodiscard]] auto release() noexcept -> int {
    return std::exchange(value_, -1);
  }

private:
  int value_;
};

struct DirectoryDeleter {
  void operator()(DIR *directory) const noexcept {
    if (directory != nullptr) {
      static_cast<void>(::closedir(directory));
    }
  }
};
using Directory = std::unique_ptr<DIR, DirectoryDeleter>;

struct KeyDeleter {
  void operator()(ssh_key_struct *key) const noexcept {
    if (key != nullptr) {
      ssh_key_free(key);
    }
  }
};
using Key = std::unique_ptr<ssh_key_struct, KeyDeleter>;

[[nodiscard]] auto system_message(std::string_view operation) -> std::string {
  return std::string(operation) + ": " +
         std::error_code(errno, std::generic_category()).message();
}

[[nodiscard]] auto random_suffix() -> std::expected<std::string, std::string> {
  std::array<unsigned char, 8> bytes{};
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count =
        ::getrandom(bytes.data() + offset, bytes.size() - offset, 0);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      return std::unexpected(system_message("cannot generate backup name"));
    }
    offset += static_cast<std::size_t>(count);
  }
  constexpr std::string_view digits = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2U);
  for (const auto byte : bytes) {
    result.push_back(digits[byte >> 4U]);
    result.push_back(digits[byte & 0x0fU]);
  }
  return result;
}

[[nodiscard]] auto open_private_directory(const std::filesystem::path &path,
                                          bool create)
    -> std::expected<Descriptor, std::string> {
  if (create && ::mkdir(path.c_str(), S_IRWXU) != 0 && errno != EEXIST) {
    return std::unexpected(system_message("cannot create backup directory"));
  }
  Descriptor directory(
      ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
  if (directory.get() < 0) {
    return std::unexpected(system_message("cannot open backup directory"));
  }
  struct stat metadata{};
  if (::fstat(directory.get(), &metadata) != 0) {
    return std::unexpected(system_message("cannot inspect backup directory"));
  }
  if (!S_ISDIR(metadata.st_mode)) {
    return std::unexpected("backup path is not a directory: " + path.string());
  }
  if ((metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return std::unexpected(
        "backup directory must not be accessible by group or others: " +
        path.string());
  }
  return directory;
}

[[nodiscard]] auto read_file(int directory, std::string_view name,
                             std::size_t maximum, bool require_private)
    -> std::expected<std::string, std::string> {
  const std::string filename(name);
  Descriptor file(::openat(directory, filename.c_str(),
                           O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (file.get() < 0) {
    return std::unexpected(system_message("cannot open backup file"));
  }
  struct stat metadata{};
  if (::fstat(file.get(), &metadata) != 0) {
    return std::unexpected(system_message("cannot inspect backup file"));
  }
  if (!S_ISREG(metadata.st_mode) || metadata.st_size <= 0 ||
      static_cast<std::uintmax_t>(metadata.st_size) > maximum) {
    return std::unexpected("backup file has an invalid type or size: " +
                           filename);
  }
  if (require_private && (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return std::unexpected("backup file has unsafe permissions: " + filename);
  }
  std::string contents(static_cast<std::size_t>(metadata.st_size), '\0');
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const auto count =
        ::read(file.get(), contents.data() + offset, contents.size() - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      return std::unexpected(system_message("cannot read backup file"));
    }
    offset += static_cast<std::size_t>(count);
  }
  return contents;
}

[[nodiscard]] auto write_file(int directory, std::string_view name,
                              std::string_view contents)
    -> std::expected<void, std::string> {
  const std::string filename(name);
  Descriptor file(::openat(directory, filename.c_str(),
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                           S_IRUSR | S_IWUSR));
  if (file.get() < 0) {
    return std::unexpected(system_message("cannot create backup file"));
  }
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const auto count =
        ::write(file.get(), contents.data() + offset, contents.size() - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      return std::unexpected(system_message("cannot write backup file"));
    }
    offset += static_cast<std::size_t>(count);
  }
  if (::fsync(file.get()) != 0) {
    return std::unexpected(system_message("cannot flush backup file"));
  }
  return {};
}

void remove_fixed_snapshot(int parent, std::string_view name) noexcept {
  const std::string directory_name(name);
  Descriptor snapshot(
      ::openat(parent, directory_name.c_str(),
               O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
  if (snapshot.get() >= 0) {
    for (const auto filename : {database_name, host_key_name, manifest_name}) {
      const std::string entry(filename);
      static_cast<void>(::unlinkat(snapshot.get(), entry.c_str(), 0));
    }
  }
  static_cast<void>(::unlinkat(parent, directory_name.c_str(), AT_REMOVEDIR));
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- security-sensitive syscall failures stay adjacent to their cleanup
[[nodiscard]] auto copy_host_key(const std::filesystem::path &source,
                                 int destination_directory,
                                 std::string_view destination_name)
    -> std::expected<void, std::string> {
  Descriptor input(
      ::open(source.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (input.get() < 0) {
    return std::unexpected(system_message("cannot open host key"));
  }
  struct stat metadata{};
  if (::fstat(input.get(), &metadata) != 0) {
    return std::unexpected(system_message("cannot inspect host key"));
  }
  if (!S_ISREG(metadata.st_mode) || metadata.st_size <= 0 ||
      static_cast<std::uintmax_t>(metadata.st_size) > max_host_key_size) {
    return std::unexpected("host key has an invalid type or size: " +
                           source.string());
  }
  if ((metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return std::unexpected(
        "host key must not be accessible by group or others: " +
        source.string());
  }

  const std::string output_name(destination_name);
  Descriptor output(::openat(
      destination_directory, output_name.c_str(),
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR));
  if (output.get() < 0) {
    return std::unexpected(system_message("cannot create host-key backup"));
  }
  std::array<char, 4096> buffer{};
  std::uintmax_t copied = 0;
  for (;;) {
    const auto count = ::read(input.get(), buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      return std::unexpected(system_message("cannot read host key"));
    }
    if (count == 0) {
      break;
    }
    copied += static_cast<std::uintmax_t>(count);
    if (copied > max_host_key_size) {
      return std::unexpected("host key changed while it was backed up");
    }
    std::size_t offset = 0;
    while (offset < static_cast<std::size_t>(count)) {
      const auto written = ::write(output.get(), buffer.data() + offset,
                                   static_cast<std::size_t>(count) - offset);
      if (written < 0 && errno == EINTR) {
        continue;
      }
      if (written <= 0) {
        return std::unexpected(system_message("cannot write host-key backup"));
      }
      offset += static_cast<std::size_t>(written);
    }
  }
  if (copied != static_cast<std::uintmax_t>(metadata.st_size)) {
    return std::unexpected("host key changed while it was backed up");
  }
  if (::fsync(output.get()) != 0) {
    return std::unexpected(system_message("cannot flush host-key backup"));
  }
  return {};
}

[[nodiscard]] auto manifest_contents(std::int64_t created_at) -> std::string {
  return "ANVIL-BACKUP 1\ncreated_at=" + std::to_string(created_at) + '\n';
}

[[nodiscard]] auto parse_manifest(int directory)
    -> std::expected<std::int64_t, std::string> {
  auto contents = read_file(directory, manifest_name, max_manifest_size, true);
  if (!contents) {
    return std::unexpected(contents.error());
  }
  constexpr std::string_view prefix = "ANVIL-BACKUP 1\ncreated_at=";
  if (!contents->starts_with(prefix) || !contents->ends_with('\n')) {
    return std::unexpected("backup manifest has an unsupported format");
  }
  const auto number = std::string_view(*contents).substr(
      prefix.size(), contents->size() - prefix.size() - 1U);
  std::int64_t timestamp = 0;
  const auto [end, error] =
      std::from_chars(number.data(), number.data() + number.size(), timestamp);
  if (error != std::errc{} || end != number.data() + number.size() ||
      timestamp < 0) {
    return std::unexpected("backup manifest has an invalid creation time");
  }
  return timestamp;
}

[[nodiscard]] auto validate_private_regular_file(int directory,
                                                 std::string_view name)
    -> std::expected<void, std::string> {
  const std::string filename(name);
  Descriptor file(::openat(directory, filename.c_str(),
                           O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (file.get() < 0) {
    return std::unexpected(system_message("cannot open backup file"));
  }
  struct stat metadata{};
  if (::fstat(file.get(), &metadata) != 0) {
    return std::unexpected(system_message("cannot inspect backup file"));
  }
  if (!S_ISREG(metadata.st_mode) || metadata.st_size <= 0) {
    return std::unexpected("backup file has an invalid type or size: " +
                           filename);
  }
  if ((metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return std::unexpected("backup file has unsafe permissions: " + filename);
  }
  return {};
}

struct Target {
  Descriptor directory;
  std::filesystem::path parent;
  std::string name;
  std::string temporary;
};

[[nodiscard]] auto prepare_target(const std::filesystem::path &path,
                                  std::string_view purpose)
    -> std::expected<Target, std::string> {
  const auto name = path.filename().string();
  if (name.empty() || name == "." || name == "..") {
    return std::unexpected(std::string(purpose) + " path must name a file");
  }
  auto parent = path.parent_path();
  if (parent.empty()) {
    parent = ".";
  }
  Descriptor directory(
      ::open(parent.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
  if (directory.get() < 0) {
    return std::unexpected(system_message("cannot open restore directory"));
  }
  struct stat metadata{};
  if (::fstatat(directory.get(), name.c_str(), &metadata,
                AT_SYMLINK_NOFOLLOW) == 0 ||
      errno != ENOENT) {
    return std::unexpected(std::string(purpose) +
                           " destination already exists: " + path.string());
  }
  auto suffix = random_suffix();
  if (!suffix) {
    return std::unexpected(suffix.error());
  }
  return Target{std::move(directory), std::move(parent), name,
                "." + name + ".restore-tmp-" + *suffix};
}

[[nodiscard]] auto validate_private_key(const std::filesystem::path &path)
    -> std::expected<void, std::string> {
  ssh_key raw_key = nullptr;
  const auto imported = ssh_pki_import_privkey_file(path.c_str(), nullptr,
                                                    nullptr, nullptr, &raw_key);
  Key key(raw_key);
  if (imported != SSH_OK || !key) {
    return std::unexpected("backup contains an invalid private host key");
  }
  return {};
}

} // namespace

auto create_snapshot(store::SqliteStore &database,
                     const std::filesystem::path &host_key,
                     const std::filesystem::path &backup_directory,
                     std::chrono::system_clock::time_point now)
    -> std::expected<Snapshot, std::string> {
  auto root = open_private_directory(backup_directory, true);
  if (!root) {
    return std::unexpected(root.error());
  }
  auto suffix = random_suffix();
  if (!suffix) {
    return std::unexpected(suffix.error());
  }
  const auto epoch =
      std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
          .count();
  if (epoch < 0) {
    return std::unexpected("backup creation time precedes the Unix epoch");
  }
  const auto temporary = std::string(temporary_prefix) + *suffix;
  if (::mkdirat(root->get(), temporary.c_str(), S_IRWXU) != 0) {
    return std::unexpected(system_message("cannot create temporary backup"));
  }
  Descriptor working(::openat(root->get(), temporary.c_str(),
                              O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
  if (working.get() < 0) {
    remove_fixed_snapshot(root->get(), temporary);
    return std::unexpected(system_message("cannot open temporary backup"));
  }

  if (auto valid = validate_private_key(host_key); !valid) {
    working = Descriptor{};
    remove_fixed_snapshot(root->get(), temporary);
    return std::unexpected(valid.error());
  }

  const auto database_path =
      backup_directory / temporary / std::string(database_name);
  if (auto copied = database.backup_to(database_path); !copied) {
    working = Descriptor{};
    remove_fixed_snapshot(root->get(), temporary);
    return std::unexpected(copied.error().detail);
  }
  if (auto copied = copy_host_key(host_key, working.get(), host_key_name);
      !copied) {
    working = Descriptor{};
    remove_fixed_snapshot(root->get(), temporary);
    return std::unexpected(copied.error());
  }
  if (auto written =
          write_file(working.get(), manifest_name, manifest_contents(epoch));
      !written) {
    working = Descriptor{};
    remove_fixed_snapshot(root->get(), temporary);
    return std::unexpected(written.error());
  }
  if (::fsync(working.get()) != 0) {
    working = Descriptor{};
    remove_fixed_snapshot(root->get(), temporary);
    return std::unexpected(system_message("cannot flush temporary backup"));
  }

  const auto final_name =
      std::string(snapshot_prefix) + std::to_string(epoch) + '-' + *suffix;
  working = Descriptor{};
  if (::renameat(root->get(), temporary.c_str(), root->get(),
                 final_name.c_str()) != 0) {
    remove_fixed_snapshot(root->get(), temporary);
    return std::unexpected(system_message("cannot publish backup"));
  }
  if (::fsync(root->get()) != 0) {
    return std::unexpected(system_message("cannot flush backup directory"));
  }
  return Snapshot{backup_directory / final_name, now};
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- fail-closed directory walking keeps every retention check explicit
auto prune_snapshots(const std::filesystem::path &backup_directory,
                     std::chrono::seconds retention,
                     std::chrono::system_clock::time_point now)
    -> std::expected<void, std::string> {
  if (retention <= std::chrono::seconds::zero()) {
    return std::unexpected("backup retention must be positive");
  }
  auto root = open_private_directory(backup_directory, false);
  if (!root) {
    return std::unexpected(root.error());
  }
  const auto duplicate = ::dup(root->get());
  if (duplicate < 0) {
    return std::unexpected(system_message("cannot scan backup directory"));
  }
  Directory entries(::fdopendir(duplicate));
  if (!entries) {
    static_cast<void>(::close(duplicate));
    return std::unexpected(system_message("cannot scan backup directory"));
  }

  std::vector<std::pair<std::string, std::int64_t>> snapshots;
  for (;;) {
    errno = 0;
    const auto *entry = ::readdir(entries.get());
    if (entry == nullptr) {
      if (errno != 0) {
        return std::unexpected(system_message("cannot read backup directory"));
      }
      break;
    }
    const std::string_view name(entry->d_name);
    if (!name.starts_with(snapshot_prefix)) {
      continue;
    }
    Descriptor snapshot(
        ::openat(root->get(), entry->d_name,
                 O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
    if (snapshot.get() < 0) {
      continue;
    }
    auto created = parse_manifest(snapshot.get());
    if (created) {
      snapshots.emplace_back(name, *created);
    }
  }
  if (snapshots.empty()) {
    return {};
  }
  const auto newest = std::max_element(snapshots.begin(), snapshots.end(),
                                       [](const auto &left, const auto &right) {
                                         return left.second < right.second;
                                       });
  const auto cutoff =
      std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
          .count() -
      retention.count();
  for (const auto &[name, created] : snapshots) {
    if (created >= cutoff || name == newest->first) {
      continue;
    }
    remove_fixed_snapshot(root->get(), name);
    struct stat remaining{};
    if (::fstatat(root->get(), name.c_str(), &remaining, AT_SYMLINK_NOFOLLOW) ==
            0 ||
        errno != ENOENT) {
      return std::unexpected("cannot remove expired backup safely: " + name);
    }
  }
  if (::fsync(root->get()) != 0) {
    return std::unexpected(
        system_message("cannot flush pruned backup directory"));
  }
  return {};
}

auto restore_snapshot(const std::filesystem::path &snapshot,
                      const std::filesystem::path &database,
                      const std::filesystem::path &host_key)
    -> std::expected<void, std::string> {
  Descriptor source(::open(snapshot.c_str(),
                           O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
  if (source.get() < 0) {
    return std::unexpected(system_message("cannot open backup snapshot"));
  }
  struct stat source_metadata{};
  if (::fstat(source.get(), &source_metadata) != 0 ||
      (source_metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return std::unexpected("backup snapshot has unsafe permissions");
  }
  if (auto manifest = parse_manifest(source.get()); !manifest) {
    return std::unexpected(manifest.error());
  }
  if (auto valid = validate_private_regular_file(source.get(), database_name);
      !valid) {
    return std::unexpected(valid.error());
  }
  if (database.lexically_normal() == host_key.lexically_normal()) {
    return std::unexpected("database and host-key destinations must differ");
  }
  auto database_target = prepare_target(database, "database");
  if (!database_target) {
    return std::unexpected(database_target.error());
  }
  for (const auto suffix :
       {std::string_view("-wal"), std::string_view("-shm")}) {
    struct stat metadata{};
    const auto sidecar = database_target->name + std::string(suffix);
    if (::fstatat(database_target->directory.get(), sidecar.c_str(), &metadata,
                  AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
      return std::unexpected("database sidecar already exists: " + sidecar);
    }
  }
  auto key_target = prepare_target(host_key, "host key");
  if (!key_target) {
    return std::unexpected(key_target.error());
  }

  const auto restored_database =
      database_target->parent / database_target->temporary;
  auto restored = store::SqliteStore::restore_from(
      snapshot / std::string(database_name), restored_database);
  if (!restored) {
    return std::unexpected(restored.error().detail);
  }
  const auto cleanup_database = [&] {
    static_cast<void>(::unlinkat(database_target->directory.get(),
                                 database_target->temporary.c_str(), 0));
  };

  auto copied_key =
      copy_host_key(snapshot / std::string(host_key_name),
                    key_target->directory.get(), key_target->temporary);
  if (!copied_key) {
    cleanup_database();
    return std::unexpected(copied_key.error());
  }
  const auto restored_key = key_target->parent / key_target->temporary;
  if (auto valid = validate_private_key(restored_key); !valid) {
    cleanup_database();
    static_cast<void>(::unlinkat(key_target->directory.get(),
                                 key_target->temporary.c_str(), 0));
    return std::unexpected(valid.error());
  }

  if (::linkat(database_target->directory.get(),
               database_target->temporary.c_str(),
               database_target->directory.get(), database_target->name.c_str(),
               0) != 0) {
    cleanup_database();
    static_cast<void>(::unlinkat(key_target->directory.get(),
                                 key_target->temporary.c_str(), 0));
    return std::unexpected(system_message("cannot publish restored database"));
  }
  if (::linkat(key_target->directory.get(), key_target->temporary.c_str(),
               key_target->directory.get(), key_target->name.c_str(), 0) != 0) {
    static_cast<void>(::unlinkat(database_target->directory.get(),
                                 database_target->name.c_str(), 0));
    cleanup_database();
    static_cast<void>(::unlinkat(key_target->directory.get(),
                                 key_target->temporary.c_str(), 0));
    return std::unexpected(system_message("cannot publish restored host key"));
  }
  cleanup_database();
  static_cast<void>(::unlinkat(key_target->directory.get(),
                               key_target->temporary.c_str(), 0));
  if (::fsync(database_target->directory.get()) != 0 ||
      ::fsync(key_target->directory.get()) != 0) {
    return std::unexpected(system_message("cannot flush restored state"));
  }
  return {};
}

} // namespace anvil::server::backup
