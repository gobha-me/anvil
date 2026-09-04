#include "backup.hpp"
#include "sqlite_store.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libssh/libssh.h>
#include <libssh/libssh_version.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

#include <sys/stat.h>
#include <unistd.h>

namespace {

using anvil::server::backup::create_snapshot;
using anvil::server::backup::prune_snapshots;
using anvil::server::backup::restore_snapshot;
using anvil::store::SqliteStore;
using anvil::store::TransactionMode;
using namespace std::chrono_literals;

class TemporaryState {
public:
  TemporaryState() {
    static std::atomic<unsigned int> sequence{};
    directory_ = std::filesystem::temp_directory_path() /
                 ("anvil-backup-test-" + std::to_string(::getpid()) + '-' +
                  std::to_string(sequence.fetch_add(1)));
    std::filesystem::create_directory(directory_);
    std::filesystem::permissions(directory_, std::filesystem::perms::owner_all);
  }

  ~TemporaryState() {
    std::error_code ignored;
    std::filesystem::remove_all(directory_, ignored);
  }

  [[nodiscard]] auto path(std::string_view name) const
      -> std::filesystem::path {
    return directory_ / name;
  }

private:
  std::filesystem::path directory_;
};

void write_host_key(const std::filesystem::path &path) {
  ssh_key raw_key = nullptr;
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 12, 0)
  REQUIRE(ssh_pki_generate_key(SSH_KEYTYPE_ED25519, nullptr, &raw_key) ==
          SSH_OK);
#else
  REQUIRE(ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &raw_key) == SSH_OK);
#endif
  REQUIRE(raw_key != nullptr);
  char *exported = nullptr;
  REQUIRE(ssh_pki_export_privkey_base64(raw_key, nullptr, nullptr, nullptr,
                                        &exported) == SSH_OK);
  REQUIRE(exported != nullptr);
  {
    std::ofstream output(path);
    output << exported;
  }
  REQUIRE(::chmod(path.c_str(), S_IRUSR | S_IWUSR) == 0);
  ssh_string_free_char(exported);
  ssh_key_free(raw_key);
}

void seed_board(SqliteStore &store) {
  auto transaction = store.begin(TransactionMode::read_write);
  REQUIRE(transaction.has_value());
  REQUIRE(store
              .execute_for_testing(
                  *transaction,
                  "INSERT INTO users(handle, status, created_at) "
                  "VALUES('alice', 'active', 10);"
                  "INSERT INTO boards(board_id, name, title, created_at) "
                  "VALUES('00000000-0000-0000-0000-000000000001', "
                  "'general', 'General', 11);"
                  "INSERT INTO threads(thread_id, board_id, author_handle, "
                  "subject, created_at, updated_at) VALUES('thread-1', "
                  "'00000000-0000-0000-0000-000000000001', 'alice', "
                  "'Welcome', 12, 12);"
                  "INSERT INTO messages(message_id, board_id, thread_id, "
                  "author_handle, body, posted_at, received_at) VALUES("
                  "'message-1', "
                  "'00000000-0000-0000-0000-000000000001', 'thread-1', "
                  "'alice', 'restored content', 13, 14)")
              .has_value());
  REQUIRE(transaction->commit().has_value());
}

[[nodiscard]] auto read_bytes(const std::filesystem::path &path)
    -> std::string {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input),
          std::istreambuf_iterator<char>()};
}

[[nodiscard]] auto snapshot_count(const std::filesystem::path &directory)
    -> std::size_t {
  std::size_t count = 0;
  for (const auto &entry : std::filesystem::directory_iterator(directory)) {
    if (entry.path().filename().string().starts_with("anvil-backup-")) {
      ++count;
    }
  }
  return count;
}

[[nodiscard]] auto has_entry_with_prefix(const std::filesystem::path &directory,
                                         std::string_view prefix) -> bool {
  for (const auto &entry : std::filesystem::directory_iterator(directory)) {
    if (entry.path().filename().string().starts_with(prefix)) {
      return true;
    }
  }
  return false;
}

} // namespace

TEST_CASE("backup restores committed WAL content and the exact host key") {
  TemporaryState state;
  const auto database_path = state.path("live.db");
  const auto host_key = state.path("live_host_key");
  const auto backups = state.path("backups");
  write_host_key(host_key);
  const auto original_key = read_bytes(host_key);

  auto database = SqliteStore::open(database_path);
  REQUIRE(database.has_value());
  seed_board(**database);
  const auto created_at = std::chrono::system_clock::time_point{100s};
  auto snapshot = create_snapshot(**database, host_key, backups, created_at);
  INFO((snapshot ? std::string{} : snapshot.error()));
  REQUIRE(snapshot.has_value());
  CHECK(std::filesystem::is_regular_file(snapshot->path / "anvil.db"));
  CHECK(std::filesystem::is_regular_file(snapshot->path / "host_key"));
  CHECK((std::filesystem::status(snapshot->path).permissions() &
         std::filesystem::perms::group_all) == std::filesystem::perms::none);

  database->reset();
  std::filesystem::remove(database_path.string() + "-wal");
  std::filesystem::remove(database_path.string() + "-shm");
  REQUIRE(std::filesystem::remove(database_path));
  REQUIRE(std::filesystem::remove(host_key));

  auto restored = restore_snapshot(snapshot->path, database_path, host_key);
  REQUIRE(restored.has_value());
  CHECK(read_bytes(host_key) == original_key);
  auto reopened = SqliteStore::open(database_path);
  REQUIRE(reopened.has_value());
  auto transaction = (*reopened)->begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());
  auto body = (*reopened)->scalar_text_for_testing(
      *transaction, "SELECT body FROM messages WHERE message_id = 'message-1'");
  REQUIRE(body.has_value());
  CHECK(*body == "restored content");
}

TEST_CASE("backup retention removes only expired completed snapshots") {
  TemporaryState state;
  const auto database_path = state.path("live.db");
  const auto host_key = state.path("live_host_key");
  const auto backups = state.path("backups");
  write_host_key(host_key);
  auto database = SqliteStore::open(database_path);
  REQUIRE(database.has_value());

  auto oldest = create_snapshot(**database, host_key, backups,
                                std::chrono::system_clock::time_point{10s});
  INFO((oldest ? std::string{} : oldest.error()));
  REQUIRE(oldest);
  auto middle = create_snapshot(**database, host_key, backups,
                                std::chrono::system_clock::time_point{20s});
  INFO((middle ? std::string{} : middle.error()));
  REQUIRE(middle);
  auto newest = create_snapshot(**database, host_key, backups,
                                std::chrono::system_clock::time_point{30s});
  REQUIRE(newest.has_value());
  {
    std::ofstream unrelated(backups / "operator-note");
    unrelated << "preserve me";
  }
  std::filesystem::create_directory(backups / ".anvil-backup-tmp-interrupted");

  REQUIRE(prune_snapshots(backups, 75s,
                          std::chrono::system_clock::time_point{100s}));
  CHECK(snapshot_count(backups) == 1);
  CHECK(std::filesystem::exists(newest->path));
  CHECK(read_bytes(backups / "operator-note") == "preserve me");
  CHECK(
      std::filesystem::is_directory(backups / ".anvil-backup-tmp-interrupted"));
}

TEST_CASE("backup paths and restore targets fail closed") {
  TemporaryState state;
  const auto database_path = state.path("live.db");
  const auto host_key = state.path("live_host_key");
  const auto backups = state.path("backups");
  write_host_key(host_key);
  auto database = SqliteStore::open(database_path);
  REQUIRE(database.has_value());
  auto snapshot = create_snapshot(**database, host_key, backups,
                                  std::chrono::system_clock::time_point{10s});
  INFO((snapshot ? std::string{} : snapshot.error()));
  REQUIRE(snapshot.has_value());

  CHECK_FALSE(restore_snapshot(snapshot->path, database_path,
                               state.path("restored_key")));
  REQUIRE(::chmod((snapshot->path / "anvil.db").c_str(),
                  S_IRUSR | S_IWUSR | S_IRGRP) == 0);
  CHECK_FALSE(restore_snapshot(snapshot->path, state.path("restored.db"),
                               state.path("restored_key")));
  REQUIRE(::chmod((snapshot->path / "anvil.db").c_str(), S_IRUSR | S_IWUSR) ==
          0);
  const auto database_backup = snapshot->path / "anvil.db";
  const auto original_database = read_bytes(database_backup);
  {
    std::fstream corrupted(database_backup,
                           std::ios::in | std::ios::out | std::ios::binary);
    corrupted.write("not-a-sqlite-db", 15);
  }
  CHECK_FALSE(restore_snapshot(snapshot->path, state.path("restored.db"),
                               state.path("restored_key")));
  {
    std::ofstream repaired(database_backup, std::ios::binary | std::ios::trunc);
    repaired.write(original_database.data(),
                   static_cast<std::streamsize>(original_database.size()));
  }
  REQUIRE(::chmod(database_backup.c_str(), S_IRUSR | S_IWUSR) == 0);
  REQUIRE(::chmod((snapshot->path / "manifest").c_str(),
                  S_IRUSR | S_IWUSR | S_IRGRP) == 0);
  CHECK_FALSE(restore_snapshot(snapshot->path, state.path("restored.db"),
                               state.path("restored_key")));

  const auto linked = state.path("linked-backups");
  std::filesystem::create_directory_symlink(backups, linked);
  REQUIRE(std::filesystem::is_symlink(linked));
  CHECK_FALSE(create_snapshot(**database, host_key, linked,
                              std::chrono::system_clock::time_point{20s}));
}

TEST_CASE("failed snapshot validation removes its temporary directory") {
  TemporaryState state;
  const auto database_path = state.path("live.db");
  const auto host_key = state.path("invalid_host_key");
  const auto backups = state.path("backups");
  {
    std::ofstream output(host_key);
    output << "not a private key";
  }
  REQUIRE(::chmod(host_key.c_str(), S_IRUSR | S_IWUSR) == 0);
  auto database = SqliteStore::open(database_path);
  REQUIRE(database.has_value());

  const auto snapshot =
      create_snapshot(**database, host_key, backups,
                      std::chrono::system_clock::time_point{10s});
  REQUIRE_FALSE(snapshot.has_value());
  CHECK(snapshot.error() == "backup contains an invalid private host key");
  CHECK(std::filesystem::is_empty(backups));
}

TEST_CASE("host-key restore rejects symlinks and removes target temporaries") {
  TemporaryState state;
  const auto database_path = state.path("live.db");
  const auto host_key = state.path("live_host_key");
  const auto backups = state.path("backups");
  write_host_key(host_key);
  auto database = SqliteStore::open(database_path);
  REQUIRE(database.has_value());
  auto snapshot = create_snapshot(**database, host_key, backups,
                                  std::chrono::system_clock::time_point{10s});
  REQUIRE(snapshot.has_value());

  REQUIRE(std::filesystem::remove(snapshot->path / "host_key"));
  std::filesystem::create_symlink(host_key, snapshot->path / "host_key");
  const auto restored_database = state.path("restored.db");
  const auto restored_key = state.path("restored_key");
  const auto restored =
      restore_snapshot(snapshot->path, restored_database, restored_key);
  REQUIRE_FALSE(restored.has_value());
  CHECK(restored.error().starts_with("cannot open host key:"));
  CHECK_FALSE(std::filesystem::exists(restored_database));
  CHECK_FALSE(std::filesystem::exists(restored_key));
  CHECK_FALSE(
      has_entry_with_prefix(state.path("."), ".restored.db.restore-tmp-"));
  CHECK_FALSE(
      has_entry_with_prefix(state.path("."), ".restored_key.restore-tmp-"));
}

TEST_CASE("pruning fails closed when an expired snapshot cannot be emptied") {
  TemporaryState state;
  const auto database_path = state.path("live.db");
  const auto host_key = state.path("live_host_key");
  const auto backups = state.path("backups");
  const auto outside = state.path("outside");
  write_host_key(host_key);
  auto database = SqliteStore::open(database_path);
  REQUIRE(database.has_value());
  auto expired = create_snapshot(**database, host_key, backups,
                                 std::chrono::system_clock::time_point{10s});
  REQUIRE(expired.has_value());
  auto newest = create_snapshot(**database, host_key, backups,
                                std::chrono::system_clock::time_point{30s});
  REQUIRE(newest.has_value());

  {
    std::ofstream extra(expired->path / "operator-owned");
    extra << "preserve me";
  }
  std::filesystem::create_directory(outside);
  {
    std::ofstream sentinel(outside / "sentinel");
    sentinel << "outside";
  }
  const auto hostile_link = backups / "anvil-backup-hostile-link";
  std::filesystem::create_directory_symlink(outside, hostile_link);
  const auto incomplete = backups / "anvil-backup-incomplete";
  std::filesystem::create_directory(incomplete);

  const auto pruned = prune_snapshots(
      backups, 10s, std::chrono::system_clock::time_point{100s});
  REQUIRE_FALSE(pruned.has_value());
  CHECK(pruned.error() == "cannot remove expired backup safely: " +
                              expired->path.filename().string());
  CHECK(std::filesystem::is_directory(expired->path));
  CHECK(read_bytes(expired->path / "operator-owned") == "preserve me");
  CHECK_FALSE(std::filesystem::exists(expired->path / "anvil.db"));
  CHECK_FALSE(std::filesystem::exists(expired->path / "host_key"));
  CHECK_FALSE(std::filesystem::exists(expired->path / "manifest"));
  CHECK(std::filesystem::exists(newest->path));
  CHECK(std::filesystem::is_symlink(hostile_link));
  CHECK(read_bytes(outside / "sentinel") == "outside");
  CHECK(std::filesystem::is_directory(incomplete));
}
