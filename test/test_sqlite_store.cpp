#include "sqlite_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using anvil::store::ErrorCode;
using anvil::store::SqliteOptions;
using anvil::store::SqliteStore;
using anvil::store::TransactionMode;
using anvil::store::detail::SqliteMigration;
using namespace std::chrono_literals;

class TemporaryDatabase {
public:
  TemporaryDatabase() {
    static std::atomic<unsigned int> sequence{};
    directory_ = std::filesystem::temp_directory_path() /
                 ("anvil-sqlite-" + std::to_string(::getpid()) + '-' +
                  std::to_string(sequence.fetch_add(1)));
    std::filesystem::create_directory(directory_);
    path_ = directory_ / "anvil.db";
  }

  ~TemporaryDatabase() {
    std::error_code ignored;
    std::filesystem::remove(path_.string() + "-shm", ignored);
    std::filesystem::remove(path_.string() + "-wal", ignored);
    std::filesystem::remove(path_, ignored);
    std::filesystem::remove(directory_ / "linked.db", ignored);
    std::filesystem::remove(directory_, ignored);
  }

  TemporaryDatabase(const TemporaryDatabase &) = delete;
  auto operator=(const TemporaryDatabase &) -> TemporaryDatabase & = delete;

  [[nodiscard]] auto path() const -> const std::filesystem::path & {
    return path_;
  }

  [[nodiscard]] auto directory() const -> const std::filesystem::path & {
    return directory_;
  }

private:
  std::filesystem::path directory_;
  std::filesystem::path path_;
};

constexpr std::array probe_migrations{
    SqliteMigration{1, "CREATE TABLE probe(value INTEGER NOT NULL)"},
};

[[nodiscard]] auto open_probe(const std::filesystem::path &path,
                              SqliteOptions options = {}) {
  return anvil::store::detail::open_sqlite_store(path, probe_migrations,
                                                  options);
}

} // namespace

TEST_CASE("SQLite startup claims an empty database without domain tables") {
  TemporaryDatabase database;

  auto store = SqliteStore::open(database.path());

  REQUIRE(store.has_value());
  CHECK((*store)->schema_version() == 1);
  auto transaction = (*store)->begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());
  CHECK((*store)->scalar_for_testing(*transaction, "PRAGMA application_id") ==
        0x414E564C);
  CHECK((*store)->scalar_for_testing(*transaction, "PRAGMA user_version") ==
        1);
  CHECK((*store)->scalar_for_testing(*transaction, "PRAGMA synchronous") ==
        2);
  CHECK((*store)->scalar_for_testing(*transaction,
                                     "PRAGMA wal_autocheckpoint") == 1000);
  CHECK((*store)->scalar_for_testing(
            *transaction,
            "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE "
            "'sqlite_%'") == 0);
  CHECK(transaction->commit().has_value());

  struct stat metadata {};
  REQUIRE(::stat(database.path().c_str(), &metadata) == 0);
  CHECK((metadata.st_mode & (S_IRWXG | S_IRWXO)) == 0);

  auto reopened = SqliteStore::open(database.path());
  REQUIRE(reopened.has_value());
  CHECK((*reopened)->schema_version() == 1);
}

TEST_CASE("SQLite migrations are ordered and atomic") {
  TemporaryDatabase database;
  constexpr std::array migrations{
      SqliteMigration{1, "CREATE TABLE probe(value INTEGER NOT NULL)"},
      SqliteMigration{2, "INSERT INTO probe(value) VALUES(7)"},
  };

  auto store =
      anvil::store::detail::open_sqlite_store(database.path(), migrations);

  REQUIRE(store.has_value());
  CHECK((*store)->schema_version() == 2);
  auto transaction = (*store)->begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());
  CHECK((*store)->scalar_for_testing(*transaction, "SELECT value FROM probe") ==
        7);
  CHECK(transaction->commit().has_value());
}

TEST_CASE("a failed SQLite migration rolls back the whole pending chain") {
  TemporaryDatabase database;
  constexpr std::array broken{
      SqliteMigration{1, "CREATE TABLE probe(value INTEGER NOT NULL)"},
      SqliteMigration{2, "THIS IS NOT SQL"},
  };

  const auto failed =
      anvil::store::detail::open_sqlite_store(database.path(), broken);

  REQUIRE_FALSE(failed.has_value());
  auto recovered = open_probe(database.path());
  REQUIRE(recovered.has_value());
  auto transaction = (*recovered)->begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());
  CHECK((*recovered)->scalar_for_testing(*transaction,
                                         "SELECT count(*) FROM probe") == 0);
  CHECK(transaction->commit().has_value());
}

TEST_CASE("SQLite startup rejects newer and foreign databases") {
  SECTION("newer schema") {
    TemporaryDatabase database;
    auto store = SqliteStore::open(database.path());
    REQUIRE(store.has_value());
    auto transaction = (*store)->begin(TransactionMode::read_write);
    REQUIRE(transaction.has_value());
    REQUIRE((*store)
                ->execute_for_testing(*transaction, "PRAGMA user_version=2")
                .has_value());
    REQUIRE(transaction->commit().has_value());

    const auto reopened = SqliteStore::open(database.path());
    REQUIRE_FALSE(reopened.has_value());
    CHECK(reopened.error().code == ErrorCode::invalid_data);
  }

  SECTION("foreign application ID") {
    TemporaryDatabase database;
    auto store = SqliteStore::open(database.path());
    REQUIRE(store.has_value());
    auto transaction = (*store)->begin(TransactionMode::read_write);
    REQUIRE(transaction.has_value());
    REQUIRE((*store)
                ->execute_for_testing(*transaction, "PRAGMA application_id=1")
                .has_value());
    REQUIRE(transaction->commit().has_value());

    const auto reopened = SqliteStore::open(database.path());
    REQUIRE_FALSE(reopened.has_value());
    CHECK(reopened.error().code == ErrorCode::invalid_data);
  }
}

TEST_CASE("SQLite refuses non-persistent and symlink database paths") {
  const auto in_memory = SqliteStore::open(":memory:");
  REQUIRE_FALSE(in_memory.has_value());
  CHECK(in_memory.error().code == ErrorCode::invalid_data);

  TemporaryDatabase database;
  REQUIRE(SqliteStore::open(database.path()).has_value());
  const auto link = database.directory() / "linked.db";
  std::filesystem::create_symlink(database.path(), link);

  const auto linked = SqliteStore::open(link);
  REQUIRE_FALSE(linked.has_value());
  CHECK(linked.error().code == ErrorCode::unavailable);
}

TEST_CASE("WAL readers and writers use independent transaction connections") {
  TemporaryDatabase database;
  auto reader_store = open_probe(database.path());
  auto writer_store = open_probe(database.path());
  REQUIRE(reader_store.has_value());
  REQUIRE(writer_store.has_value());

  auto slow_reader = (*reader_store)->begin(TransactionMode::read_only);
  REQUIRE(slow_reader.has_value());
  REQUIRE((*reader_store)
              ->scalar_for_testing(*slow_reader, "SELECT count(*) FROM probe") ==
          0);

  auto writer = (*writer_store)->begin(TransactionMode::read_write);
  REQUIRE(writer.has_value());
  REQUIRE((*writer_store)
              ->execute_for_testing(*writer,
                                    "INSERT INTO probe(value) VALUES(1)")
              .has_value());
  CHECK(writer->commit().has_value());
  CHECK((*reader_store)
            ->scalar_for_testing(*slow_reader, "SELECT count(*) FROM probe") ==
        0);
  CHECK(slow_reader->commit().has_value());

  auto uncommitted_writer =
      (*writer_store)->begin(TransactionMode::read_write);
  REQUIRE(uncommitted_writer.has_value());
  REQUIRE((*writer_store)
              ->execute_for_testing(*uncommitted_writer,
                                    "INSERT INTO probe(value) VALUES(2)")
              .has_value());
  auto unrelated_reader =
      (*reader_store)->begin(TransactionMode::read_only);
  REQUIRE(unrelated_reader.has_value());
  CHECK((*reader_store)
            ->scalar_for_testing(*unrelated_reader,
                                 "SELECT count(*) FROM probe") == 1);
  CHECK(unrelated_reader->commit().has_value());
  uncommitted_writer->rollback();
}

TEST_CASE("a competing SQLite writer times out as a conflict") {
  TemporaryDatabase database;
  const SqliteOptions short_wait{50ms};
  auto first = open_probe(database.path(), short_wait);
  auto second = open_probe(database.path(), short_wait);
  REQUIRE(first.has_value());
  REQUIRE(second.has_value());

  auto held = (*first)->begin(TransactionMode::read_write);
  REQUIRE(held.has_value());
  const auto blocked = (*second)->begin(TransactionMode::read_write);

  REQUIRE_FALSE(blocked.has_value());
  CHECK(blocked.error().code == ErrorCode::conflict);
  held->rollback();
}

TEST_CASE("read-only SQLite transactions reject writes") {
  TemporaryDatabase database;
  auto store = open_probe(database.path());
  REQUIRE(store.has_value());
  auto transaction = (*store)->begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());

  const auto written = (*store)->execute_for_testing(
      *transaction, "INSERT INTO probe(value) VALUES(1)");

  REQUIRE_FALSE(written.has_value());
  CHECK(written.error().code == ErrorCode::unavailable);
}

TEST_CASE("a SQLite store constructed before fork opens only child-local handles") {
  TemporaryDatabase database;
  auto store = open_probe(database.path());
  REQUIRE(store.has_value());

  const auto child = ::fork();
  REQUIRE(child >= 0);
  if (child == 0) {
    auto transaction = (*store)->begin(TransactionMode::read_only);
    const bool passed =
        transaction.has_value() &&
        (*store)->scalar_for_testing(*transaction,
                                     "SELECT count(*) FROM probe") == 0 &&
        transaction->commit().has_value();
    ::_exit(passed ? 0 : 1);
  }

  int status = 0;
  REQUIRE(::waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status));
  CHECK(WEXITSTATUS(status) == 0);

  auto parent_transaction = (*store)->begin(TransactionMode::read_only);
  REQUIRE(parent_transaction.has_value());
  CHECK(parent_transaction->commit().has_value());
}
