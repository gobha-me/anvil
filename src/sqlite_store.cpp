#include "sqlite_store.hpp"

#include <sqlite3.h>

#include <array>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <unistd.h>

namespace anvil::store {
namespace {

constexpr std::int64_t anvil_application_id = 0x414E564C;
constexpr std::array production_migrations{
    detail::SqliteMigration{1, {}},
};

struct DatabaseDeleter {
  void operator()(sqlite3 *database) const noexcept {
    if (database != nullptr) {
      static_cast<void>(sqlite3_close_v2(database));
    }
  }
};
using Database = std::unique_ptr<sqlite3, DatabaseDeleter>;

struct StatementDeleter {
  void operator()(sqlite3_stmt *statement) const noexcept {
    if (statement != nullptr) {
      static_cast<void>(sqlite3_finalize(statement));
    }
  }
};
using Statement = std::unique_ptr<sqlite3_stmt, StatementDeleter>;

[[nodiscard]] auto error_code(int result) noexcept -> ErrorCode {
  switch (result & 0xff) {
  case SQLITE_BUSY:
  case SQLITE_LOCKED:
    return ErrorCode::conflict;
  case SQLITE_CONSTRAINT:
    return ErrorCode::constraint_violation;
  case SQLITE_CORRUPT:
  case SQLITE_FORMAT:
  case SQLITE_MISMATCH:
  case SQLITE_NOTADB:
  case SQLITE_SCHEMA:
    return ErrorCode::invalid_data;
  case SQLITE_MISUSE:
    return ErrorCode::invalid_state;
  case SQLITE_CANTOPEN:
  case SQLITE_FULL:
  case SQLITE_IOERR:
  case SQLITE_NOMEM:
  case SQLITE_READONLY:
    return ErrorCode::unavailable;
  default:
    return ErrorCode::internal;
  }
}

[[nodiscard]] auto sqlite_error(sqlite3 *database, int result,
                                std::string_view operation) -> Error {
  std::string detail(operation);
  detail += ": ";
  if (database != nullptr) {
    detail += sqlite3_errmsg(database);
  } else {
    detail += sqlite3_errstr(result);
  }
  return {error_code(result), std::move(detail)};
}

[[nodiscard]] auto invalid_data(std::string detail) -> Error {
  return {ErrorCode::invalid_data, std::move(detail)};
}

[[nodiscard]] auto validate_options(const SqliteOptions &options)
    -> std::expected<void, Error> {
  const auto count = options.busy_timeout.count();
  if (count <= 0 || count > INT_MAX) {
    return std::unexpected(Error{ErrorCode::invalid_state,
                                 "SQLite busy timeout is out of range"});
  }
  return {};
}

[[nodiscard]] auto validate_migrations(
    std::span<const detail::SqliteMigration> migrations)
    -> std::expected<void, Error> {
  std::uint32_t expected = 1;
  for (const auto &migration : migrations) {
    if (migration.version != expected) {
      return std::unexpected(Error{
          ErrorCode::invalid_state,
          "SQLite migrations must be contiguous and start at version 1"});
    }
    ++expected;
  }
  return {};
}

[[nodiscard]] auto ensure_database_file(const std::filesystem::path &path)
    -> std::expected<void, Error> {
  const auto &native = path.native();
  if (native.empty() || native == ":memory:" ||
      native.find('\0') != std::string::npos) {
    return std::unexpected(Error{ErrorCode::invalid_data,
                                 "SQLite database path is not a persistent file"});
  }

  const auto descriptor = ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL |
                                                   O_CLOEXEC | O_NOFOLLOW,
                                 S_IRUSR | S_IWUSR);
  if (descriptor >= 0) {
    if (::close(descriptor) != 0) {
      return std::unexpected(
          Error{ErrorCode::unavailable,
                "cannot close newly created SQLite database: " +
                    std::error_code(errno, std::generic_category()).message()});
    }
    return {};
  }
  if (errno == EEXIST) {
    return {};
  }
  return std::unexpected(
      Error{ErrorCode::unavailable,
            "cannot create SQLite database: " +
                std::error_code(errno, std::generic_category()).message()});
}

[[nodiscard]] auto exec(sqlite3 *database, std::string_view sql,
                        std::string_view operation)
    -> std::expected<void, Error> {
  char *raw_message = nullptr;
  const std::string statement(sql);
  const auto result =
      sqlite3_exec(database, statement.c_str(), nullptr, nullptr, &raw_message);
  if (result == SQLITE_OK) {
    sqlite3_free(raw_message);
    return {};
  }
  std::string detail(operation);
  detail += ": ";
  detail += raw_message != nullptr ? raw_message : sqlite3_errmsg(database);
  sqlite3_free(raw_message);
  return std::unexpected(Error{error_code(result), std::move(detail)});
}

[[nodiscard]] auto prepare(sqlite3 *database, std::string_view sql,
                           std::string_view operation)
    -> std::expected<Statement, Error> {
  sqlite3_stmt *raw_statement = nullptr;
  const auto result = sqlite3_prepare_v3(database, sql.data(),
                                         static_cast<int>(sql.size()),
                                         SQLITE_PREPARE_PERSISTENT,
                                         &raw_statement, nullptr);
  if (result != SQLITE_OK) {
    return std::unexpected(sqlite_error(database, result, operation));
  }
  return Statement(raw_statement);
}

[[nodiscard]] auto scalar_integer(sqlite3 *database, std::string_view sql,
                                  std::string_view operation)
    -> std::expected<std::int64_t, Error> {
  auto statement = prepare(database, sql, operation);
  if (!statement) {
    return std::unexpected(statement.error());
  }
  auto result = sqlite3_step(statement->get());
  if (result != SQLITE_ROW) {
    return std::unexpected(sqlite_error(database, result, operation));
  }
  if (sqlite3_column_count(statement->get()) != 1 ||
      sqlite3_column_type(statement->get(), 0) != SQLITE_INTEGER) {
    return std::unexpected(
        invalid_data(std::string(operation) + " did not return one integer"));
  }
  const auto value = sqlite3_column_int64(statement->get(), 0);
  result = sqlite3_step(statement->get());
  if (result != SQLITE_DONE) {
    return std::unexpected(sqlite_error(database, result, operation));
  }
  return value;
}

[[nodiscard]] auto scalar_text(sqlite3 *database, std::string_view sql,
                               std::string_view operation)
    -> std::expected<std::string, Error> {
  auto statement = prepare(database, sql, operation);
  if (!statement) {
    return std::unexpected(statement.error());
  }
  auto result = sqlite3_step(statement->get());
  if (result != SQLITE_ROW) {
    return std::unexpected(sqlite_error(database, result, operation));
  }
  if (sqlite3_column_count(statement->get()) != 1 ||
      sqlite3_column_type(statement->get(), 0) != SQLITE_TEXT) {
    return std::unexpected(
        invalid_data(std::string(operation) + " did not return one string"));
  }
  const auto *value = sqlite3_column_text(statement->get(), 0);
  const auto size = sqlite3_column_bytes(statement->get(), 0);
  std::string text(reinterpret_cast<const char *>(value),
                   static_cast<std::size_t>(size));
  result = sqlite3_step(statement->get());
  if (result != SQLITE_DONE) {
    return std::unexpected(sqlite_error(database, result, operation));
  }
  return text;
}

[[nodiscard]] auto configure_security(sqlite3 *database,
                                      const SqliteOptions &options)
    -> std::expected<void, Error> {
  if (const auto result = sqlite3_extended_result_codes(database, 1);
      result != SQLITE_OK) {
    return std::unexpected(
        sqlite_error(database, result, "cannot enable extended SQLite errors"));
  }
  if (const auto result = sqlite3_busy_timeout(
          database, static_cast<int>(options.busy_timeout.count()));
      result != SQLITE_OK) {
    return std::unexpected(
        sqlite_error(database, result, "cannot set SQLite busy timeout"));
  }
  if (const auto result = sqlite3_db_config(
          database, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr);
      result != SQLITE_OK) {
    return std::unexpected(
        sqlite_error(database, result, "cannot disable trusted SQLite schema"));
  }
  if (const auto result = sqlite3_db_config(database, SQLITE_DBCONFIG_DEFENSIVE,
                                             1, nullptr);
      result != SQLITE_OK) {
    return std::unexpected(
        sqlite_error(database, result, "cannot enable defensive SQLite mode"));
  }
  if (const auto result = sqlite3_db_config(
          database, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr);
      result != SQLITE_OK) {
    return std::unexpected(
        sqlite_error(database, result, "cannot disable SQLite extensions"));
  }
  if (auto result = exec(database, "PRAGMA foreign_keys=ON",
                         "cannot enable SQLite foreign keys");
      !result) {
    return result;
  }
  return {};
}

[[nodiscard]] auto open_connection(const std::filesystem::path &path,
                                   const SqliteOptions &options,
                                   bool enable_wal)
    -> std::expected<Database, Error> {
  sqlite3 *raw_database = nullptr;
  auto flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX |
               SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_EXRESCODE;
  if (enable_wal) {
    flags |= SQLITE_OPEN_CREATE;
  }
  const auto result =
      sqlite3_open_v2(path.c_str(), &raw_database, flags, nullptr);
  Database database(raw_database);
  if (result != SQLITE_OK) {
    return std::unexpected(
        sqlite_error(database.get(), result, "cannot open SQLite database"));
  }
  if (auto configured = configure_security(database.get(), options);
      !configured) {
    return std::unexpected(configured.error());
  }

  const auto journal_mode = scalar_text(
      database.get(), enable_wal ? "PRAGMA journal_mode=WAL"
                                 : "PRAGMA journal_mode",
      enable_wal ? "cannot enable SQLite WAL mode"
                 : "cannot verify SQLite WAL mode");
  if (!journal_mode) {
    return std::unexpected(journal_mode.error());
  }
  if (*journal_mode != "wal") {
    return std::unexpected(Error{
        ErrorCode::unavailable,
        "SQLite database did not enter WAL mode (reported " + *journal_mode +
            ')'});
  }
  if (auto configured = exec(database.get(), "PRAGMA synchronous=FULL",
                             "cannot set SQLite durability");
      !configured) {
    return std::unexpected(configured.error());
  }
  if (auto configured = exec(database.get(), "PRAGMA wal_autocheckpoint=1000",
                             "cannot configure SQLite WAL checkpointing");
      !configured) {
    return std::unexpected(configured.error());
  }
  return database;
}

class SqliteTransactionBackend final : public TransactionBackend {
public:
  explicit SqliteTransactionBackend(Database database) noexcept
      : database_(std::move(database)) {}

  ~SqliteTransactionBackend() noexcept final { rollback(); }

  [[nodiscard]] auto commit() -> std::expected<void, Error> final {
    auto result = exec(database_.get(), "COMMIT", "cannot commit transaction");
    if (result) {
      active_ = false;
    }
    return result;
  }

  void rollback() noexcept final {
    if (active_) {
      static_cast<void>(
          sqlite3_exec(database_.get(), "ROLLBACK", nullptr, nullptr, nullptr));
      active_ = false;
    }
  }

  [[nodiscard]] auto database() const noexcept -> sqlite3 * {
    return database_.get();
  }

private:
  Database database_;
  bool active_{true};
};

} // namespace

SqliteStore::SqliteStore(std::filesystem::path path, SqliteOptions options,
                         std::uint32_t schema_version)
    : path_(std::move(path)), options_(options),
      schema_version_(schema_version) {}

auto SqliteStore::open(const std::filesystem::path &path)
    -> std::expected<std::unique_ptr<SqliteStore>, Error> {
  return detail::open_sqlite_store(path, production_migrations);
}

auto SqliteStore::begin(TransactionMode mode)
    -> std::expected<Transaction, Error> {
  auto database = open_connection(path_, options_, false);
  if (!database) {
    return std::unexpected(database.error());
  }
  const auto application_id = scalar_integer(
      database->get(), "PRAGMA application_id",
      "cannot verify SQLite application ID for transaction");
  if (!application_id) {
    return std::unexpected(application_id.error());
  }
  const auto version = scalar_integer(
      database->get(), "PRAGMA user_version",
      "cannot verify SQLite schema version for transaction");
  if (!version) {
    return std::unexpected(version.error());
  }
  if (*application_id != anvil_application_id || *version < 0 ||
      static_cast<std::uint64_t>(*version) != schema_version_) {
    return std::unexpected(invalid_data(
        "SQLite migration metadata changed after server startup"));
  }
  if (mode == TransactionMode::read_only) {
    if (auto result = exec(database->get(), "PRAGMA query_only=ON",
                           "cannot make transaction read-only");
        !result) {
      return std::unexpected(result.error());
    }
  }
  auto begun = exec(database->get(),
                    mode == TransactionMode::read_only ? "BEGIN DEFERRED"
                                                       : "BEGIN IMMEDIATE",
                    "cannot begin transaction");
  if (!begun) {
    return std::unexpected(begun.error());
  }
  return make_transaction(
      std::make_unique<SqliteTransactionBackend>(std::move(*database)));
}

auto SqliteStore::schema_version() const noexcept -> std::uint32_t {
  return schema_version_;
}

auto SqliteStore::execute_for_testing(Transaction &transaction,
                                      std::string_view sql)
    -> std::expected<void, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(Error{
        ErrorCode::invalid_state,
        "transaction is inactive or belongs to a different SQLite store"});
  }
  return exec(backend->database(), sql, "SQLite test statement failed");
}

auto SqliteStore::scalar_for_testing(Transaction &transaction,
                                     std::string_view sql)
    -> std::expected<std::int64_t, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(Error{
        ErrorCode::invalid_state,
        "transaction is inactive or belongs to a different SQLite store"});
  }
  return scalar_integer(backend->database(), sql,
                        "SQLite test query failed");
}

namespace detail {

auto open_sqlite_store(const std::filesystem::path &path,
                       std::span<const SqliteMigration> migrations,
                       SqliteOptions options)
    -> std::expected<std::unique_ptr<SqliteStore>, Error> {
  if (auto result = validate_options(options); !result) {
    return std::unexpected(result.error());
  }
  if (auto result = validate_migrations(migrations); !result) {
    return std::unexpected(result.error());
  }
  if (auto result = ensure_database_file(path); !result) {
    return std::unexpected(result.error());
  }
  auto database = open_connection(path, options, true);
  if (!database) {
    return std::unexpected(database.error());
  }
  if (auto begun = exec(database->get(), "BEGIN IMMEDIATE",
                        "cannot begin SQLite migration");
      !begun) {
    return std::unexpected(begun.error());
  }

  const auto fail = [&](Error error)
      -> std::expected<std::unique_ptr<SqliteStore>, Error> {
    static_cast<void>(
        sqlite3_exec(database->get(), "ROLLBACK", nullptr, nullptr, nullptr));
    return std::unexpected(std::move(error));
  };

  auto application_id = scalar_integer(database->get(), "PRAGMA application_id",
                                       "cannot read SQLite application ID");
  if (!application_id) {
    return fail(application_id.error());
  }
  auto version = scalar_integer(database->get(), "PRAGMA user_version",
                                "cannot read SQLite schema version");
  if (!version) {
    return fail(version.error());
  }
  auto object_count = scalar_integer(
      database->get(),
      "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
      "cannot inspect SQLite schema");
  if (!object_count) {
    return fail(object_count.error());
  }

  if (*application_id == 0) {
    if (*version != 0 || *object_count != 0) {
      return fail(invalid_data(
          "refusing to claim a non-empty SQLite database without Anvil's "
          "application ID"));
    }
  } else if (*application_id != anvil_application_id) {
    return fail(invalid_data("SQLite application ID does not belong to Anvil"));
  }

  const auto current_version =
      migrations.empty() ? 0U : migrations.back().version;
  if (*version < 0 ||
      static_cast<std::uint64_t>(*version) > current_version) {
    return fail(invalid_data(
        "SQLite schema version is newer than this Anvil binary"));
  }

  if (*application_id == 0 && !migrations.empty()) {
    if (auto claimed = exec(database->get(),
                            "PRAGMA application_id=1095652940",
                            "cannot assign Anvil's SQLite application ID");
        !claimed) {
      return fail(claimed.error());
    }
  }

  for (const auto &migration : migrations) {
    if (migration.version <= static_cast<std::uint64_t>(*version)) {
      continue;
    }
    if (!migration.sql.empty()) {
      if (auto applied = exec(database->get(), migration.sql,
                              "SQLite migration " +
                                  std::to_string(migration.version) + " failed");
          !applied) {
        return fail(applied.error());
      }
    }
    if (auto recorded = exec(database->get(),
                             "PRAGMA user_version=" +
                                 std::to_string(migration.version),
                             "cannot record SQLite schema version");
        !recorded) {
      return fail(recorded.error());
    }
  }

  application_id = scalar_integer(database->get(), "PRAGMA application_id",
                                  "cannot verify SQLite application ID");
  version = scalar_integer(database->get(), "PRAGMA user_version",
                           "cannot verify SQLite schema version");
  if (!application_id || !version) {
    return fail(!application_id ? application_id.error() : version.error());
  }
  if (*application_id != anvil_application_id ||
      *version != current_version) {
    return fail(invalid_data("SQLite migration metadata verification failed"));
  }
  if (auto committed = exec(database->get(), "COMMIT",
                            "cannot commit SQLite migrations");
      !committed) {
    return fail(committed.error());
  }

  return std::unique_ptr<SqliteStore>(
      new SqliteStore(path, options, current_version));
}

} // namespace detail
} // namespace anvil::store
