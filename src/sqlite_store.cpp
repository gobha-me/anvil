#include "sqlite_store.hpp"

#include <fcntl.h>
#include <sqlite3.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include "sqlite_schema.hpp"

namespace anvil::store {
namespace {

constexpr std::int64_t anvil_application_id = 0x414E564C;
constexpr std::array production_migrations{
    detail::SqliteMigration{1, {}},
    detail::SqliteMigration{2, detail::domain_schema_v2},
    detail::SqliteMigration{3, detail::invite_economics_v3},
    detail::SqliteMigration{4, detail::message_boards_v4},
    detail::SqliteMigration{5, detail::oneliner_indexes_v5},
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

struct BackupDeleter {
  void operator()(sqlite3_backup *backup) const noexcept {
    if (backup != nullptr) {
      static_cast<void>(sqlite3_backup_finish(backup));
    }
  }
};
using Backup = std::unique_ptr<sqlite3_backup, BackupDeleter>;

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

[[nodiscard]] constexpr auto saturating_subtract(UtcEpochSeconds value,
                                                 std::uint32_t seconds) noexcept
    -> std::int64_t {
  const auto amount = static_cast<std::int64_t>(seconds);
  if (value.value < std::numeric_limits<std::int64_t>::min() + amount) {
    return std::numeric_limits<std::int64_t>::min();
  }
  return value.value - amount;
}

[[nodiscard]] auto validate_options(const SqliteOptions &options)
    -> std::expected<void, Error> {
  const auto count = options.busy_timeout.count();
  if (count <= 0 || count > INT_MAX) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "SQLite busy timeout is out of range"});
  }
  return {};
}

[[nodiscard]] auto
validate_migrations(std::span<const detail::SqliteMigration> migrations)
    -> std::expected<void, Error> {
  std::uint32_t expected = 1;
  for (const auto &migration : migrations) {
    if (migration.version != expected) {
      return std::unexpected(
          Error{ErrorCode::invalid_state,
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
    return std::unexpected(
        Error{ErrorCode::invalid_data,
              "SQLite database path is not a persistent file"});
  }

  const auto descriptor =
      ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
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
  const auto result =
      sqlite3_prepare_v3(database, sql.data(), static_cast<int>(sql.size()),
                         SQLITE_PREPARE_PERSISTENT, &raw_statement, nullptr);
  if (result != SQLITE_OK) {
    return std::unexpected(sqlite_error(database, result, operation));
  }
  return Statement(raw_statement);
}

[[nodiscard]] auto bind_text(sqlite3 *database, sqlite3_stmt *statement,
                             int parameter, std::string_view value,
                             std::string_view operation)
    -> std::expected<void, Error> {
  const auto result =
      sqlite3_bind_text(statement, parameter, value.data(),
                        static_cast<int>(value.size()), SQLITE_TRANSIENT);
  if (result != SQLITE_OK) {
    return std::unexpected(sqlite_error(database, result, operation));
  }
  return {};
}

[[nodiscard]] auto bind_integer(sqlite3 *database, sqlite3_stmt *statement,
                                int parameter, std::int64_t value,
                                std::string_view operation)
    -> std::expected<void, Error> {
  const auto result = sqlite3_bind_int64(statement, parameter, value);
  if (result != SQLITE_OK) {
    return std::unexpected(sqlite_error(database, result, operation));
  }
  return {};
}

[[nodiscard]] auto bind_null(sqlite3 *database, sqlite3_stmt *statement,
                             int parameter, std::string_view operation)
    -> std::expected<void, Error> {
  const auto result = sqlite3_bind_null(statement, parameter);
  if (result != SQLITE_OK) {
    return std::unexpected(sqlite_error(database, result, operation));
  }
  return {};
}

[[nodiscard]] auto column_text(sqlite3_stmt *statement, int column,
                               std::string_view field)
    -> std::expected<std::string, Error> {
  if (sqlite3_column_type(statement, column) != SQLITE_TEXT) {
    return std::unexpected(
        invalid_data(std::string(field) + " is not stored as text"));
  }
  const auto size = sqlite3_column_bytes(statement, column);
  const auto *value = sqlite3_column_text(statement, column);
  if (size == 0) {
    return std::string{};
  }
  if (value == nullptr || size < 0) {
    return std::unexpected(
        invalid_data(std::string(field) + " has invalid text storage"));
  }
  return std::string(reinterpret_cast<const char *>(value),
                     static_cast<std::size_t>(size));
}

[[nodiscard]] auto column_optional_text(sqlite3_stmt *statement, int column,
                                        std::string_view field)
    -> std::expected<std::optional<std::string>, Error> {
  if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
    return std::nullopt;
  }
  auto value = column_text(statement, column, field);
  if (!value) {
    return std::unexpected(value.error());
  }
  return std::optional<std::string>{std::move(*value)};
}

[[nodiscard]] auto parse_user_status(std::string_view value)
    -> std::optional<UserStatus> {
  if (value == "pending")
    return UserStatus::pending;
  if (value == "active")
    return UserStatus::active;
  if (value == "suspended")
    return UserStatus::suspended;
  if (value == "tombstoned")
    return UserStatus::tombstoned;
  return std::nullopt;
}

[[nodiscard]] auto column_integer(sqlite3_stmt *statement, int column,
                                  std::string_view field)
    -> std::expected<std::int64_t, Error> {
  if (sqlite3_column_type(statement, column) != SQLITE_INTEGER) {
    return std::unexpected(
        invalid_data(std::string(field) + " is not stored as an integer"));
  }
  return sqlite3_column_int64(statement, column);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- column-specific validation must identify the exact corrupt SQLite field
[[nodiscard]] auto read_message(sqlite3_stmt *statement)
    -> std::expected<MessageRecord, Error> {
  if (sqlite3_column_count(statement) != 11) {
    return std::unexpected(
        invalid_data("message query returned an unexpected shape"));
  }

  auto message_id = column_text(statement, 0, "message ID");
  auto board_id = column_text(statement, 1, "message board ID");
  auto thread_id = column_text(statement, 2, "message thread ID");
  auto parent_id = column_optional_text(statement, 3, "parent message ID");
  auto author_handle = column_text(statement, 4, "message author handle");
  auto author_origin =
      column_optional_text(statement, 5, "message author origin");
  auto body = column_text(statement, 6, "message body");
  auto posted_at = column_integer(statement, 7, "message posted_at");
  auto received_at = column_integer(statement, 8, "message received_at");
  auto local_sequence = column_integer(statement, 9, "message local sequence");
  auto status = column_text(statement, 10, "message status");
  if (!message_id || !board_id || !thread_id || !parent_id || !author_handle ||
      !author_origin || !body || !posted_at || !received_at ||
      !local_sequence || !status) {
    if (!message_id) {
      return std::unexpected(message_id.error());
    }
    if (!board_id) {
      return std::unexpected(board_id.error());
    }
    if (!thread_id) {
      return std::unexpected(thread_id.error());
    }
    if (!parent_id) {
      return std::unexpected(parent_id.error());
    }
    if (!author_handle) {
      return std::unexpected(author_handle.error());
    }
    if (!author_origin) {
      return std::unexpected(author_origin.error());
    }
    if (!body) {
      return std::unexpected(body.error());
    }
    if (!posted_at) {
      return std::unexpected(posted_at.error());
    }
    if (!received_at) {
      return std::unexpected(received_at.error());
    }
    if (!local_sequence) {
      return std::unexpected(local_sequence.error());
    }
    return std::unexpected(status.error());
  }

  ContentStatus lifecycle{};
  if (*status == "active") {
    lifecycle = ContentStatus::active;
  } else if (*status == "tombstoned") {
    lifecycle = ContentStatus::tombstoned;
  } else {
    return std::unexpected(invalid_data("message has an unknown status"));
  }

  return MessageRecord{
      .message_id = std::move(*message_id),
      .board_id = std::move(*board_id),
      .thread_id = std::move(*thread_id),
      .parent_message_id = std::move(*parent_id),
      .author_handle = std::move(*author_handle),
      .author_origin = std::move(*author_origin),
      .body = std::move(*body),
      .posted_at = UtcEpochSeconds{*posted_at},
      .received_at = UtcEpochSeconds{*received_at},
      .local_sequence = *local_sequence,
      .status = lifecycle,
  };
}

struct TombstoneSql {
  std::string_view update;
  std::string_view exists;
  bool integer_identifier{};
};

[[nodiscard]] auto tombstone_sql(ContentKind kind)
    -> std::expected<TombstoneSql, Error> {
  switch (kind) {
  case ContentKind::board:
    return TombstoneSql{
        "UPDATE boards SET status='tombstoned' WHERE board_id=?1 AND "
        "status!='tombstoned'",
        "SELECT 1 FROM boards WHERE board_id=?1", false};
  case ContentKind::thread:
    return TombstoneSql{
        "UPDATE threads SET status='tombstoned' WHERE thread_id=?1 AND "
        "status!='tombstoned'",
        "SELECT 1 FROM threads WHERE thread_id=?1", false};
  case ContentKind::message:
    return TombstoneSql{
        "UPDATE messages SET status='tombstoned' WHERE message_id=?1 AND "
        "status!='tombstoned'",
        "SELECT 1 FROM messages WHERE message_id=?1", false};
  case ContentKind::file:
    return TombstoneSql{
        "UPDATE files SET status='tombstoned' WHERE file_id=?1 AND "
        "status!='tombstoned'",
        "SELECT 1 FROM files WHERE file_id=?1", false};
  case ContentKind::leaderboard_entry:
    return TombstoneSql{
        "UPDATE leaderboards SET status='tombstoned' WHERE entry_id=?1 AND "
        "status!='tombstoned'",
        "SELECT 1 FROM leaderboards WHERE entry_id=?1", false};
  case ContentKind::oneliner:
    return TombstoneSql{
        "UPDATE oneliners SET status='tombstoned' WHERE oneliner_id=?1 AND "
        "status!='tombstoned'",
        "SELECT 1 FROM oneliners WHERE oneliner_id=?1", false};
  case ContentKind::block:
    return TombstoneSql{
        "UPDATE blocks SET status='tombstoned' WHERE block_id=?1 AND "
        "status!='tombstoned'",
        "SELECT 1 FROM blocks WHERE block_id=?1", true};
  case ContentKind::report:
    return TombstoneSql{
        "UPDATE reports SET status='tombstoned' WHERE report_id=?1 AND "
        "status!='tombstoned'",
        "SELECT 1 FROM reports WHERE report_id=?1", false};
  }
  return std::unexpected(invalid_data("unknown content kind"));
}

[[nodiscard]] auto
bind_content_identifier(sqlite3 *database, sqlite3_stmt *statement,
                        const ContentRef &content, const TombstoneSql &sql)
    -> std::expected<void, Error> {
  if (sql.integer_identifier) {
    return bind_integer(database, statement, 1,
                        std::get<std::int64_t>(content.id),
                        "cannot bind tombstone identifier");
  }
  return bind_text(database, statement, 1, std::get<std::string>(content.id),
                   "cannot bind tombstone identifier");
}

constexpr std::string_view message_columns =
    "m.message_id,m.board_id,m.thread_id,m.parent_message_id,"
    "m.author_handle,m.author_origin,m.body,m.posted_at,m.received_at,"
    "m.local_sequence,m.status ";

[[nodiscard]] auto query_messages(sqlite3 *database, std::string_view sql,
                                  std::string_view identifier, bool at_most_one)
    -> std::expected<std::vector<MessageRecord>, Error> {
  auto statement = prepare(database, sql, "cannot prepare message query");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  if (auto bound = bind_text(database, statement->get(), 1, identifier,
                             "cannot bind message query identifier");
      !bound) {
    return std::unexpected(bound.error());
  }

  std::vector<MessageRecord> messages;
  for (;;) {
    const auto result = sqlite3_step(statement->get());
    if (result == SQLITE_DONE) {
      return messages;
    }
    if (result != SQLITE_ROW) {
      return std::unexpected(
          sqlite_error(database, result, "cannot execute message query"));
    }
    auto message = read_message(statement->get());
    if (!message) {
      return std::unexpected(message.error());
    }
    messages.push_back(std::move(*message));
    if (at_most_one && messages.size() > 1) {
      return std::unexpected(
          invalid_data("message lookup returned more than one row"));
    }
  }
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
  if (const auto result =
          sqlite3_db_config(database, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
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
      database.get(),
      enable_wal ? "PRAGMA journal_mode=WAL" : "PRAGMA journal_mode",
      enable_wal ? "cannot enable SQLite WAL mode"
                 : "cannot verify SQLite WAL mode");
  if (!journal_mode) {
    return std::unexpected(journal_mode.error());
  }
  if (*journal_mode != "wal") {
    return std::unexpected(
        Error{ErrorCode::unavailable,
              "SQLite database did not enter WAL mode (reported " +
                  *journal_mode + ')'});
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

[[nodiscard]] auto open_backup_destination(const std::filesystem::path &path,
                                           const SqliteOptions &options)
    -> std::expected<Database, Error> {
  const auto descriptor =
      ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
             S_IRUSR | S_IWUSR);
  if (descriptor < 0) {
    return std::unexpected(
        Error{ErrorCode::unavailable,
              "cannot create SQLite backup destination: " +
                  std::error_code(errno, std::generic_category()).message()});
  }
  if (::close(descriptor) != 0) {
    const auto failure = errno;
    static_cast<void>(::unlink(path.c_str()));
    return std::unexpected(
        Error{ErrorCode::unavailable,
              "cannot close SQLite backup destination: " +
                  std::error_code(failure, std::generic_category()).message()});
  }

  sqlite3 *raw_database = nullptr;
  const auto flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX |
                     SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_EXRESCODE;
  const auto result =
      sqlite3_open_v2(path.c_str(), &raw_database, flags, nullptr);
  Database database(raw_database);
  if (result != SQLITE_OK) {
    static_cast<void>(::unlink(path.c_str()));
    return std::unexpected(sqlite_error(
        database.get(), result, "cannot open SQLite backup destination"));
  }
  if (auto configured = configure_security(database.get(), options);
      !configured) {
    static_cast<void>(::unlink(path.c_str()));
    return std::unexpected(configured.error());
  }
  return database;
}

[[nodiscard]] auto copy_database(sqlite3 *source,
                                 const std::filesystem::path &destination,
                                 const SqliteOptions &options)
    -> std::expected<void, Error> {
  auto target = open_backup_destination(destination, options);
  if (!target) {
    return std::unexpected(target.error());
  }

  sqlite3_backup *raw_backup =
      sqlite3_backup_init(target->get(), "main", source, "main");
  if (raw_backup == nullptr) {
    const auto error =
        sqlite_error(target->get(), sqlite3_errcode(target->get()),
                     "cannot initialize SQLite backup");
    target->reset();
    static_cast<void>(::unlink(destination.c_str()));
    return std::unexpected(error);
  }
  Backup backup(raw_backup);

  const auto deadline = std::chrono::steady_clock::now() + options.busy_timeout;
  int result = SQLITE_OK;
  do {
    result = sqlite3_backup_step(backup.get(), 256);
    if (result == SQLITE_BUSY || result == SQLITE_LOCKED) {
      if (std::chrono::steady_clock::now() >= deadline) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  } while (result == SQLITE_OK || result == SQLITE_BUSY ||
           result == SQLITE_LOCKED);

  const auto finished = sqlite3_backup_finish(backup.release());
  if (result != SQLITE_DONE || finished != SQLITE_OK) {
    const auto failure = result == SQLITE_DONE ? finished : result;
    const auto error =
        sqlite_error(target->get(), failure, "cannot complete SQLite backup");
    target->reset();
    static_cast<void>(::unlink(destination.c_str()));
    return std::unexpected(error);
  }
  if (const auto flushed = sqlite3_db_cacheflush(target->get());
      flushed != SQLITE_OK) {
    const auto error =
        sqlite_error(target->get(), flushed, "cannot flush SQLite backup");
    target->reset();
    static_cast<void>(::unlink(destination.c_str()));
    return std::unexpected(error);
  }
  target->reset();

  const auto descriptor =
      ::open(destination.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0 || ::fsync(descriptor) != 0) {
    const auto failure = errno;
    if (descriptor >= 0) {
      static_cast<void>(::close(descriptor));
    }
    static_cast<void>(::unlink(destination.c_str()));
    return std::unexpected(
        Error{ErrorCode::unavailable,
              "cannot flush SQLite backup file: " +
                  std::error_code(failure, std::generic_category()).message()});
  }
  static_cast<void>(::close(descriptor));
  return {};
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

[[nodiscard]] auto next_message_sequence(sqlite3 *database)
    -> std::expected<std::int64_t, Error> {
  auto current = scalar_integer(
      database, "SELECT coalesce(max(local_sequence),0) FROM messages",
      "cannot allocate message sequence");
  if (!current) {
    return std::unexpected(current.error());
  }
  if (*current == std::numeric_limits<std::int64_t>::max()) {
    return std::unexpected(
        Error{ErrorCode::conflict, "message sequence is exhausted"});
  }
  return *current + 1;
}

[[nodiscard]] auto insert_message(sqlite3 *database,
                                  const MessageRecord &message)
    -> std::expected<void, Error> {
  constexpr std::string_view sql =
      "INSERT INTO messages(message_id,board_id,thread_id,parent_message_id,"
      "author_handle,body,posted_at,received_at,local_sequence) "
      "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)";
  auto statement = prepare(database, sql, "cannot prepare message insert");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  const std::array values{std::string_view{message.message_id},
                          std::string_view{message.board_id},
                          std::string_view{message.thread_id}};
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (auto bound =
            bind_text(database, statement->get(), static_cast<int>(index + 1U),
                      values[index], "cannot bind message identity");
        !bound) {
      return std::unexpected(bound.error());
    }
  }
  auto parent =
      message.parent_message_id
          ? bind_text(database, statement->get(), 4, *message.parent_message_id,
                      "cannot bind parent message")
          : bind_null(database, statement->get(), 4,
                      "cannot bind absent parent message");
  if (!parent) {
    return std::unexpected(parent.error());
  }
  if (auto bound =
          bind_text(database, statement->get(), 5, message.author_handle,
                    "cannot bind message author");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_text(database, statement->get(), 6, message.body,
                             "cannot bind message body");
      !bound) {
    return std::unexpected(bound.error());
  }
  const std::array integers{message.posted_at.value, message.received_at.value,
                            message.local_sequence};
  for (std::size_t index = 0; index < integers.size(); ++index) {
    if (auto bound = bind_integer(database, statement->get(),
                                  static_cast<int>(index + 7U), integers[index],
                                  "cannot bind message metadata");
        !bound) {
      return std::unexpected(bound.error());
    }
  }
  const auto inserted = sqlite3_step(statement->get());
  if (inserted != SQLITE_DONE) {
    auto error = sqlite_error(database, inserted, "cannot insert message");
    if (error.code == ErrorCode::constraint_violation) {
      error.code = ErrorCode::conflict;
    }
    return std::unexpected(std::move(error));
  }
  return {};
}

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
  const auto application_id =
      scalar_integer(database->get(), "PRAGMA application_id",
                     "cannot verify SQLite application ID for transaction");
  if (!application_id) {
    return std::unexpected(application_id.error());
  }
  const auto version =
      scalar_integer(database->get(), "PRAGMA user_version",
                     "cannot verify SQLite schema version for transaction");
  if (!version) {
    return std::unexpected(version.error());
  }
  if (*application_id != anvil_application_id || *version < 0 ||
      static_cast<std::uint64_t>(*version) != schema_version_) {
    return std::unexpected(
        invalid_data("SQLite migration metadata changed after server startup"));
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
      mode, std::make_unique<SqliteTransactionBackend>(std::move(*database)));
}

auto SqliteStore::backup_to(const std::filesystem::path &destination)
    -> std::expected<void, Error> {
  auto source = open_connection(path_, options_, false);
  if (!source) {
    return std::unexpected(source.error());
  }
  return copy_database(source->get(), destination, options_);
}

auto SqliteStore::restore_from(const std::filesystem::path &snapshot,
                               const std::filesystem::path &destination)
    -> std::expected<void, Error> {
  const auto remove_destination = [&destination] {
    static_cast<void>(::unlink(destination.c_str()));
    static_cast<void>(::unlink((destination.string() + "-wal").c_str()));
    static_cast<void>(::unlink((destination.string() + "-shm").c_str()));
  };
  sqlite3 *raw_source = nullptr;
  const auto flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX |
                     SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_EXRESCODE;
  const auto result =
      sqlite3_open_v2(snapshot.c_str(), &raw_source, flags, nullptr);
  Database source(raw_source);
  if (result != SQLITE_OK) {
    return std::unexpected(
        sqlite_error(source.get(), result, "cannot open SQLite backup"));
  }
  SqliteOptions options;
  if (auto configured = configure_security(source.get(), options);
      !configured) {
    return std::unexpected(configured.error());
  }
  auto integrity = scalar_text(source.get(), "PRAGMA quick_check",
                               "cannot check SQLite backup integrity");
  if (!integrity) {
    return std::unexpected(integrity.error());
  }
  if (*integrity != "ok") {
    return std::unexpected(
        invalid_data("SQLite backup failed its integrity check"));
  }
  auto copied = copy_database(source.get(), destination, options);
  if (!copied) {
    return copied;
  }
  auto validated = SqliteStore::open(destination);
  if (!validated) {
    remove_destination();
    return std::unexpected(validated.error());
  }
  validated->reset();
  static_cast<void>(::unlink((destination.string() + "-wal").c_str()));
  static_cast<void>(::unlink((destination.string() + "-shm").c_str()));
  return {};
}

auto SqliteStore::schema_version() const noexcept -> std::uint32_t {
  return schema_version_;
}

auto SqliteStore::tombstone_impl(Transaction &transaction,
                                 const ContentRef &content)
    -> std::expected<void, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  auto sql = tombstone_sql(content.kind);
  if (!sql) {
    return std::unexpected(sql.error());
  }
  auto statement =
      prepare(backend->database(), sql->update, "cannot prepare tombstone");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  if (auto bound = bind_content_identifier(backend->database(),
                                           statement->get(), content, *sql);
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto updated = sqlite3_step(statement->get());
  if (updated != SQLITE_DONE) {
    return std::unexpected(
        sqlite_error(backend->database(), updated, "cannot tombstone content"));
  }
  if (sqlite3_changes64(backend->database()) == 1) {
    return {};
  }

  auto exists = prepare(backend->database(), sql->exists,
                        "cannot prepare tombstone existence check");
  if (!exists) {
    return std::unexpected(exists.error());
  }
  if (auto bound = bind_content_identifier(backend->database(), exists->get(),
                                           content, *sql);
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto found = sqlite3_step(exists->get());
  if (found == SQLITE_ROW) {
    return {};
  }
  if (found == SQLITE_DONE) {
    return std::unexpected(
        Error{ErrorCode::not_found, "content to tombstone does not exist"});
  }
  return std::unexpected(sqlite_error(backend->database(), found,
                                      "cannot check tombstone target"));
}

auto SqliteStore::find_message_impl(Transaction &transaction,
                                    std::string_view message_id,
                                    ContentVisibility visibility)
    -> std::expected<std::optional<MessageRecord>, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  std::string sql = "SELECT ";
  sql += message_columns;
  sql += "FROM messages AS m JOIN threads AS t ON t.thread_id=m.thread_id "
         "AND t.board_id=m.board_id JOIN boards AS b ON "
         "b.board_id=m.board_id WHERE m.message_id=?1";
  if (visibility == ContentVisibility::active_only) {
    sql += " AND m.status!='tombstoned' AND t.status!='tombstoned' AND "
           "b.status!='tombstoned' AND b.guest_readable=1";
  }
  auto messages = query_messages(backend->database(), sql, message_id, true);
  if (!messages) {
    return std::unexpected(messages.error());
  }
  if (messages->empty()) {
    return std::nullopt;
  }
  return std::optional<MessageRecord>{std::move(messages->front())};
}

auto SqliteStore::list_messages_for_board_impl(Transaction &transaction,
                                               std::string_view board_id,
                                               ContentVisibility visibility)
    -> std::expected<std::vector<MessageRecord>, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  std::string sql = "SELECT ";
  sql += message_columns;
  sql += "FROM messages AS m JOIN threads AS t ON t.thread_id=m.thread_id "
         "AND t.board_id=m.board_id JOIN boards AS b ON "
         "b.board_id=m.board_id WHERE m.board_id=?1";
  if (visibility == ContentVisibility::active_only) {
    sql += " AND m.status!='tombstoned' AND t.status!='tombstoned' AND "
           "b.status!='tombstoned' AND b.guest_readable=1";
  }
  sql += " ORDER BY m.received_at,m.message_id";
  return query_messages(backend->database(), sql, board_id, false);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- nullable columns and status decoding retain precise corrupt-row diagnostics
auto SqliteStore::find_local_credential_impl(Transaction &transaction,
                                             std::string_view fingerprint)
    -> std::expected<std::optional<CredentialRecord>, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  constexpr std::string_view sql =
      "SELECT u.handle,k.fingerprint,k.public_key,u.status,k.revoked_at,"
      "u.origin,k.user_origin FROM user_keys AS k JOIN users AS u ON "
      "u.handle=k.user_handle AND u.origin_key=k.user_origin_key WHERE "
      "k.fingerprint=?1";
  auto statement =
      prepare(backend->database(), sql, "cannot prepare credential lookup");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  if (auto bound = bind_text(backend->database(), statement->get(), 1,
                             fingerprint, "cannot bind credential lookup");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto result = sqlite3_step(statement->get());
  if (result == SQLITE_DONE) {
    return std::nullopt;
  }
  if (result != SQLITE_ROW) {
    return std::unexpected(
        sqlite_error(backend->database(), result, "cannot look up credential"));
  }
  if (sqlite3_column_count(statement->get()) != 7) {
    return std::unexpected(
        invalid_data("credential query returned an unexpected shape"));
  }
  auto handle = column_text(statement->get(), 0, "credential handle");
  auto stored_fingerprint =
      column_text(statement->get(), 1, "credential fingerprint");
  auto public_key = column_text(statement->get(), 2, "credential public key");
  auto user_status = column_text(statement->get(), 3, "credential user status");
  if (!handle || !stored_fingerprint || !public_key || !user_status) {
    if (!handle)
      return std::unexpected(handle.error());
    if (!stored_fingerprint)
      return std::unexpected(stored_fingerprint.error());
    if (!public_key)
      return std::unexpected(public_key.error());
    return std::unexpected(user_status.error());
  }
  if (sqlite3_column_type(statement->get(), 5) != SQLITE_NULL ||
      sqlite3_column_type(statement->get(), 6) != SQLITE_NULL) {
    return std::unexpected(
        invalid_data("credential belongs to a non-local identity"));
  }

  CredentialStatus status{};
  if (sqlite3_column_type(statement->get(), 4) != SQLITE_NULL) {
    if (sqlite3_column_type(statement->get(), 4) != SQLITE_INTEGER) {
      return std::unexpected(
          invalid_data("credential revoked_at is not stored as an integer"));
    }
    status = CredentialStatus::revoked;
  } else if (*user_status == "pending") {
    status = CredentialStatus::pending;
  } else if (*user_status == "active") {
    status = CredentialStatus::active;
  } else if (*user_status == "suspended") {
    status = CredentialStatus::suspended;
  } else if (*user_status == "tombstoned") {
    status = CredentialStatus::tombstoned;
  } else {
    return std::unexpected(invalid_data("credential user has unknown status"));
  }
  return CredentialRecord{.handle = std::move(*handle),
                          .fingerprint = std::move(*stored_fingerprint),
                          .public_key = std::move(*public_key),
                          .status = status};
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- user and credential conflict handling share one atomic transaction boundary
auto SqliteStore::provision_local_credential_impl(
    Transaction &transaction, const LocalCredentialProvision &provision)
    -> std::expected<void, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }

  auto credential =
      find_local_credential_impl(transaction, provision.fingerprint);
  if (!credential) {
    return std::unexpected(credential.error());
  }
  if (credential->has_value()) {
    const auto &existing = **credential;
    if (provision.user_status == UserStatus::active &&
        existing.handle == provision.handle &&
        existing.public_key == provision.public_key &&
        existing.status == CredentialStatus::active) {
      return {};
    }
    return std::unexpected(Error{
        ErrorCode::conflict, "credential fingerprint is already provisioned"});
  }

  constexpr std::string_view find_user_sql =
      "SELECT status,origin FROM users WHERE handle=?1 AND origin_key=''";
  auto find_user = prepare(backend->database(), find_user_sql,
                           "cannot prepare local user lookup");
  if (!find_user) {
    return std::unexpected(find_user.error());
  }
  if (auto bound = bind_text(backend->database(), find_user->get(), 1,
                             provision.handle, "cannot bind local user lookup");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto found_user = sqlite3_step(find_user->get());
  if (found_user != SQLITE_ROW && found_user != SQLITE_DONE) {
    return std::unexpected(sqlite_error(backend->database(), found_user,
                                        "cannot look up local user"));
  }
  if (found_user == SQLITE_ROW) {
    auto status = column_text(find_user->get(), 0, "local user status");
    if (!status) {
      return std::unexpected(status.error());
    }
    if (sqlite3_column_type(find_user->get(), 1) != SQLITE_NULL) {
      return std::unexpected(invalid_data("local user has a non-null origin"));
    }
    if (provision.user_status != UserStatus::active || *status != "active") {
      return std::unexpected(
          Error{ErrorCode::conflict, "local handle is already provisioned"});
    }
  } else {
    constexpr std::string_view insert_user_sql =
        "INSERT INTO users(handle,status,created_at) VALUES(?1,?2,?3)";
    auto insert_user = prepare(backend->database(), insert_user_sql,
                               "cannot prepare local user provision");
    if (!insert_user)
      return std::unexpected(insert_user.error());
    const auto status = provision.user_status == UserStatus::active
                            ? std::string_view{"active"}
                            : std::string_view{"pending"};
    if (auto bound =
            bind_text(backend->database(), insert_user->get(), 1,
                      provision.handle, "cannot bind local user handle");
        !bound) {
      return std::unexpected(bound.error());
    }
    if (auto bound = bind_text(backend->database(), insert_user->get(), 2,
                               status, "cannot bind local user status");
        !bound) {
      return std::unexpected(bound.error());
    }
    if (auto bound = bind_integer(backend->database(), insert_user->get(), 3,
                                  provision.created_at.value,
                                  "cannot bind local user creation time");
        !bound) {
      return std::unexpected(bound.error());
    }
    const auto inserted = sqlite3_step(insert_user->get());
    if (inserted != SQLITE_DONE) {
      auto error = sqlite_error(backend->database(), inserted,
                                "cannot provision local user");
      if (error.code == ErrorCode::constraint_violation) {
        error.code = ErrorCode::conflict;
      }
      return std::unexpected(std::move(error));
    }
  }

  constexpr std::string_view insert_key_sql =
      "INSERT INTO user_keys(fingerprint,user_handle,public_key,added_at) "
      "VALUES(?1,?2,?3,?4)";
  auto insert_key = prepare(backend->database(), insert_key_sql,
                            "cannot prepare credential provision");
  if (!insert_key)
    return std::unexpected(insert_key.error());
  if (auto bound = bind_text(backend->database(), insert_key->get(), 1,
                             provision.fingerprint,
                             "cannot bind credential fingerprint");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_text(backend->database(), insert_key->get(), 2,
                             provision.handle, "cannot bind credential handle");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound =
          bind_text(backend->database(), insert_key->get(), 3,
                    provision.public_key, "cannot bind credential public key");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_integer(backend->database(), insert_key->get(), 4,
                                provision.created_at.value,
                                "cannot bind credential creation time");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto inserted = sqlite3_step(insert_key->get());
  if (inserted != SQLITE_DONE) {
    auto error = sqlite_error(backend->database(), inserted,
                              "cannot provision credential");
    if (error.code == ErrorCode::constraint_violation) {
      error.code = ErrorCode::conflict;
    }
    return std::unexpected(std::move(error));
  }
  return {};
}

auto SqliteStore::has_tos_acceptance_impl(Transaction &transaction,
                                          std::string_view user_handle,
                                          std::string_view tos_version)
    -> std::expected<bool, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  constexpr std::string_view sql =
      "SELECT 1 FROM tos_acceptances WHERE user_handle=?1 AND "
      "user_origin IS NULL AND tos_version=?2";
  auto statement =
      prepare(backend->database(), sql, "cannot prepare TOS acceptance lookup");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  if (auto bound = bind_text(backend->database(), statement->get(), 1,
                             user_handle, "cannot bind TOS user");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_text(backend->database(), statement->get(), 2,
                             tos_version, "cannot bind TOS version");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto result = sqlite3_step(statement->get());
  if (result == SQLITE_ROW) {
    return true;
  }
  if (result == SQLITE_DONE) {
    return false;
  }
  return std::unexpected(sqlite_error(backend->database(), result,
                                      "cannot look up TOS acceptance"));
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- status transition and append-only acceptance remain one atomic operation
auto SqliteStore::accept_tos_impl(Transaction &transaction,
                                  const TosAcceptance &acceptance)
    -> std::expected<UserStatus, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }

  constexpr std::string_view find_user_sql =
      "SELECT status,origin FROM users WHERE handle=?1 AND origin_key=''";
  auto find_user = prepare(backend->database(), find_user_sql,
                           "cannot prepare TOS user lookup");
  if (!find_user) {
    return std::unexpected(find_user.error());
  }
  if (auto bound =
          bind_text(backend->database(), find_user->get(), 1,
                    acceptance.user_handle, "cannot bind TOS user lookup");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto found = sqlite3_step(find_user->get());
  if (found == SQLITE_DONE) {
    return std::unexpected(
        Error{ErrorCode::not_found, "TOS user does not exist"});
  }
  if (found != SQLITE_ROW) {
    return std::unexpected(
        sqlite_error(backend->database(), found, "cannot look up TOS user"));
  }
  auto status = column_text(find_user->get(), 0, "TOS user status");
  if (!status) {
    return std::unexpected(status.error());
  }
  if (sqlite3_column_type(find_user->get(), 1) != SQLITE_NULL) {
    return std::unexpected(invalid_data("TOS user has a non-null origin"));
  }
  if (*status != "pending" && *status != "active") {
    return std::unexpected(
        Error{ErrorCode::conflict,
              "only pending or active accounts may accept the TOS"});
  }

  constexpr std::string_view insert_sql =
      "INSERT INTO tos_acceptances(user_handle,tos_version,accepted_at) "
      "VALUES(?1,?2,?3) ON CONFLICT(user_handle,user_origin_key,tos_version) "
      "DO NOTHING";
  auto insert = prepare(backend->database(), insert_sql,
                        "cannot prepare TOS acceptance insert");
  if (!insert) {
    return std::unexpected(insert.error());
  }
  if (auto bound = bind_text(backend->database(), insert->get(), 1,
                             acceptance.user_handle, "cannot bind TOS user");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_text(backend->database(), insert->get(), 2,
                             acceptance.tos_version, "cannot bind TOS version");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_integer(backend->database(), insert->get(), 3,
                                acceptance.accepted_at.value,
                                "cannot bind TOS acceptance time");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto inserted = sqlite3_step(insert->get());
  if (inserted != SQLITE_DONE) {
    return std::unexpected(sqlite_error(backend->database(), inserted,
                                        "cannot record TOS acceptance"));
  }

  if (*status == "pending") {
    constexpr std::string_view activate_sql =
        "UPDATE users SET status='active' WHERE handle=?1 AND origin IS NULL "
        "AND status='pending'";
    auto activate = prepare(backend->database(), activate_sql,
                            "cannot prepare TOS account activation");
    if (!activate) {
      return std::unexpected(activate.error());
    }
    if (auto bound = bind_text(backend->database(), activate->get(), 1,
                               acceptance.user_handle,
                               "cannot bind TOS account activation");
        !bound) {
      return std::unexpected(bound.error());
    }
    const auto activated = sqlite3_step(activate->get());
    if (activated != SQLITE_DONE) {
      return std::unexpected(sqlite_error(backend->database(), activated,
                                          "cannot activate TOS user"));
    }
    if (sqlite3_changes(backend->database()) != 1) {
      return std::unexpected(
          Error{ErrorCode::conflict, "TOS user status changed concurrently"});
    }
  }
  return UserStatus::active;
}

auto SqliteStore::claim_invite_impl(Transaction &transaction,
                                    const InviteClaim &claim)
    -> std::expected<void, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }

  constexpr std::string_view sql =
      "UPDATE invites SET claimed_by_handle=?2,claimed_by_origin=NULL,"
      "status='claimed',claimed_at=?3 WHERE code_hash=?1 AND status='active' "
      "AND claimed_by_handle IS NULL AND claimed_by_origin IS NULL AND "
      "claimed_at IS NULL AND expires_at>?3 AND "
      "EXISTS(SELECT 1 FROM users WHERE handle=?2 "
      "AND origin IS NULL AND status='pending')";
  auto statement =
      prepare(backend->database(), sql, "cannot prepare invite claim");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  if (auto bound = bind_text(backend->database(), statement->get(), 1,
                             claim.code_hash, "cannot bind invite code hash");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound =
          bind_text(backend->database(), statement->get(), 2,
                    claim.claimed_by_handle, "cannot bind invite claimant");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound =
          bind_integer(backend->database(), statement->get(), 3,
                       claim.claimed_at.value, "cannot bind invite claim time");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto updated = sqlite3_step(statement->get());
  if (updated != SQLITE_DONE) {
    return std::unexpected(
        sqlite_error(backend->database(), updated, "cannot claim invite"));
  }
  if (sqlite3_changes64(backend->database()) != 1) {
    return std::unexpected(
        Error{ErrorCode::conflict, "invite is invalid or no longer available"});
  }
  return {};
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity, readability-function-size) -- credit regeneration and code issuance must commit atomically
auto SqliteStore::issue_invite_impl(Transaction &transaction,
                                    const InviteIssue &issue)
    -> std::expected<InviteIssueResult, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }

  constexpr std::string_view lookup_sql =
      "SELECT status,invite_balance,invite_next_regeneration FROM users "
      "WHERE handle=?1 AND origin_key=''";
  auto lookup = prepare(backend->database(), lookup_sql,
                        "cannot prepare invite balance lookup");
  if (!lookup) {
    return std::unexpected(lookup.error());
  }
  if (auto bound = bind_text(backend->database(), lookup->get(), 1,
                             issue.inviter_handle, "cannot bind invite issuer");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto found = sqlite3_step(lookup->get());
  if (found == SQLITE_DONE) {
    return std::unexpected(
        Error{ErrorCode::not_found, "invite issuer does not exist"});
  }
  if (found != SQLITE_ROW) {
    return std::unexpected(sqlite_error(backend->database(), found,
                                        "cannot look up invite issuer"));
  }
  auto status = column_text(lookup->get(), 0, "invite issuer status");
  if (!status) {
    return std::unexpected(status.error());
  }
  if (*status != "active") {
    return std::unexpected(
        Error{ErrorCode::conflict, "only active accounts may issue invites"});
  }
  const auto stored_balance =
      static_cast<std::int64_t>(sqlite3_column_int64(lookup->get(), 1));
  if (stored_balance < 0) {
    return std::unexpected(invalid_data("invite balance is negative"));
  }

  const auto cap = static_cast<std::int64_t>(issue.balance_cap);
  auto balance = std::min(stored_balance, cap);
  std::optional<std::int64_t> next_regeneration;
  if (sqlite3_column_type(lookup->get(), 2) != SQLITE_NULL) {
    next_regeneration = sqlite3_column_int64(lookup->get(), 2);
  } else {
    balance = cap;
  }

  const auto period = static_cast<std::int64_t>(issue.regeneration_seconds);
  if (next_regeneration && issue.created_at.value >= *next_regeneration) {
    const auto elapsed = static_cast<std::uint64_t>(issue.created_at.value) -
                         static_cast<std::uint64_t>(*next_regeneration);
    const auto elapsed_intervals = elapsed / static_cast<std::uint64_t>(period);
    const auto credits_needed = static_cast<std::uint64_t>(cap - balance);
    if (credits_needed == 0U || elapsed_intervals >= credits_needed - 1U) {
      balance = cap;
      next_regeneration.reset();
    } else {
      const auto intervals = 1 + static_cast<std::int64_t>(elapsed_intervals);
      balance += intervals;
      *next_regeneration += intervals * period;
    }
  }
  if (balance == 0) {
    return std::unexpected(
        Error{ErrorCode::conflict, "invite balance is exhausted"});
  }
  --balance;
  if (balance < cap && !next_regeneration) {
    next_regeneration = issue.created_at.value + period;
  }

  if (auto saved = exec(backend->database(), "SAVEPOINT issue_invite",
                        "cannot start invite issuance");
      !saved) {
    return std::unexpected(saved.error());
  }
  const auto rollback =
      [&](Error error) -> std::expected<InviteIssueResult, Error> {
    static_cast<void>(exec(backend->database(),
                           "ROLLBACK TO issue_invite; RELEASE issue_invite",
                           "cannot roll back invite issuance"));
    return std::unexpected(std::move(error));
  };

  constexpr std::string_view insert_sql =
      "INSERT INTO invites(code_hash,inviter_handle,status,created_at,"
      "expires_at) VALUES(?1,?2,'active',?3,?4)";
  auto insert = prepare(backend->database(), insert_sql,
                        "cannot prepare invite issuance");
  if (!insert)
    return rollback(insert.error());
  if (auto bound = bind_text(backend->database(), insert->get(), 1,
                             issue.code_hash, "cannot bind invite code hash");
      !bound) {
    return rollback(bound.error());
  }
  if (auto bound = bind_text(backend->database(), insert->get(), 2,
                             issue.inviter_handle, "cannot bind invite issuer");
      !bound) {
    return rollback(bound.error());
  }
  if (auto bound = bind_integer(backend->database(), insert->get(), 3,
                                issue.created_at.value,
                                "cannot bind invite creation time");
      !bound) {
    return rollback(bound.error());
  }
  if (auto bound =
          bind_integer(backend->database(), insert->get(), 4,
                       issue.expires_at.value, "cannot bind invite expiry");
      !bound) {
    return rollback(bound.error());
  }
  const auto inserted = sqlite3_step(insert->get());
  if (inserted != SQLITE_DONE) {
    auto error =
        sqlite_error(backend->database(), inserted, "cannot issue invite");
    if (error.code == ErrorCode::constraint_violation) {
      error.code = ErrorCode::conflict;
    }
    return rollback(std::move(error));
  }

  constexpr std::string_view update_sql =
      "UPDATE users SET invite_balance=?2,invite_next_regeneration=?3 "
      "WHERE handle=?1 AND origin_key='' AND status='active'";
  auto update = prepare(backend->database(), update_sql,
                        "cannot prepare invite balance update");
  if (!update)
    return rollback(update.error());
  if (auto bound =
          bind_text(backend->database(), update->get(), 1, issue.inviter_handle,
                    "cannot bind invite balance owner");
      !bound) {
    return rollback(bound.error());
  }
  if (auto bound = bind_integer(backend->database(), update->get(), 2, balance,
                                "cannot bind invite balance");
      !bound) {
    return rollback(bound.error());
  }
  const auto next_result =
      next_regeneration
          ? bind_integer(backend->database(), update->get(), 3,
                         *next_regeneration, "cannot bind next regeneration")
          : bind_null(backend->database(), update->get(), 3,
                      "cannot bind next regeneration");
  if (!next_result) {
    return rollback(next_result.error());
  }
  const auto updated = sqlite3_step(update->get());
  if (updated != SQLITE_DONE || sqlite3_changes64(backend->database()) != 1) {
    return rollback(updated == SQLITE_DONE
                        ? Error{ErrorCode::conflict,
                                "invite issuer changed during issuance"}
                        : sqlite_error(backend->database(), updated,
                                       "cannot update invite balance"));
  }
  if (auto released = exec(backend->database(), "RELEASE issue_invite",
                           "cannot finish invite issuance");
      !released) {
    return rollback(released.error());
  }
  return InviteIssueResult{
      .remaining_balance = static_cast<std::uint32_t>(balance),
      .next_regeneration =
          next_regeneration
              ? std::optional<UtcEpochSeconds>{{*next_regeneration}}
              : std::nullopt,
  };
}

auto SqliteStore::find_inviter_impl(Transaction &transaction,
                                    std::string_view invitee_handle)
    -> std::expected<std::optional<InviteUser>, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  constexpr std::string_view sql =
      "SELECT u.handle,u.origin,u.status FROM invites i JOIN users u ON "
      "u.handle=i.inviter_handle AND u.origin_key=i.inviter_origin_key "
      "WHERE i.claimed_by_handle=?1 AND i.claimed_by_origin_key='' AND "
      "i.status='claimed'";
  auto statement =
      prepare(backend->database(), sql, "cannot prepare inviter lookup");
  if (!statement)
    return std::unexpected(statement.error());
  if (auto bound = bind_text(backend->database(), statement->get(), 1,
                             invitee_handle, "cannot bind invitee handle");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto row = sqlite3_step(statement->get());
  if (row == SQLITE_DONE)
    return std::optional<InviteUser>{};
  if (row != SQLITE_ROW) {
    return std::unexpected(
        sqlite_error(backend->database(), row, "cannot look up inviter"));
  }
  auto handle = column_text(statement->get(), 0, "inviter handle");
  auto origin = column_optional_text(statement->get(), 1, "inviter origin");
  auto status_text = column_text(statement->get(), 2, "inviter status");
  if (!handle || !origin || !status_text) {
    return std::unexpected(!handle   ? handle.error()
                           : !origin ? origin.error()
                                     : status_text.error());
  }
  const auto status = parse_user_status(*status_text);
  if (!status) {
    return std::unexpected(invalid_data("inviter has an unknown status"));
  }
  return std::optional<InviteUser>{InviteUser{.handle = std::move(*handle),
                                              .origin = std::move(*origin),
                                              .status = *status}};
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- recursive-query rows are validated explicitly before becoming ancestry evidence
auto SqliteStore::list_invite_subtree_impl(Transaction &transaction,
                                           std::string_view root_handle)
    -> std::expected<std::vector<InviteDescendant>, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  constexpr std::string_view exists_sql =
      "SELECT 1 FROM users WHERE handle=?1 AND origin_key=''";
  auto exists = prepare(backend->database(), exists_sql,
                        "cannot prepare invite subtree root lookup");
  if (!exists)
    return std::unexpected(exists.error());
  if (auto bound = bind_text(backend->database(), exists->get(), 1, root_handle,
                             "cannot bind invite subtree root");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto found = sqlite3_step(exists->get());
  if (found == SQLITE_DONE) {
    return std::unexpected(
        Error{ErrorCode::not_found, "invite subtree root does not exist"});
  }
  if (found != SQLITE_ROW) {
    return std::unexpected(sqlite_error(backend->database(), found,
                                        "cannot look up invite subtree root"));
  }

  constexpr std::string_view sql = R"sql(
WITH RECURSIVE descendants(handle,origin_key,depth,path) AS (
  SELECT i.claimed_by_handle,i.claimed_by_origin_key,1,
         ',' || hex(?1) || ':,' || hex(i.claimed_by_handle) || ':' ||
         hex(i.claimed_by_origin_key) || ','
    FROM invites i
   WHERE i.inviter_handle=?1 AND i.inviter_origin_key='' AND
         i.status='claimed'
  UNION ALL
  SELECT i.claimed_by_handle,i.claimed_by_origin_key,d.depth+1,
         d.path || hex(i.claimed_by_handle) || ':' ||
         hex(i.claimed_by_origin_key) || ','
    FROM descendants d JOIN invites i
      ON i.inviter_handle=d.handle AND i.inviter_origin_key=d.origin_key
   WHERE i.status='claimed' AND
         instr(d.path, ',' || hex(i.claimed_by_handle) || ':' ||
                       hex(i.claimed_by_origin_key) || ',')=0
)
SELECT u.handle,u.origin,u.status,d.depth
  FROM descendants d JOIN users u
    ON u.handle=d.handle AND u.origin_key=d.origin_key
 ORDER BY d.depth,u.handle,u.origin_key
)sql";
  auto statement =
      prepare(backend->database(), sql, "cannot prepare invite subtree query");
  if (!statement)
    return std::unexpected(statement.error());
  if (auto bound = bind_text(backend->database(), statement->get(), 1,
                             root_handle, "cannot bind invite subtree root");
      !bound) {
    return std::unexpected(bound.error());
  }

  std::vector<InviteDescendant> result;
  auto row = sqlite3_step(statement->get());
  for (; row == SQLITE_ROW; row = sqlite3_step(statement->get())) {
    auto handle = column_text(statement->get(), 0, "descendant handle");
    auto origin =
        column_optional_text(statement->get(), 1, "descendant origin");
    auto status_text = column_text(statement->get(), 2, "descendant status");
    const auto depth = sqlite3_column_int64(statement->get(), 3);
    if (!handle || !origin || !status_text || depth <= 0 ||
        depth > std::numeric_limits<std::uint32_t>::max()) {
      return std::unexpected(
          !handle        ? handle.error()
          : !origin      ? origin.error()
          : !status_text ? status_text.error()
                         : invalid_data("invite subtree depth is invalid"));
    }
    const auto status = parse_user_status(*status_text);
    if (!status) {
      return std::unexpected(
          invalid_data("invite descendant has an unknown status"));
    }
    result.push_back({.user = {.handle = std::move(*handle),
                               .origin = std::move(*origin),
                               .status = *status},
                      .depth = static_cast<std::uint32_t>(depth)});
  }
  if (row != SQLITE_DONE) {
    return std::unexpected(
        sqlite_error(backend->database(), row, "cannot read invite subtree"));
  }
  return result;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- create-or-update provisioning must remain one atomic startup operation
auto SqliteStore::reconcile_board_impl(Transaction &transaction,
                                       const BoardProvision &board)
    -> std::expected<BoardRecord, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  constexpr std::string_view find_sql =
      "SELECT board_id,title,description,status,guest_readable FROM boards "
      "WHERE name=?1 AND origin_key=''";
  auto find = prepare(backend->database(), find_sql,
                      "cannot prepare board declaration lookup");
  if (!find) {
    return std::unexpected(find.error());
  }
  if (auto bound = bind_text(backend->database(), find->get(), 1, board.name,
                             "cannot bind board declaration name");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto found = sqlite3_step(find->get());
  std::string board_id = board.board_id;
  if (found == SQLITE_ROW) {
    auto existing_id = column_text(find->get(), 0, "declared board ID");
    auto status = column_text(find->get(), 3, "declared board status");
    if (!existing_id || !status) {
      return std::unexpected(!existing_id ? existing_id.error()
                                          : status.error());
    }
    if (*status != "active") {
      return std::unexpected(Error{
          ErrorCode::conflict, "board declaration matches a tombstoned board"});
    }
    board_id = std::move(*existing_id);
    constexpr std::string_view update_sql =
        "UPDATE boards SET title=?1,guest_readable=?2 WHERE board_id=?3 AND "
        "origin_key='' AND status='active'";
    auto update = prepare(backend->database(), update_sql,
                          "cannot prepare board declaration update");
    if (!update) {
      return std::unexpected(update.error());
    }
    if (auto bound = bind_text(backend->database(), update->get(), 1,
                               board.title, "cannot bind board title");
        !bound) {
      return std::unexpected(bound.error());
    }
    if (auto bound = bind_integer(
            backend->database(), update->get(), 2,
            board.visibility == BoardVisibility::public_read ? 1 : 0,
            "cannot bind board visibility");
        !bound) {
      return std::unexpected(bound.error());
    }
    if (auto bound = bind_text(backend->database(), update->get(), 3, board_id,
                               "cannot bind declared board ID");
        !bound) {
      return std::unexpected(bound.error());
    }
    if (const auto updated = sqlite3_step(update->get());
        updated != SQLITE_DONE) {
      return std::unexpected(sqlite_error(backend->database(), updated,
                                          "cannot update declared board"));
    }
  } else if (found == SQLITE_DONE) {
    constexpr std::string_view insert_sql =
        "INSERT INTO boards(board_id,name,title,guest_readable,created_at) "
        "VALUES(?1,?2,?3,?4,?5)";
    auto insert = prepare(backend->database(), insert_sql,
                          "cannot prepare board declaration insert");
    if (!insert) {
      return std::unexpected(insert.error());
    }
    const std::array texts{std::string_view{board_id},
                           std::string_view{board.name},
                           std::string_view{board.title}};
    for (std::size_t index = 0; index < texts.size(); ++index) {
      if (auto bound = bind_text(backend->database(), insert->get(),
                                 static_cast<int>(index + 1U), texts[index],
                                 "cannot bind board declaration");
          !bound) {
        return std::unexpected(bound.error());
      }
    }
    if (auto bound = bind_integer(
            backend->database(), insert->get(), 4,
            board.visibility == BoardVisibility::public_read ? 1 : 0,
            "cannot bind board visibility");
        !bound) {
      return std::unexpected(bound.error());
    }
    if (auto bound = bind_integer(backend->database(), insert->get(), 5,
                                  board.created_at.value,
                                  "cannot bind board creation time");
        !bound) {
      return std::unexpected(bound.error());
    }
    const auto inserted = sqlite3_step(insert->get());
    if (inserted != SQLITE_DONE) {
      auto error = sqlite_error(backend->database(), inserted,
                                "cannot insert declared board");
      if (error.code == ErrorCode::constraint_violation) {
        error.code = ErrorCode::conflict;
      }
      return std::unexpected(std::move(error));
    }
  } else {
    return std::unexpected(sqlite_error(backend->database(), found,
                                        "cannot look up declared board"));
  }
  return BoardRecord{.board_id = std::move(board_id),
                     .name = board.name,
                     .title = board.title,
                     .description = {},
                     .visibility = board.visibility,
                     .unread_messages = 0};
}

auto SqliteStore::list_boards_impl(Transaction &transaction,
                                   const BoardReader &reader)
    -> std::expected<std::vector<BoardRecord>, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  constexpr std::string_view sql = R"sql(
SELECT b.board_id,b.name,b.title,b.description,b.guest_readable,
       CASE WHEN ?1 IS NULL THEN 0 ELSE (
         SELECT count(*) FROM messages m
         JOIN threads t ON t.thread_id=m.thread_id AND t.board_id=m.board_id
         LEFT JOIN board_reads br ON br.user_handle=?1 AND
              br.user_origin_key='' AND br.board_id=b.board_id
         LEFT JOIN thread_reads tr ON tr.user_handle=?1 AND
              tr.user_origin_key='' AND tr.thread_id=m.thread_id
         WHERE m.board_id=b.board_id AND m.status='active' AND
               t.status='active' AND m.local_sequence >
               max(coalesce(br.read_through_sequence,0),
                   coalesce(tr.read_through_sequence,0))
       ) END
FROM boards b
WHERE b.status='active' AND (?2=1 OR b.guest_readable=1)
ORDER BY b.name,b.board_id
)sql";
  auto statement =
      prepare(backend->database(), sql, "cannot prepare visible board list");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  auto handle_bound =
      reader.handle ? bind_text(backend->database(), statement->get(), 1,
                                *reader.handle, "cannot bind board reader")
                    : bind_null(backend->database(), statement->get(), 1,
                                "cannot bind guest board reader");
  if (!handle_bound) {
    return std::unexpected(handle_bound.error());
  }
  if (auto bound = bind_integer(backend->database(), statement->get(), 2,
                                reader.may_read_registered ? 1 : 0,
                                "cannot bind board read scope");
      !bound) {
    return std::unexpected(bound.error());
  }
  std::vector<BoardRecord> result;
  for (;;) {
    const auto row = sqlite3_step(statement->get());
    if (row == SQLITE_DONE) {
      return result;
    }
    if (row != SQLITE_ROW) {
      return std::unexpected(
          sqlite_error(backend->database(), row, "cannot read visible boards"));
    }
    auto id = column_text(statement->get(), 0, "board ID");
    auto name = column_text(statement->get(), 1, "board name");
    auto title = column_text(statement->get(), 2, "board title");
    auto description = column_text(statement->get(), 3, "board description");
    auto guest = column_integer(statement->get(), 4, "board guest visibility");
    auto unread = column_integer(statement->get(), 5, "board unread count");
    if (!id || !name || !title || !description || !guest || !unread ||
        (*guest != 0 && *guest != 1) || *unread < 0) {
      return std::unexpected(invalid_data("visible board row is invalid"));
    }
    result.push_back({.board_id = std::move(*id),
                      .name = std::move(*name),
                      .title = std::move(*title),
                      .description = std::move(*description),
                      .visibility = *guest == 1
                                        ? BoardVisibility::public_read
                                        : BoardVisibility::registered_only,
                      .unread_messages = static_cast<std::uint64_t>(*unread)});
  }
}

auto SqliteStore::list_threads_impl(Transaction &transaction,
                                    std::string_view board_id,
                                    const BoardReader &reader)
    -> std::expected<std::vector<ThreadRecord>, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  constexpr std::string_view sql = R"sql(
SELECT t.thread_id,t.board_id,t.author_handle,t.subject,t.created_at,
       t.updated_at,t.locked_at,count(m.message_id),
       CASE WHEN ?2 IS NULL THEN 0 ELSE sum(CASE WHEN m.local_sequence >
         max(coalesce(br.read_through_sequence,0),
             coalesce(tr.read_through_sequence,0)) THEN 1 ELSE 0 END) END
FROM threads t JOIN boards b ON b.board_id=t.board_id
LEFT JOIN messages m ON m.thread_id=t.thread_id AND m.board_id=t.board_id AND
     m.status='active'
LEFT JOIN board_reads br ON br.user_handle=?2 AND br.user_origin_key='' AND
     br.board_id=t.board_id
LEFT JOIN thread_reads tr ON tr.user_handle=?2 AND tr.user_origin_key='' AND
     tr.thread_id=t.thread_id
WHERE t.board_id=?1 AND t.status='active' AND b.status='active' AND
      (?3=1 OR b.guest_readable=1)
GROUP BY t.thread_id
ORDER BY t.updated_at DESC,t.thread_id
)sql";
  auto statement =
      prepare(backend->database(), sql, "cannot prepare visible thread list");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  if (auto bound = bind_text(backend->database(), statement->get(), 1, board_id,
                             "cannot bind thread board");
      !bound) {
    return std::unexpected(bound.error());
  }
  auto handle_bound =
      reader.handle ? bind_text(backend->database(), statement->get(), 2,
                                *reader.handle, "cannot bind thread reader")
                    : bind_null(backend->database(), statement->get(), 2,
                                "cannot bind guest thread reader");
  if (!handle_bound) {
    return std::unexpected(handle_bound.error());
  }
  if (auto bound = bind_integer(backend->database(), statement->get(), 3,
                                reader.may_read_registered ? 1 : 0,
                                "cannot bind thread read scope");
      !bound) {
    return std::unexpected(bound.error());
  }
  std::vector<ThreadRecord> result;
  for (;;) {
    const auto row = sqlite3_step(statement->get());
    if (row == SQLITE_DONE) {
      return result;
    }
    if (row != SQLITE_ROW) {
      return std::unexpected(sqlite_error(backend->database(), row,
                                          "cannot read visible threads"));
    }
    auto id = column_text(statement->get(), 0, "thread ID");
    auto stored_board = column_text(statement->get(), 1, "thread board ID");
    auto author = column_text(statement->get(), 2, "thread author");
    auto subject = column_text(statement->get(), 3, "thread subject");
    auto created = column_integer(statement->get(), 4, "thread created_at");
    auto updated = column_integer(statement->get(), 5, "thread updated_at");
    auto count = column_integer(statement->get(), 7, "thread message count");
    auto unread = column_integer(statement->get(), 8, "thread unread count");
    if (!id || !stored_board || !author || !subject || !created || !updated ||
        !count || !unread || *count < 0 || *unread < 0) {
      return std::unexpected(invalid_data("visible thread row is invalid"));
    }
    result.push_back(
        {.thread_id = std::move(*id),
         .board_id = std::move(*stored_board),
         .author_handle = std::move(*author),
         .subject = std::move(*subject),
         .created_at = {*created},
         .updated_at = {*updated},
         .locked = sqlite3_column_type(statement->get(), 6) != SQLITE_NULL,
         .message_count = static_cast<std::uint64_t>(*count),
         .unread_messages = static_cast<std::uint64_t>(*unread)});
  }
}

auto SqliteStore::list_messages_for_thread_impl(Transaction &transaction,
                                                std::string_view board_id,
                                                std::string_view thread_id,
                                                const BoardReader &reader)
    -> std::expected<std::vector<MessageRecord>, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  std::string sql = "SELECT ";
  sql += message_columns;
  sql += "FROM messages m JOIN threads t ON t.thread_id=m.thread_id AND "
         "t.board_id=m.board_id JOIN boards b ON b.board_id=m.board_id "
         "WHERE m.board_id=?1 AND m.thread_id=?2 AND m.status='active' AND "
         "t.status='active' AND b.status='active' AND (?3=1 OR "
         "b.guest_readable=1) ORDER BY m.local_sequence";
  auto statement =
      prepare(backend->database(), sql, "cannot prepare visible message list");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  if (auto bound = bind_text(backend->database(), statement->get(), 1, board_id,
                             "cannot bind message board");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_text(backend->database(), statement->get(), 2,
                             thread_id, "cannot bind message thread");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_integer(backend->database(), statement->get(), 3,
                                reader.may_read_registered ? 1 : 0,
                                "cannot bind message read scope");
      !bound) {
    return std::unexpected(bound.error());
  }
  std::vector<MessageRecord> result;
  for (;;) {
    const auto row = sqlite3_step(statement->get());
    if (row == SQLITE_DONE) {
      return result;
    }
    if (row != SQLITE_ROW) {
      return std::unexpected(sqlite_error(backend->database(), row,
                                          "cannot read visible messages"));
    }
    auto message = read_message(statement->get());
    if (!message) {
      return std::unexpected(message.error());
    }
    result.push_back(std::move(*message));
  }
}

auto SqliteStore::create_thread_impl(Transaction &transaction,
                                     const ThreadCreate &thread)
    -> std::expected<MessageRecord, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  auto sequence = next_message_sequence(backend->database());
  if (!sequence) {
    return std::unexpected(sequence.error());
  }
  constexpr std::string_view sql =
      "INSERT INTO threads(thread_id,board_id,author_handle,subject,created_at,"
      "updated_at) SELECT ?1,?2,?3,?4,?5,?5 FROM boards WHERE board_id=?2 "
      "AND status='active' AND EXISTS(SELECT 1 FROM users WHERE handle=?3 "
      "AND origin_key='' AND status='active')";
  auto statement = prepare(backend->database(), sql, "cannot prepare thread");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  const std::array texts{
      std::string_view{thread.thread_id}, std::string_view{thread.board_id},
      std::string_view{thread.author_handle}, std::string_view{thread.subject}};
  for (std::size_t index = 0; index < texts.size(); ++index) {
    if (auto bound = bind_text(backend->database(), statement->get(),
                               static_cast<int>(index + 1U), texts[index],
                               "cannot bind thread creation");
        !bound) {
      return std::unexpected(bound.error());
    }
  }
  if (auto bound = bind_integer(backend->database(), statement->get(), 5,
                                thread.created_at.value,
                                "cannot bind thread creation time");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto inserted = sqlite3_step(statement->get());
  if (inserted != SQLITE_DONE || sqlite3_changes64(backend->database()) != 1) {
    if (inserted == SQLITE_DONE) {
      return std::unexpected(
          Error{ErrorCode::not_found, "thread board does not exist"});
    }
    return std::unexpected(
        sqlite_error(backend->database(), inserted, "cannot create thread"));
  }
  MessageRecord message{.message_id = thread.message_id,
                        .board_id = thread.board_id,
                        .thread_id = thread.thread_id,
                        .parent_message_id = std::nullopt,
                        .author_handle = thread.author_handle,
                        .author_origin = std::nullopt,
                        .body = thread.body,
                        .posted_at = thread.created_at,
                        .received_at = thread.created_at,
                        .local_sequence = *sequence,
                        .status = ContentStatus::active};
  if (auto stored = insert_message(backend->database(), message); !stored) {
    return std::unexpected(stored.error());
  }
  return message;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- thread and parent authority checks share the message insertion transaction
auto SqliteStore::create_reply_impl(Transaction &transaction,
                                    const ReplyCreate &reply)
    -> std::expected<MessageRecord, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  constexpr std::string_view thread_sql =
      "SELECT 1 FROM threads t JOIN boards b ON b.board_id=t.board_id WHERE "
      "t.thread_id=?1 AND t.board_id=?2 AND t.status='active' AND "
      "t.locked_at IS NULL AND b.status='active' AND EXISTS(SELECT 1 FROM "
      "users WHERE handle=?3 AND origin_key='' AND status='active')";
  auto thread = prepare(backend->database(), thread_sql,
                        "cannot prepare reply thread lookup");
  if (!thread) {
    return std::unexpected(thread.error());
  }
  if (auto bound = bind_text(backend->database(), thread->get(), 1,
                             reply.thread_id, "cannot bind reply thread");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_text(backend->database(), thread->get(), 2,
                             reply.board_id, "cannot bind reply board");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_text(backend->database(), thread->get(), 3,
                             reply.author_handle, "cannot bind reply author");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (const auto found = sqlite3_step(thread->get()); found != SQLITE_ROW) {
    return std::unexpected(Error{ErrorCode::not_found,
                                 "reply thread is absent, deleted, or locked"});
  }
  if (reply.parent_message_id) {
    constexpr std::string_view parent_sql =
        "SELECT 1 FROM messages WHERE message_id=?1 AND thread_id=?2 AND "
        "board_id=?3 AND status='active'";
    auto parent = prepare(backend->database(), parent_sql,
                          "cannot prepare quote parent lookup");
    if (!parent) {
      return std::unexpected(parent.error());
    }
    const std::array values{std::string_view{*reply.parent_message_id},
                            std::string_view{reply.thread_id},
                            std::string_view{reply.board_id}};
    for (std::size_t index = 0; index < values.size(); ++index) {
      if (auto bound = bind_text(backend->database(), parent->get(),
                                 static_cast<int>(index + 1U), values[index],
                                 "cannot bind quote parent");
          !bound) {
        return std::unexpected(bound.error());
      }
    }
    if (const auto found = sqlite3_step(parent->get()); found != SQLITE_ROW) {
      return std::unexpected(
          Error{ErrorCode::not_found, "quote parent is not active in thread"});
    }
  }
  auto sequence = next_message_sequence(backend->database());
  if (!sequence) {
    return std::unexpected(sequence.error());
  }
  MessageRecord message{.message_id = reply.message_id,
                        .board_id = reply.board_id,
                        .thread_id = reply.thread_id,
                        .parent_message_id = reply.parent_message_id,
                        .author_handle = reply.author_handle,
                        .author_origin = std::nullopt,
                        .body = reply.body,
                        .posted_at = reply.created_at,
                        .received_at = reply.created_at,
                        .local_sequence = *sequence,
                        .status = ContentStatus::active};
  if (auto stored = insert_message(backend->database(), message); !stored) {
    return std::unexpected(stored.error());
  }
  constexpr std::string_view update_sql =
      "UPDATE threads SET updated_at=max(updated_at,?1) WHERE thread_id=?2 "
      "AND board_id=?3";
  auto update = prepare(backend->database(), update_sql,
                        "cannot prepare thread activity update");
  if (!update) {
    return std::unexpected(update.error());
  }
  if (auto bound = bind_integer(backend->database(), update->get(), 1,
                                reply.created_at.value,
                                "cannot bind thread activity time");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_text(backend->database(), update->get(), 2,
                             reply.thread_id, "cannot bind updated thread");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_text(backend->database(), update->get(), 3,
                             reply.board_id, "cannot bind updated board");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (const auto updated = sqlite3_step(update->get());
      updated != SQLITE_DONE) {
    return std::unexpected(sqlite_error(backend->database(), updated,
                                        "cannot update thread activity"));
  }
  return message;
}

auto SqliteStore::mark_thread_read_impl(Transaction &transaction,
                                        std::string_view user_handle,
                                        std::string_view board_id,
                                        std::string_view thread_id)
    -> std::expected<void, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  constexpr std::string_view sql = R"sql(
INSERT INTO thread_reads(user_handle,board_id,thread_id,read_through_sequence)
SELECT ?1,?2,?3,coalesce(max(m.local_sequence),0)
FROM threads t JOIN boards b ON b.board_id=t.board_id
LEFT JOIN messages m ON m.thread_id=t.thread_id AND
     m.board_id=t.board_id AND m.status='active'
WHERE t.thread_id=?3 AND t.board_id=?2 AND t.status='active' AND
      b.status='active' AND EXISTS(
        SELECT 1 FROM users u WHERE u.handle=?1 AND u.origin_key='' AND
               u.status='active')
HAVING count(t.thread_id)>0
ON CONFLICT(user_handle,user_origin_key,thread_id) DO UPDATE SET
read_through_sequence=max(thread_reads.read_through_sequence,
                          excluded.read_through_sequence)
)sql";
  auto statement =
      prepare(backend->database(), sql, "cannot prepare thread read marker");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  const std::array values{user_handle, board_id, thread_id};
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (auto bound = bind_text(backend->database(), statement->get(),
                               static_cast<int>(index + 1U), values[index],
                               "cannot bind thread read marker");
        !bound) {
      return std::unexpected(bound.error());
    }
  }
  const auto updated = sqlite3_step(statement->get());
  if (updated != SQLITE_DONE) {
    return std::unexpected(
        sqlite_error(backend->database(), updated, "cannot mark thread read"));
  }
  if (sqlite3_changes64(backend->database()) == 0) {
    return std::unexpected(
        Error{ErrorCode::not_found, "thread read target does not exist"});
  }
  return {};
}

auto SqliteStore::catch_up_board_impl(Transaction &transaction,
                                      std::string_view user_handle,
                                      std::string_view board_id)
    -> std::expected<void, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  constexpr std::string_view sql = R"sql(
INSERT INTO board_reads(user_handle,board_id,read_through_sequence)
SELECT ?1,b.board_id,coalesce(max(m.local_sequence),0)
FROM boards b LEFT JOIN threads t ON t.board_id=b.board_id AND
     t.status='active'
LEFT JOIN messages m ON m.thread_id=t.thread_id AND m.board_id=b.board_id AND
     m.status='active'
WHERE b.board_id=?2 AND b.status='active' AND EXISTS(
  SELECT 1 FROM users u WHERE u.handle=?1 AND u.origin_key='' AND
         u.status='active')
GROUP BY b.board_id
ON CONFLICT(user_handle,user_origin_key,board_id) DO UPDATE SET
read_through_sequence=max(board_reads.read_through_sequence,
                          excluded.read_through_sequence)
)sql";
  auto statement =
      prepare(backend->database(), sql, "cannot prepare board catch-up marker");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  if (auto bound = bind_text(backend->database(), statement->get(), 1,
                             user_handle, "cannot bind board reader");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_text(backend->database(), statement->get(), 2, board_id,
                             "cannot bind catch-up board");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto updated = sqlite3_step(statement->get());
  if (updated != SQLITE_DONE) {
    return std::unexpected(
        sqlite_error(backend->database(), updated, "cannot catch up board"));
  }
  if (sqlite3_changes64(backend->database()) == 0) {
    return std::unexpected(
        Error{ErrorCode::not_found, "catch-up board does not exist"});
  }
  return {};
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- target visibility and reporter authority checks remain co-located
auto SqliteStore::submit_report_impl(Transaction &transaction,
                                     const ReportSubmission &report)
    -> std::expected<void, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  const auto &target_id = std::get<std::string>(report.target.id);
  std::string_view target_kind;
  std::string_view target_sql;
  if (report.target.kind == ContentKind::thread) {
    target_kind = "thread";
    target_sql = "SELECT 1 FROM threads t JOIN boards b ON "
                 "b.board_id=t.board_id WHERE t.thread_id=?1 "
                 "AND t.status='active' AND b.status='active' "
                 "AND (b.guest_readable=1 OR EXISTS(SELECT 1 "
                 "FROM users u WHERE u.handle=?2 AND "
                 "u.origin_key='' AND u.status='active'))";
  } else if (report.target.kind == ContentKind::message) {
    target_kind = "message";
    target_sql = "SELECT 1 FROM messages m JOIN threads t ON "
                 "t.thread_id=m.thread_id AND t.board_id=m.board_id "
                 "JOIN boards b ON b.board_id=m.board_id WHERE "
                 "m.message_id=?1 AND m.status='active' AND "
                 "t.status='active' AND b.status='active' AND "
                 "(b.guest_readable=1 OR EXISTS(SELECT 1 FROM users u "
                 "WHERE u.handle=?2 AND u.origin_key='' AND "
                 "u.status='active'))";
  } else {
    target_kind = "oneliner";
    target_sql = "SELECT 1 FROM oneliners o WHERE o.oneliner_id=?1 AND "
                 "o.status='active' AND (?2 IS NULL OR EXISTS(SELECT 1 "
                 "FROM users u WHERE u.handle=?2 AND u.origin_key='' AND "
                 "u.status='active'))";
  }
  auto target = prepare(backend->database(), target_sql,
                        "cannot prepare report target lookup");
  if (!target) {
    return std::unexpected(target.error());
  }
  if (auto bound = bind_text(backend->database(), target->get(), 1, target_id,
                             "cannot bind report target");
      !bound) {
    return std::unexpected(bound.error());
  }
  auto reporter_scope =
      report.reporter_handle
          ? bind_text(backend->database(), target->get(), 2,
                      *report.reporter_handle,
                      "cannot bind report visibility scope")
          : bind_null(backend->database(), target->get(), 2,
                      "cannot bind guest report visibility scope");
  if (!reporter_scope) {
    return std::unexpected(reporter_scope.error());
  }
  if (const auto found = sqlite3_step(target->get()); found != SQLITE_ROW) {
    return std::unexpected(
        Error{ErrorCode::not_found, "report target is not visible"});
  }
  constexpr std::string_view insert_sql =
      "INSERT INTO reports(report_id,reporter_kind,reporter_handle,target_kind,"
      "target_id,evidence,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)";
  auto insert =
      prepare(backend->database(), insert_sql, "cannot prepare report insert");
  if (!insert) {
    return std::unexpected(insert.error());
  }
  if (auto bound = bind_text(backend->database(), insert->get(), 1,
                             report.report_id, "cannot bind report ID");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_text(backend->database(), insert->get(), 2,
                             report.reporter_handle ? "registered" : "guest",
                             "cannot bind reporter kind");
      !bound) {
    return std::unexpected(bound.error());
  }
  auto reporter =
      report.reporter_handle
          ? bind_text(backend->database(), insert->get(), 3,
                      *report.reporter_handle, "cannot bind reporter handle")
          : bind_null(backend->database(), insert->get(), 3,
                      "cannot bind anonymous reporter");
  if (!reporter) {
    return std::unexpected(reporter.error());
  }
  const std::array values{target_kind, std::string_view{target_id},
                          std::string_view{report.reason}};
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (auto bound = bind_text(backend->database(), insert->get(),
                               static_cast<int>(index + 4U), values[index],
                               "cannot bind report content");
        !bound) {
      return std::unexpected(bound.error());
    }
  }
  if (auto bound = bind_integer(backend->database(), insert->get(), 7,
                                report.created_at.value,
                                "cannot bind report creation time");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto inserted = sqlite3_step(insert->get());
  if (inserted != SQLITE_DONE) {
    auto error =
        sqlite_error(backend->database(), inserted, "cannot submit report");
    if (error.code == ErrorCode::constraint_violation) {
      error.code = ErrorCode::conflict;
    }
    return std::unexpected(std::move(error));
  }
  return {};
}

auto SqliteStore::create_oneliner_impl(Transaction &transaction,
                                       const OnelinerCreate &oneliner,
                                       const OnelinerPolicy &policy)
    -> std::expected<OnelinerRecord, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }

  constexpr std::string_view count_sql =
      "SELECT count(*) FROM oneliners WHERE author_handle=?1 AND "
      "author_origin_key='' AND received_at>?2";
  auto count = prepare(backend->database(), count_sql,
                       "cannot prepare one-liner rate lookup");
  if (!count) {
    return std::unexpected(count.error());
  }
  if (auto bound =
          bind_text(backend->database(), count->get(), 1,
                    oneliner.author_handle, "cannot bind one-liner author");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_integer(
          backend->database(), count->get(), 2,
          saturating_subtract(oneliner.received_at, policy.window_seconds),
          "cannot bind one-liner rate window");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto counted = sqlite3_step(count->get());
  if (counted != SQLITE_ROW) {
    return std::unexpected(sqlite_error(backend->database(), counted,
                                        "cannot count recent one-liners"));
  }
  auto recent = column_integer(count->get(), 0, "recent one-liner count");
  if (!recent || *recent < 0) {
    return std::unexpected(recent ? invalid_data("one-liner count is invalid")
                                  : recent.error());
  }
  if (static_cast<std::uint64_t>(*recent) >= policy.max_posts) {
    return std::unexpected(
        Error{ErrorCode::conflict, "one-liner rate limit reached"});
  }

  constexpr std::string_view insert_sql = R"sql(
INSERT INTO oneliners(oneliner_id,author_handle,body,posted_at,received_at)
SELECT ?1,?2,?3,?4,?5 FROM users
WHERE handle=?2 AND origin_key='' AND status='active'
)sql";
  auto insert = prepare(backend->database(), insert_sql,
                        "cannot prepare one-liner insert");
  if (!insert) {
    return std::unexpected(insert.error());
  }
  const std::array text_values{std::string_view{oneliner.oneliner_id},
                               std::string_view{oneliner.author_handle},
                               std::string_view{oneliner.body}};
  for (std::size_t index = 0; index < text_values.size(); ++index) {
    if (auto bound = bind_text(backend->database(), insert->get(),
                               static_cast<int>(index + 1U), text_values[index],
                               "cannot bind one-liner content");
        !bound) {
      return std::unexpected(bound.error());
    }
  }
  if (auto bound = bind_integer(backend->database(), insert->get(), 4,
                                oneliner.posted_at.value,
                                "cannot bind one-liner posted time");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_integer(backend->database(), insert->get(), 5,
                                oneliner.received_at.value,
                                "cannot bind one-liner received time");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto inserted = sqlite3_step(insert->get());
  if (inserted != SQLITE_DONE) {
    auto error =
        sqlite_error(backend->database(), inserted, "cannot create one-liner");
    if (error.code == ErrorCode::constraint_violation) {
      error.code = ErrorCode::conflict;
    }
    return std::unexpected(std::move(error));
  }
  if (sqlite3_changes64(backend->database()) != 1) {
    return std::unexpected(Error{
        ErrorCode::not_found, "one-liner author is not an active local user"});
  }
  return OnelinerRecord{.oneliner_id = oneliner.oneliner_id,
                        .author_handle = oneliner.author_handle,
                        .author_origin = std::nullopt,
                        .body = oneliner.body,
                        .posted_at = oneliner.posted_at,
                        .received_at = oneliner.received_at,
                        .status = ContentStatus::active};
}

auto SqliteStore::list_oneliners_impl(Transaction &transaction,
                                      UtcEpochSeconds now,
                                      const OnelinerPolicy &policy,
                                      std::uint32_t limit)
    -> std::expected<std::vector<OnelinerRecord>, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  constexpr std::string_view sql = R"sql(
SELECT oneliner_id,author_handle,author_origin,body,posted_at,received_at,status
FROM oneliners
WHERE status='active' AND received_at>?1
ORDER BY received_at DESC,oneliner_id DESC
LIMIT ?2
)sql";
  auto statement =
      prepare(backend->database(), sql, "cannot prepare one-liner list");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  if (auto bound =
          bind_integer(backend->database(), statement->get(), 1,
                       saturating_subtract(now, policy.retention_seconds),
                       "cannot bind one-liner retention cutoff");
      !bound) {
    return std::unexpected(bound.error());
  }
  if (auto bound = bind_integer(backend->database(), statement->get(), 2,
                                static_cast<std::int64_t>(limit),
                                "cannot bind one-liner list limit");
      !bound) {
    return std::unexpected(bound.error());
  }

  std::vector<OnelinerRecord> result;
  result.reserve(limit);
  for (;;) {
    const auto row = sqlite3_step(statement->get());
    if (row == SQLITE_DONE) {
      return result;
    }
    if (row != SQLITE_ROW) {
      return std::unexpected(
          sqlite_error(backend->database(), row, "cannot read one-liner list"));
    }
    auto id = column_text(statement->get(), 0, "one-liner ID");
    auto author = column_text(statement->get(), 1, "one-liner author");
    auto origin =
        column_optional_text(statement->get(), 2, "one-liner author origin");
    auto body = column_text(statement->get(), 3, "one-liner body");
    auto posted = column_integer(statement->get(), 4, "one-liner posted_at");
    auto received =
        column_integer(statement->get(), 5, "one-liner received_at");
    auto status = column_text(statement->get(), 6, "one-liner status");
    if (!id || !author || !origin || !body || !posted || !received || !status ||
        *status != "active") {
      return std::unexpected(invalid_data("one-liner row is invalid"));
    }
    result.push_back({.oneliner_id = std::move(*id),
                      .author_handle = std::move(*author),
                      .author_origin = std::move(*origin),
                      .body = std::move(*body),
                      .posted_at = {*posted},
                      .received_at = {*received},
                      .status = ContentStatus::active});
  }
}

auto SqliteStore::purge_expired_oneliners_impl(Transaction &transaction,
                                               UtcEpochSeconds now,
                                               const OnelinerPolicy &policy)
    -> std::expected<std::uint64_t, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(
        Error{ErrorCode::invalid_state, "invalid SQLite transaction"});
  }
  auto statement = prepare(backend->database(),
                           "DELETE FROM oneliners WHERE received_at<=?1",
                           "cannot prepare one-liner purge");
  if (!statement) {
    return std::unexpected(statement.error());
  }
  if (auto bound =
          bind_integer(backend->database(), statement->get(), 1,
                       saturating_subtract(now, policy.retention_seconds),
                       "cannot bind one-liner purge cutoff");
      !bound) {
    return std::unexpected(bound.error());
  }
  const auto deleted = sqlite3_step(statement->get());
  if (deleted != SQLITE_DONE) {
    return std::unexpected(sqlite_error(backend->database(), deleted,
                                        "cannot purge expired one-liners"));
  }
  const auto changes = sqlite3_changes64(backend->database());
  if (changes < 0) {
    return std::unexpected(invalid_data("one-liner purge count is invalid"));
  }
  return static_cast<std::uint64_t>(changes);
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
  return scalar_integer(backend->database(), sql, "SQLite test query failed");
}

auto SqliteStore::scalar_text_for_testing(Transaction &transaction,
                                          std::string_view sql)
    -> std::expected<std::string, Error> {
  auto *backend = dynamic_cast<SqliteTransactionBackend *>(
      transaction_backend(transaction));
  if (backend == nullptr) {
    return std::unexpected(Error{
        ErrorCode::invalid_state,
        "transaction is inactive or belongs to a different SQLite store"});
  }
  return scalar_text(backend->database(), sql, "SQLite test query failed");
}

namespace detail {

// NOLINTNEXTLINE(readability-function-cognitive-complexity) -- admission, migration, and rollback form one fail-closed database sequence
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

  const auto fail =
      [&](Error error) -> std::expected<std::unique_ptr<SqliteStore>, Error> {
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
  if (*version < 0 || static_cast<std::uint64_t>(*version) > current_version) {
    return fail(
        invalid_data("SQLite schema version is newer than this Anvil binary"));
  }

  if (*application_id == 0 && !migrations.empty()) {
    if (auto claimed = exec(database->get(), "PRAGMA application_id=1095652940",
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
      if (auto applied =
              exec(database->get(), migration.sql,
                   "SQLite migration " + std::to_string(migration.version) +
                       " failed");
          !applied) {
        return fail(applied.error());
      }
    }
    if (auto recorded =
            exec(database->get(),
                 "PRAGMA user_version=" + std::to_string(migration.version),
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
  if (*application_id != anvil_application_id || *version != current_version) {
    return fail(invalid_data("SQLite migration metadata verification failed"));
  }
  if (auto committed =
          exec(database->get(), "COMMIT", "cannot commit SQLite migrations");
      !committed) {
    return fail(committed.error());
  }

  return std::unique_ptr<SqliteStore>(
      new SqliteStore(path, options, current_version));
}

} // namespace detail
} // namespace anvil::store
