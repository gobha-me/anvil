#pragma once

#include <anvil/store.hpp>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string_view>

namespace anvil::store {

struct SqliteOptions {
  std::chrono::milliseconds busy_timeout{std::chrono::seconds{5}};
};

namespace detail {

struct SqliteMigration {
  std::uint32_t version{};
  std::string_view sql;
};

}  // namespace detail

// Server-private SQLite implementation. It intentionally retains only the
// database path and configuration: every Transaction owns a fresh connection,
// so no SQLite handle is inherited by a forked session worker.
class SqliteStore final : public Store {
 public:
  [[nodiscard]] static auto open(const std::filesystem::path &path)
      -> std::expected<std::unique_ptr<SqliteStore>, Error>;

  SqliteStore(std::filesystem::path path, SqliteOptions options,
              std::uint32_t schema_version);

  [[nodiscard]] auto begin(TransactionMode mode)
      -> std::expected<Transaction, Error> final;

  // Server-private online backup support. The destination must not already
  // exist and is removed if SQLite cannot publish a complete backup.
  [[nodiscard]] auto backup_to(const std::filesystem::path &destination)
      -> std::expected<void, Error>;

  // Restore an offline snapshot into a new database file. The restored
  // database is validated and migrated before it is published by the caller.
  [[nodiscard]] static auto
  restore_from(const std::filesystem::path &snapshot,
               const std::filesystem::path &destination)
      -> std::expected<void, Error>;

  [[nodiscard]] auto schema_version() const noexcept -> std::uint32_t;

  // Internal probes used by backend tests. Domain code must continue to add
  // backend-neutral Store operations instead of exposing SQL at call sites.
  [[nodiscard]] auto execute_for_testing(Transaction &transaction,
                                         std::string_view sql)
      -> std::expected<void, Error>;
  [[nodiscard]] auto scalar_for_testing(Transaction &transaction,
                                        std::string_view sql)
      -> std::expected<std::int64_t, Error>;
  [[nodiscard]] auto scalar_text_for_testing(Transaction &transaction,
                                             std::string_view sql)
      -> std::expected<std::string, Error>;

 private:
  [[nodiscard]] auto tombstone_impl(Transaction &transaction,
                                    const ContentRef &content)
      -> std::expected<void, Error> final;
  [[nodiscard]] auto find_message_impl(Transaction &transaction,
                                       std::string_view message_id,
                                       ContentVisibility visibility)
      -> std::expected<std::optional<MessageRecord>, Error> final;
  [[nodiscard]] auto list_messages_for_board_impl(Transaction &transaction,
                                                  std::string_view board_id,
                                                  ContentVisibility visibility)
      -> std::expected<std::vector<MessageRecord>, Error> final;
  [[nodiscard]] auto find_local_credential_impl(Transaction &transaction,
                                                std::string_view fingerprint)
      -> std::expected<std::optional<CredentialRecord>, Error> final;
  [[nodiscard]] auto
  provision_local_credential_impl(Transaction &transaction,
                                  const LocalCredentialProvision &provision)
      -> std::expected<void, Error> final;

  std::filesystem::path path_;
  SqliteOptions options_;
  std::uint32_t schema_version_{};
};

namespace detail {

[[nodiscard]] auto
open_sqlite_store(const std::filesystem::path &path,
                  std::span<const SqliteMigration> migrations,
                  SqliteOptions options = {})
    -> std::expected<std::unique_ptr<SqliteStore>, Error>;

}  // namespace detail

}  // namespace anvil::store
