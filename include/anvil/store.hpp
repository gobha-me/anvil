#pragma once

#include <compare>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace anvil::store {

// UTC at the storage boundary is represented as signed seconds from the Unix
// epoch. The wrapper prevents accidental mixing with durations or local-time
// values while keeping every backend's persisted representation explicit.
struct UtcEpochSeconds {
  std::int64_t value{};

  [[nodiscard]] auto
  operator<=>(const UtcEpochSeconds &) const noexcept = default;
};

enum class ErrorCode {
  unavailable,
  conflict,
  not_found,
  constraint_violation,
  invalid_data,
  invalid_state,
  internal,
};

struct Error {
  ErrorCode code{ErrorCode::internal};
  std::string detail;

  [[nodiscard]] auto operator==(const Error &) const -> bool = default;
};

enum class TransactionMode {
  read_only,
  read_write,
};

enum class ContentKind {
  board,
  thread,
  message,
  file,
  leaderboard_entry,
  oneliner,
  block,
  report,
};

// Content identifiers remain backend-neutral. Every current content table uses
// an opaque string identifier except blocks, whose schema key is an integer.
// Store implementations must reject a kind/value mismatch rather than
// coercing hostile input into a different identifier.
struct ContentRef {
  ContentKind kind{ContentKind::message};
  std::variant<std::string, std::int64_t> id;

  [[nodiscard]] auto operator==(const ContentRef &) const -> bool = default;
};

enum class ContentStatus {
  active,
  tombstoned,
};

struct MessageRecord {
  std::string message_id;
  std::string board_id;
  std::string thread_id;
  std::optional<std::string> parent_message_id;
  std::string author_handle;
  std::optional<std::string> author_origin;
  std::string body;
  UtcEpochSeconds posted_at;
  UtcEpochSeconds received_at;
  ContentStatus status{ContentStatus::active};

  [[nodiscard]] auto operator==(const MessageRecord &) const -> bool = default;
};

class Store;
class TransactionBackend;

// A transaction is bound to the Store that created it. The Store must outlive
// every active transaction. Transactions are move-only and roll back on
// destruction unless a commit or explicit rollback completed them.
class Transaction final {
public:
  ~Transaction() noexcept;

  Transaction(const Transaction &) = delete;
  auto operator=(const Transaction &) -> Transaction & = delete;
  Transaction(Transaction &&other) noexcept;
  auto operator=(Transaction &&other) noexcept -> Transaction &;

  [[nodiscard]] auto commit() -> std::expected<void, Error>;
  void rollback() noexcept;
  [[nodiscard]] auto active() const noexcept -> bool;
  [[nodiscard]] auto mode() const noexcept -> TransactionMode;

private:
  friend class Store;

  Transaction(const Store *owner, TransactionMode mode,
              std::unique_ptr<TransactionBackend> backend) noexcept;

  const Store *owner_{};
  TransactionMode mode_{TransactionMode::read_only};
  std::unique_ptr<TransactionBackend> backend_;
};

// Implementations keep backend-flavoured transaction state behind this seam.
// rollback() is noexcept because Transaction invokes it during stack unwinding.
class TransactionBackend {
public:
  virtual ~TransactionBackend() noexcept;

  [[nodiscard]] virtual auto commit() -> std::expected<void, Error> = 0;
  virtual void rollback() noexcept = 0;
};

class Store {
public:
  virtual ~Store() noexcept;

  [[nodiscard]] virtual auto begin(TransactionMode mode)
      -> std::expected<Transaction, Error> = 0;

  // Tombstoning is retry-safe: an existing tombstone succeeds, while a target
  // that never existed reports not_found. No content kind cascades or deletes
  // another row.
  [[nodiscard]] auto tombstone(Transaction &transaction,
                               const ContentRef &content)
      -> std::expected<void, Error>;

  // Ordinary board reads cannot request deleted content. The deliberately
  // verbose alternatives are reserved for moderation and audit views.
  [[nodiscard]] auto find_message(Transaction &transaction,
                                  std::string_view message_id)
      -> std::expected<std::optional<MessageRecord>, Error>;
  [[nodiscard]] auto list_messages_for_board(Transaction &transaction,
                                             std::string_view board_id)
      -> std::expected<std::vector<MessageRecord>, Error>;
  [[nodiscard]] auto
  find_message_including_tombstones(Transaction &transaction,
                                    std::string_view message_id)
      -> std::expected<std::optional<MessageRecord>, Error>;
  [[nodiscard]] auto
  list_messages_for_board_including_tombstones(Transaction &transaction,
                                               std::string_view board_id)
      -> std::expected<std::vector<MessageRecord>, Error>;

protected:
  // Store implementations use this factory so null backends fail as data,
  // rather than producing an apparently active transaction that later crashes.
  [[nodiscard]] auto
  make_transaction(TransactionMode mode,
                   std::unique_ptr<TransactionBackend> backend) const noexcept
      -> std::expected<Transaction, Error>;

  // Future domain operations can recover their own backend state only from an
  // active transaction created by the same Store. Foreign transactions fail
  // closed with nullptr.
  [[nodiscard]] auto
  transaction_backend(Transaction &transaction) const noexcept
      -> TransactionBackend *;

  enum class ContentVisibility {
    active_only,
    including_tombstones,
  };

  [[nodiscard]] virtual auto tombstone_impl(Transaction &transaction,
                                            const ContentRef &content)
      -> std::expected<void, Error> = 0;
  [[nodiscard]] virtual auto find_message_impl(Transaction &transaction,
                                               std::string_view message_id,
                                               ContentVisibility visibility)
      -> std::expected<std::optional<MessageRecord>, Error> = 0;
  [[nodiscard]] virtual auto
  list_messages_for_board_impl(Transaction &transaction,
                               std::string_view board_id,
                               ContentVisibility visibility)
      -> std::expected<std::vector<MessageRecord>, Error> = 0;
};

} // namespace anvil::store
