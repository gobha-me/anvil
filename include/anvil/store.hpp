#pragma once

#include <compare>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>

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

private:
  friend class Store;

  Transaction(const Store *owner,
              std::unique_ptr<TransactionBackend> backend) noexcept;

  const Store *owner_{};
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

protected:
  // Store implementations use this factory so null backends fail as data,
  // rather than producing an apparently active transaction that later crashes.
  [[nodiscard]] auto
  make_transaction(std::unique_ptr<TransactionBackend> backend) const noexcept
      -> std::expected<Transaction, Error>;

  // Future domain operations can recover their own backend state only from an
  // active transaction created by the same Store. Foreign transactions fail
  // closed with nullptr.
  [[nodiscard]] auto
  transaction_backend(Transaction &transaction) const noexcept
      -> TransactionBackend *;
};

} // namespace anvil::store
