#include <anvil/store.hpp>

#include <utility>

namespace anvil::store {

namespace {

[[nodiscard]] auto inactive_transaction_error() -> Error {
  return {ErrorCode::invalid_state, "transaction is no longer active"};
}

} // namespace

Transaction::Transaction(const Store *owner,
                         std::unique_ptr<TransactionBackend> backend) noexcept
    : owner_(owner), backend_(std::move(backend)) {}

Transaction::~Transaction() noexcept { rollback(); }

Transaction::Transaction(Transaction &&other) noexcept
    : owner_(std::exchange(other.owner_, nullptr)),
      backend_(std::move(other.backend_)) {}

auto Transaction::operator=(Transaction &&other) noexcept -> Transaction & {
  if (this == &other) {
    return *this;
  }
  rollback();
  owner_ = std::exchange(other.owner_, nullptr);
  backend_ = std::move(other.backend_);
  return *this;
}

auto Transaction::commit() -> std::expected<void, Error> {
  if (!active()) {
    return std::unexpected(inactive_transaction_error());
  }

  auto result = backend_->commit();
  if (result) {
    backend_.reset();
    owner_ = nullptr;
  }
  return result;
}

void Transaction::rollback() noexcept {
  if (backend_) {
    backend_->rollback();
    backend_.reset();
  }
  owner_ = nullptr;
}

auto Transaction::active() const noexcept -> bool {
  return backend_ != nullptr;
}

TransactionBackend::~TransactionBackend() noexcept = default;

Store::~Store() noexcept = default;

auto Store::make_transaction(std::unique_ptr<TransactionBackend> backend)
    const noexcept -> std::expected<Transaction, Error> {
  if (!backend) {
    return std::unexpected(Error{ErrorCode::internal,
                                 "store returned a null transaction backend"});
  }
  return Transaction{this, std::move(backend)};
}

auto Store::transaction_backend(Transaction &transaction) const noexcept
    -> TransactionBackend * {
  if (transaction.owner_ != this) {
    return nullptr;
  }
  return transaction.backend_.get();
}

} // namespace anvil::store
