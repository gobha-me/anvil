#include <anvil/store.hpp>

#include <cstddef>
#include <utility>

namespace anvil::store {

namespace {

[[nodiscard]] auto inactive_transaction_error() -> Error {
  return {ErrorCode::invalid_state, "transaction is no longer active"};
}

[[nodiscard]] auto invalid_identifier(std::string detail) -> Error {
  return {ErrorCode::invalid_data, std::move(detail)};
}

[[nodiscard]] auto valid_opaque_identifier(std::string_view identifier,
                                           std::size_t maximum) -> bool {
  return !identifier.empty() && identifier.size() <= maximum &&
         identifier.find('\0') == std::string_view::npos;
}

[[nodiscard]] auto valid_board_identifier(std::string_view identifier) -> bool {
  if (identifier.size() != 36 || identifier[8] != '-' ||
      identifier[13] != '-' || identifier[18] != '-' || identifier[23] != '-') {
    return false;
  }
  for (std::size_t index = 0; index < identifier.size(); ++index) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      continue;
    }
    const auto value = identifier[index];
    if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] auto validate_content_ref(const ContentRef &content)
    -> std::expected<void, Error> {
  if (content.kind == ContentKind::block) {
    const auto *identifier = std::get_if<std::int64_t>(&content.id);
    if (identifier == nullptr || *identifier <= 0) {
      return std::unexpected(invalid_identifier(
          "block content requires a positive integer identifier"));
    }
    return {};
  }

  const auto *identifier = std::get_if<std::string>(&content.id);
  if (identifier == nullptr) {
    return std::unexpected(
        invalid_identifier("content kind requires a string identifier"));
  }
  switch (content.kind) {
  case ContentKind::board:
    if (!valid_board_identifier(*identifier)) {
      return std::unexpected(
          invalid_identifier("board identifier is not a canonical UUID"));
    }
    return {};
  case ContentKind::thread:
  case ContentKind::message:
  case ContentKind::file:
  case ContentKind::leaderboard_entry:
  case ContentKind::oneliner:
  case ContentKind::report:
    if (!valid_opaque_identifier(*identifier, 128)) {
      return std::unexpected(invalid_identifier(
          "content identifier must contain 1 to 128 bytes and no NUL"));
    }
    return {};
  case ContentKind::block:
    break;
  }
  return std::unexpected(invalid_identifier("unknown content kind"));
}

[[nodiscard]] auto validate_message_identifier(std::string_view identifier,
                                               std::string_view name,
                                               bool board)
    -> std::expected<void, Error> {
  const auto valid = board ? valid_board_identifier(identifier)
                           : valid_opaque_identifier(identifier, 128);
  if (!valid) {
    return std::unexpected(
        invalid_identifier(std::string(name) + " is not a valid identifier"));
  }
  return {};
}

} // namespace

Transaction::Transaction(const Store *owner, TransactionMode mode,
                         std::unique_ptr<TransactionBackend> backend) noexcept
    : owner_(owner), mode_(mode), backend_(std::move(backend)) {}

Transaction::~Transaction() noexcept { rollback(); }

Transaction::Transaction(Transaction &&other) noexcept
    : owner_(std::exchange(other.owner_, nullptr)), mode_(other.mode_),
      backend_(std::move(other.backend_)) {}

auto Transaction::operator=(Transaction &&other) noexcept -> Transaction & {
  if (this == &other) {
    return *this;
  }
  rollback();
  owner_ = std::exchange(other.owner_, nullptr);
  mode_ = other.mode_;
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

auto Transaction::mode() const noexcept -> TransactionMode { return mode_; }

TransactionBackend::~TransactionBackend() noexcept = default;

Store::~Store() noexcept = default;

auto Store::make_transaction(TransactionMode mode,
                             std::unique_ptr<TransactionBackend> backend)
    const noexcept -> std::expected<Transaction, Error> {
  if (!backend) {
    return std::unexpected(Error{ErrorCode::internal,
                                 "store returned a null transaction backend"});
  }
  return Transaction{this, mode, std::move(backend)};
}

auto Store::transaction_backend(Transaction &transaction) const noexcept
    -> TransactionBackend * {
  if (transaction.owner_ != this) {
    return nullptr;
  }
  return transaction.backend_.get();
}

auto Store::tombstone(Transaction &transaction, const ContentRef &content)
    -> std::expected<void, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(Error{ErrorCode::invalid_state,
                                 "tombstoning requires a write transaction"});
  }
  if (auto valid = validate_content_ref(content); !valid) {
    return std::unexpected(valid.error());
  }
  return tombstone_impl(transaction, content);
}

auto Store::find_message(Transaction &transaction, std::string_view message_id)
    -> std::expected<std::optional<MessageRecord>, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (auto valid =
          validate_message_identifier(message_id, "message identifier", false);
      !valid) {
    return std::unexpected(valid.error());
  }
  return find_message_impl(transaction, message_id,
                           ContentVisibility::active_only);
}

auto Store::list_messages_for_board(Transaction &transaction,
                                    std::string_view board_id)
    -> std::expected<std::vector<MessageRecord>, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (auto valid =
          validate_message_identifier(board_id, "board identifier", true);
      !valid) {
    return std::unexpected(valid.error());
  }
  return list_messages_for_board_impl(transaction, board_id,
                                      ContentVisibility::active_only);
}

auto Store::find_message_including_tombstones(Transaction &transaction,
                                              std::string_view message_id)
    -> std::expected<std::optional<MessageRecord>, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (auto valid =
          validate_message_identifier(message_id, "message identifier", false);
      !valid) {
    return std::unexpected(valid.error());
  }
  return find_message_impl(transaction, message_id,
                           ContentVisibility::including_tombstones);
}

auto Store::list_messages_for_board_including_tombstones(
    Transaction &transaction, std::string_view board_id)
    -> std::expected<std::vector<MessageRecord>, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (auto valid =
          validate_message_identifier(board_id, "board identifier", true);
      !valid) {
    return std::unexpected(valid.error());
  }
  return list_messages_for_board_impl(transaction, board_id,
                                      ContentVisibility::including_tombstones);
}

} // namespace anvil::store
