#include <anvil/store.hpp>
#include <cstddef>
#include <limits>
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

[[nodiscard]] auto valid_fingerprint(std::string_view fingerprint) -> bool {
  return fingerprint.starts_with("SHA256:") && fingerprint.size() > 7 &&
         fingerprint.size() <= 128 &&
         fingerprint.find('\0') == std::string_view::npos;
}

[[nodiscard]] auto valid_handle(std::string_view handle) -> bool {
  if (handle.empty() || handle.size() > 32) {
    return false;
  }
  for (const auto value : handle) {
    if (!((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
          (value >= '0' && value <= '9') || value == '_' || value == '-')) {
      return false;
    }
  }
  constexpr std::string_view guest = "guest";
  if (handle.size() != guest.size()) {
    return true;
  }
  for (std::size_t index = 0; index < handle.size(); ++index) {
    auto value = handle[index];
    if (value >= 'A' && value <= 'Z') {
      value = static_cast<char>(value - 'A' + 'a');
    }
    if (value != guest[index]) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] auto validate_provision(const LocalCredentialProvision &provision)
    -> std::expected<void, Error> {
  if (!valid_handle(provision.handle)) {
    return std::unexpected(invalid_identifier(
        "local handle violates the M1 handle grammar or is reserved"));
  }
  if (!valid_fingerprint(provision.fingerprint)) {
    return std::unexpected(
        invalid_identifier("credential fingerprint is not canonical SHA256"));
  }
  if (provision.public_key.empty() || provision.public_key.size() > 65'536 ||
      provision.public_key.find('\0') != std::string::npos) {
    return std::unexpected(invalid_identifier(
        "credential public key must contain 1 to 65536 bytes and no NUL"));
  }
  if (provision.user_status != UserStatus::pending &&
      provision.user_status != UserStatus::active) {
    return std::unexpected(invalid_identifier(
        "new local credential requires pending or active user status"));
  }
  return {};
}

[[nodiscard]] constexpr auto is_utf8_continuation(unsigned char value) -> bool {
  return value >= 0x80U && value <= 0xbfU;
}

[[nodiscard]] auto valid_two_byte_sequence(std::string_view input,
                                           std::size_t offset) -> bool {
  if (offset + 1U >= input.size()) {
    return false;
  }
  const auto first = static_cast<unsigned char>(input[offset]);
  const auto second = static_cast<unsigned char>(input[offset + 1U]);
  return is_utf8_continuation(second) && (first != 0xc2U || second > 0x9fU);
}

[[nodiscard]] auto valid_three_byte_sequence(std::string_view input,
                                             std::size_t offset) -> bool {
  if (offset + 2U >= input.size()) {
    return false;
  }
  const auto first = static_cast<unsigned char>(input[offset]);
  const auto second = static_cast<unsigned char>(input[offset + 1U]);
  const auto third = static_cast<unsigned char>(input[offset + 2U]);
  return is_utf8_continuation(second) && is_utf8_continuation(third) &&
         (first != 0xe0U || second >= 0xa0U) &&
         (first != 0xedU || second <= 0x9fU);
}

[[nodiscard]] auto valid_four_byte_sequence(std::string_view input,
                                            std::size_t offset) -> bool {
  if (offset + 3U >= input.size()) {
    return false;
  }
  const auto first = static_cast<unsigned char>(input[offset]);
  const auto second = static_cast<unsigned char>(input[offset + 1U]);
  const auto third = static_cast<unsigned char>(input[offset + 2U]);
  const auto fourth = static_cast<unsigned char>(input[offset + 3U]);
  return is_utf8_continuation(second) && is_utf8_continuation(third) &&
         is_utf8_continuation(fourth) && (first != 0xf0U || second >= 0x90U) &&
         (first != 0xf4U || second <= 0x8fU);
}

[[nodiscard]] auto tos_sequence_width(std::string_view input,
                                      std::size_t offset) -> std::size_t {
  const auto first = static_cast<unsigned char>(input[offset]);
  if (first <= 0x7fU) {
    return first >= 0x20U && first != 0x7fU ? 1U : 0U;
  }
  if (first >= 0xc2U && first <= 0xdfU) {
    return valid_two_byte_sequence(input, offset) ? 2U : 0U;
  }
  if (first >= 0xe0U && first <= 0xefU) {
    return valid_three_byte_sequence(input, offset) ? 3U : 0U;
  }
  if (first >= 0xf0U && first <= 0xf4U) {
    return valid_four_byte_sequence(input, offset) ? 4U : 0U;
  }
  return 0U;
}

[[nodiscard]] auto valid_tos_version(std::string_view version) -> bool {
  if (!valid_opaque_identifier(version, 128)) {
    return false;
  }
  for (std::size_t offset = 0; offset < version.size();) {
    const auto width = tos_sequence_width(version, offset);
    if (width == 0U) {
      return false;
    }
    offset += width;
  }
  return true;
}

[[nodiscard]] auto validate_tos_identity(std::string_view handle,
                                         std::string_view version)
    -> std::expected<void, Error> {
  if (!valid_handle(handle)) {
    return std::unexpected(invalid_identifier(
        "TOS user violates the M1 handle grammar or is reserved"));
  }
  if (!valid_tos_version(version)) {
    return std::unexpected(invalid_identifier(
        "TOS version must contain 1 to 128 bytes of valid UTF-8 and no "
        "controls"));
  }
  return {};
}

[[nodiscard]] auto valid_sha256_hex(std::string_view value) -> bool {
  if (value.size() != 64) {
    return false;
  }
  for (const auto character : value) {
    if (!((character >= '0' && character <= '9') ||
          (character >= 'a' && character <= 'f'))) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] auto validate_invite_claim(const InviteClaim &claim)
    -> std::expected<void, Error> {
  if (!valid_sha256_hex(claim.code_hash)) {
    return std::unexpected(invalid_identifier(
        "invite code hash must be lowercase hexadecimal SHA256"));
  }
  if (!valid_handle(claim.claimed_by_handle)) {
    return std::unexpected(invalid_identifier(
        "invite claimant violates the M1 handle grammar or is reserved"));
  }
  return {};
}

[[nodiscard]] auto validate_invite_issue(const InviteIssue &issue)
    -> std::expected<void, Error> {
  if (!valid_sha256_hex(issue.code_hash)) {
    return std::unexpected(invalid_identifier(
        "invite code hash must be lowercase hexadecimal SHA256"));
  }
  if (!valid_handle(issue.inviter_handle)) {
    return std::unexpected(invalid_identifier(
        "invite issuer violates the M1 handle grammar or is reserved"));
  }
  if (issue.balance_cap > 1'000'000U) {
    return std::unexpected(
        invalid_identifier("invite balance cap exceeds 1000000"));
  }
  if (issue.regeneration_seconds == 0U) {
    return std::unexpected(
        invalid_identifier("invite regeneration period must be positive"));
  }
  if (issue.expires_at <= issue.created_at) {
    return std::unexpected(
        invalid_identifier("invite expiry must be after creation"));
  }
  if (issue.created_at.value >
      std::numeric_limits<std::int64_t>::max() -
          static_cast<std::int64_t>(issue.regeneration_seconds)) {
    return std::unexpected(
        invalid_identifier("invite regeneration time would overflow"));
  }
  return {};
}

[[nodiscard]] auto valid_board_name(std::string_view name) -> bool {
  if (name.empty() || name.size() > 64U ||
      !((name.front() >= 'a' && name.front() <= 'z') ||
        (name.front() >= '0' && name.front() <= '9'))) {
    return false;
  }
  for (const auto value : name) {
    if (!((value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') ||
          value == '_' || value == '-')) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] auto valid_text(std::string_view value, std::size_t maximum,
                              bool allow_empty = false) -> bool {
  return (allow_empty || !value.empty()) && value.size() <= maximum &&
         value.find('\0') == std::string_view::npos;
}

[[nodiscard]] auto validate_reader(const BoardReader &reader)
    -> std::expected<void, Error> {
  if (reader.handle && !valid_handle(*reader.handle)) {
    return std::unexpected(
        invalid_identifier("board reader handle is invalid"));
  }
  return {};
}

[[nodiscard]] auto validate_board_provision(const BoardProvision &board)
    -> std::expected<void, Error> {
  if (!valid_board_identifier(board.board_id)) {
    return std::unexpected(
        invalid_identifier("board identifier is not a canonical UUID"));
  }
  if (!valid_board_name(board.name)) {
    return std::unexpected(invalid_identifier(
        "board name must be a 1 to 64 byte lowercase ASCII slug"));
  }
  if (!valid_text(board.title, 3'840U)) {
    return std::unexpected(
        invalid_identifier("board title is empty or exceeds its byte limit"));
  }
  return {};
}

[[nodiscard]] auto validate_thread_create(const ThreadCreate &thread)
    -> std::expected<void, Error> {
  if (!valid_board_identifier(thread.board_id) ||
      !valid_opaque_identifier(thread.thread_id, 128U) ||
      !valid_opaque_identifier(thread.message_id, 128U) ||
      !valid_handle(thread.author_handle) ||
      !valid_text(thread.subject, 3'840U) ||
      !valid_text(thread.body, 524'288U)) {
    return std::unexpected(
        invalid_identifier("thread creation contains invalid bounded data"));
  }
  return {};
}

[[nodiscard]] auto validate_reply_create(const ReplyCreate &reply)
    -> std::expected<void, Error> {
  if (!valid_board_identifier(reply.board_id) ||
      !valid_opaque_identifier(reply.thread_id, 128U) ||
      !valid_opaque_identifier(reply.message_id, 128U) ||
      (reply.parent_message_id &&
       !valid_opaque_identifier(*reply.parent_message_id, 128U)) ||
      !valid_handle(reply.author_handle) || !valid_text(reply.body, 524'288U)) {
    return std::unexpected(
        invalid_identifier("reply creation contains invalid bounded data"));
  }
  return {};
}

[[nodiscard]] auto validate_report(const ReportSubmission &report)
    -> std::expected<void, Error> {
  if (!valid_opaque_identifier(report.report_id, 128U) ||
      (report.reporter_handle && !valid_handle(*report.reporter_handle)) ||
      (report.target.kind != ContentKind::thread &&
       report.target.kind != ContentKind::message &&
       report.target.kind != ContentKind::oneliner) ||
      !valid_text(report.reason, 32'768U)) {
    return std::unexpected(
        invalid_identifier("report contains invalid bounded data"));
  }
  return validate_content_ref(report.target);
}

[[nodiscard]] auto validate_oneliner_policy(const OnelinerPolicy &policy)
    -> std::expected<void, Error> {
  if (policy.max_posts == 0U || policy.window_seconds == 0U ||
      policy.retention_seconds == 0U) {
    return std::unexpected(Error{ErrorCode::invalid_data,
                                 "one-liner policy values must be positive"});
  }
  return {};
}

[[nodiscard]] auto validate_oneliner_create(const OnelinerCreate &oneliner)
    -> std::expected<void, Error> {
  if (!valid_opaque_identifier(oneliner.oneliner_id, 128U) ||
      !valid_handle(oneliner.author_handle) || oneliner.body.empty() ||
      !valid_text(oneliner.body, 8'960U) ||
      oneliner.body.find_first_of("\r\n") != std::string::npos) {
    return std::unexpected(
        invalid_identifier("one-liner contains invalid bounded data"));
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

auto Store::find_local_credential(Transaction &transaction,
                                  std::string_view fingerprint)
    -> std::expected<std::optional<CredentialRecord>, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (!valid_fingerprint(fingerprint)) {
    return std::unexpected(
        invalid_identifier("credential fingerprint is not canonical SHA256"));
  }
  return find_local_credential_impl(transaction, fingerprint);
}

auto Store::provision_local_credential(
    Transaction &transaction, const LocalCredentialProvision &provision)
    -> std::expected<void, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(
        Error{ErrorCode::invalid_state,
              "credential provisioning requires a write transaction"});
  }
  if (auto valid = validate_provision(provision); !valid) {
    return std::unexpected(valid.error());
  }
  return provision_local_credential_impl(transaction, provision);
}

auto Store::has_tos_acceptance(Transaction &transaction,
                               std::string_view user_handle,
                               std::string_view tos_version)
    -> std::expected<bool, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (auto valid = validate_tos_identity(user_handle, tos_version); !valid) {
    return std::unexpected(valid.error());
  }
  return has_tos_acceptance_impl(transaction, user_handle, tos_version);
}

auto Store::accept_tos(Transaction &transaction,
                       const TosAcceptance &acceptance)
    -> std::expected<UserStatus, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(
        Error{ErrorCode::invalid_state,
              "TOS acceptance requires a write transaction"});
  }
  if (auto valid =
          validate_tos_identity(acceptance.user_handle, acceptance.tos_version);
      !valid) {
    return std::unexpected(valid.error());
  }
  return accept_tos_impl(transaction, acceptance);
}

auto Store::claim_invite(Transaction &transaction, const InviteClaim &claim)
    -> std::expected<void, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(Error{ErrorCode::invalid_state,
                                 "invite claim requires a write transaction"});
  }
  if (auto valid = validate_invite_claim(claim); !valid) {
    return std::unexpected(valid.error());
  }
  return claim_invite_impl(transaction, claim);
}

auto Store::issue_invite(Transaction &transaction, const InviteIssue &issue)
    -> std::expected<InviteIssueResult, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(
        Error{ErrorCode::invalid_state,
              "invite issuance requires a write transaction"});
  }
  if (auto valid = validate_invite_issue(issue); !valid) {
    return std::unexpected(valid.error());
  }
  return issue_invite_impl(transaction, issue);
}

auto Store::find_inviter(Transaction &transaction,
                         std::string_view invitee_handle)
    -> std::expected<std::optional<InviteUser>, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (!valid_handle(invitee_handle)) {
    return std::unexpected(invalid_identifier(
        "invitee violates the M1 handle grammar or is reserved"));
  }
  return find_inviter_impl(transaction, invitee_handle);
}

auto Store::list_invite_subtree(Transaction &transaction,
                                std::string_view root_handle)
    -> std::expected<std::vector<InviteDescendant>, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (!valid_handle(root_handle)) {
    return std::unexpected(invalid_identifier(
        "invite subtree root violates the M1 handle grammar or is reserved"));
  }
  return list_invite_subtree_impl(transaction, root_handle);
}

auto Store::reconcile_board(Transaction &transaction,
                            const BoardProvision &board)
    -> std::expected<BoardRecord, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(
        Error{ErrorCode::invalid_state,
              "board reconciliation requires a write transaction"});
  }
  if (auto valid = validate_board_provision(board); !valid) {
    return std::unexpected(valid.error());
  }
  return reconcile_board_impl(transaction, board);
}

auto Store::list_boards(Transaction &transaction, const BoardReader &reader)
    -> std::expected<std::vector<BoardRecord>, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (auto valid = validate_reader(reader); !valid) {
    return std::unexpected(valid.error());
  }
  return list_boards_impl(transaction, reader);
}

auto Store::list_threads(Transaction &transaction, std::string_view board_id,
                         const BoardReader &reader)
    -> std::expected<std::vector<ThreadRecord>, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (!valid_board_identifier(board_id)) {
    return std::unexpected(invalid_identifier("board identifier is invalid"));
  }
  if (auto valid = validate_reader(reader); !valid) {
    return std::unexpected(valid.error());
  }
  return list_threads_impl(transaction, board_id, reader);
}

auto Store::list_messages_for_thread(Transaction &transaction,
                                     std::string_view board_id,
                                     std::string_view thread_id,
                                     const BoardReader &reader)
    -> std::expected<std::vector<MessageRecord>, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (!valid_board_identifier(board_id) ||
      !valid_opaque_identifier(thread_id, 128U)) {
    return std::unexpected(
        invalid_identifier("board or thread identifier is invalid"));
  }
  if (auto valid = validate_reader(reader); !valid) {
    return std::unexpected(valid.error());
  }
  return list_messages_for_thread_impl(transaction, board_id, thread_id,
                                       reader);
}

auto Store::create_thread(Transaction &transaction, const ThreadCreate &thread)
    -> std::expected<MessageRecord, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(
        Error{ErrorCode::invalid_state,
              "thread creation requires a write transaction"});
  }
  if (auto valid = validate_thread_create(thread); !valid) {
    return std::unexpected(valid.error());
  }
  return create_thread_impl(transaction, thread);
}

auto Store::create_reply(Transaction &transaction, const ReplyCreate &reply)
    -> std::expected<MessageRecord, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(
        Error{ErrorCode::invalid_state,
              "reply creation requires a write transaction"});
  }
  if (auto valid = validate_reply_create(reply); !valid) {
    return std::unexpected(valid.error());
  }
  return create_reply_impl(transaction, reply);
}

auto Store::mark_thread_read(Transaction &transaction,
                             std::string_view user_handle,
                             std::string_view board_id,
                             std::string_view thread_id)
    -> std::expected<void, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(Error{ErrorCode::invalid_state,
                                 "read markers require a write transaction"});
  }
  if (!valid_handle(user_handle) || !valid_board_identifier(board_id) ||
      !valid_opaque_identifier(thread_id, 128U)) {
    return std::unexpected(
        invalid_identifier("read marker identity is invalid"));
  }
  return mark_thread_read_impl(transaction, user_handle, board_id, thread_id);
}

auto Store::catch_up_board(Transaction &transaction,
                           std::string_view user_handle,
                           std::string_view board_id)
    -> std::expected<void, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(
        Error{ErrorCode::invalid_state,
              "board catch-up requires a write transaction"});
  }
  if (!valid_handle(user_handle) || !valid_board_identifier(board_id)) {
    return std::unexpected(
        invalid_identifier("board catch-up identity is invalid"));
  }
  return catch_up_board_impl(transaction, user_handle, board_id);
}

auto Store::submit_report(Transaction &transaction,
                          const ReportSubmission &report)
    -> std::expected<void, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(
        Error{ErrorCode::invalid_state,
              "report submission requires a write transaction"});
  }
  if (auto valid = validate_report(report); !valid) {
    return std::unexpected(valid.error());
  }
  return submit_report_impl(transaction, report);
}

auto Store::create_oneliner(Transaction &transaction,
                            const OnelinerCreate &oneliner,
                            const OnelinerPolicy &policy)
    -> std::expected<OnelinerRecord, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(Error{ErrorCode::invalid_state,
                                 "one-liner creation requires a write "
                                 "transaction"});
  }
  if (auto valid = validate_oneliner_create(oneliner); !valid) {
    return std::unexpected(valid.error());
  }
  if (auto valid = validate_oneliner_policy(policy); !valid) {
    return std::unexpected(valid.error());
  }
  return create_oneliner_impl(transaction, oneliner, policy);
}

auto Store::list_oneliners(Transaction &transaction, UtcEpochSeconds now,
                           const OnelinerPolicy &policy, std::uint32_t limit)
    -> std::expected<std::vector<OnelinerRecord>, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (auto valid = validate_oneliner_policy(policy); !valid) {
    return std::unexpected(valid.error());
  }
  if (limit == 0U || limit > 100U) {
    return std::unexpected(Error{ErrorCode::invalid_data,
                                 "one-liner list limit must be 1 through 100"});
  }
  return list_oneliners_impl(transaction, now, policy, limit);
}

auto Store::purge_expired_oneliners(Transaction &transaction,
                                    UtcEpochSeconds now,
                                    const OnelinerPolicy &policy)
    -> std::expected<std::uint64_t, Error> {
  if (transaction_backend(transaction) == nullptr) {
    return std::unexpected(inactive_transaction_error());
  }
  if (transaction.mode() != TransactionMode::read_write) {
    return std::unexpected(
        Error{ErrorCode::invalid_state,
              "one-liner purge requires a write transaction"});
  }
  if (auto valid = validate_oneliner_policy(policy); !valid) {
    return std::unexpected(valid.error());
  }
  return purge_expired_oneliners_impl(transaction, now, policy);
}

} // namespace anvil::store
