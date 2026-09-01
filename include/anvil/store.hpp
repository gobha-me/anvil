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

enum class UserStatus {
  pending,
  active,
  suspended,
  tombstoned,
};

// Revocation belongs to a credential rather than its user. Keeping it in the
// lookup result prevents a revoked key from becoming indistinguishable from a
// never-seen key and accidentally entering registration again.
enum class CredentialStatus {
  pending,
  active,
  suspended,
  tombstoned,
  revoked,
};

struct CredentialRecord {
  std::string handle;
  std::string fingerprint;
  std::string public_key;
  CredentialStatus status{CredentialStatus::pending};

  [[nodiscard]] auto operator==(const CredentialRecord &) const
      -> bool = default;
};

struct LocalCredentialProvision {
  std::string handle;
  std::string fingerprint;
  std::string public_key;
  UtcEpochSeconds created_at;
  UserStatus user_status{UserStatus::pending};

  [[nodiscard]] auto operator==(const LocalCredentialProvision &) const
      -> bool = default;
};

struct TosAcceptance {
  std::string user_handle;
  std::string tos_version;
  UtcEpochSeconds accepted_at;

  [[nodiscard]] auto operator==(const TosAcceptance &) const -> bool = default;
};

struct InviteClaim {
  std::string code_hash;
  std::string claimed_by_handle;
  UtcEpochSeconds claimed_at;

  [[nodiscard]] auto operator==(const InviteClaim &) const -> bool = default;
};

struct InviteIssue {
  std::string code_hash;
  std::string inviter_handle;
  UtcEpochSeconds created_at;
  UtcEpochSeconds expires_at;
  std::uint32_t balance_cap{5};
  std::uint32_t regeneration_seconds{2'592'000};

  [[nodiscard]] auto operator==(const InviteIssue &) const -> bool = default;
};

struct InviteIssueResult {
  std::uint32_t remaining_balance{};
  std::optional<UtcEpochSeconds> next_regeneration;

  [[nodiscard]] auto operator==(const InviteIssueResult &) const
      -> bool = default;
};

struct InviteUser {
  std::string handle;
  std::optional<std::string> origin;
  UserStatus status{UserStatus::pending};

  [[nodiscard]] auto operator==(const InviteUser &) const -> bool = default;
};

struct InviteDescendant {
  InviteUser user;
  std::uint32_t depth{};

  [[nodiscard]] auto operator==(const InviteDescendant &) const
      -> bool = default;
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

  // An absent result means the fingerprint has never been registered. A
  // revoked credential remains present with CredentialStatus::revoked.
  [[nodiscard]] auto find_local_credential(Transaction &transaction,
                                           std::string_view fingerprint)
      -> std::expected<std::optional<CredentialRecord>, Error>;

  // Provisioning is atomic. Pending registration requires a new handle and
  // fingerprint. Active bootstrap provisioning is idempotent for an exact
  // match and may add another key to an existing active local user, but never
  // changes existing status or credential ownership.
  [[nodiscard]] auto
  provision_local_credential(Transaction &transaction,
                             const LocalCredentialProvision &provision)
      -> std::expected<void, Error>;

  // TOS versions are opaque exact-match identifiers. Recording acceptance is
  // append-only and promotes a pending local account to active in the same
  // write transaction. Repeating the same acceptance is idempotent and keeps
  // the original timestamp.
  [[nodiscard]] auto has_tos_acceptance(Transaction &transaction,
                                        std::string_view user_handle,
                                        std::string_view tos_version)
      -> std::expected<bool, Error>;
  [[nodiscard]] auto accept_tos(Transaction &transaction,
                                const TosAcceptance &acceptance)
      -> std::expected<UserStatus, Error>;

  // Invite redemption participates in the caller's write transaction so a
  // pending account and its single-use invite become visible together. The
  // raw bearer code never reaches the storage boundary.
  [[nodiscard]] auto claim_invite(Transaction &transaction,
                                  const InviteClaim &claim)
      -> std::expected<void, Error>;

  // Issuance consumes and regenerates invite balance atomically. Only the
  // SHA-256 digest crosses this boundary; callers retain the raw bearer code
  // just long enough to display it once.
  [[nodiscard]] auto issue_invite(Transaction &transaction,
                                  const InviteIssue &issue)
      -> std::expected<InviteIssueResult, Error>;

  // These moderation-facing reads retain tombstoned identities. The subtree
  // excludes its root and is ordered by depth, handle, then origin.
  [[nodiscard]] auto find_inviter(Transaction &transaction,
                                  std::string_view invitee_handle)
      -> std::expected<std::optional<InviteUser>, Error>;
  [[nodiscard]] auto list_invite_subtree(Transaction &transaction,
                                         std::string_view root_handle)
      -> std::expected<std::vector<InviteDescendant>, Error>;

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
  [[nodiscard]] virtual auto
  find_local_credential_impl(Transaction &transaction,
                             std::string_view fingerprint)
      -> std::expected<std::optional<CredentialRecord>, Error> = 0;
  [[nodiscard]] virtual auto
  provision_local_credential_impl(Transaction &transaction,
                                  const LocalCredentialProvision &provision)
      -> std::expected<void, Error> = 0;
  [[nodiscard]] virtual auto has_tos_acceptance_impl(
      Transaction &transaction, std::string_view user_handle,
      std::string_view tos_version) -> std::expected<bool, Error> = 0;
  [[nodiscard]] virtual auto accept_tos_impl(Transaction &transaction,
                                             const TosAcceptance &acceptance)
      -> std::expected<UserStatus, Error> = 0;
  [[nodiscard]] virtual auto claim_invite_impl(Transaction &transaction,
                                               const InviteClaim &claim)
      -> std::expected<void, Error> = 0;
  [[nodiscard]] virtual auto issue_invite_impl(Transaction &transaction,
                                               const InviteIssue &issue)
      -> std::expected<InviteIssueResult, Error> = 0;
  [[nodiscard]] virtual auto find_inviter_impl(Transaction &transaction,
                                               std::string_view invitee_handle)
      -> std::expected<std::optional<InviteUser>, Error> = 0;
  [[nodiscard]] virtual auto
  list_invite_subtree_impl(Transaction &transaction,
                           std::string_view root_handle)
      -> std::expected<std::vector<InviteDescendant>, Error> = 0;
};

} // namespace anvil::store
