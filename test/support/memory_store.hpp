#pragma once

#include <algorithm>
#include <anvil/store.hpp>
#include <cstddef>
#include <expected>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace anvil::testing {

struct TransactionObservation {
  store::TransactionMode mode{store::TransactionMode::read_only};
  std::size_t commit_attempts{};
  std::size_t rollbacks{};
};

// Reusable database-free Store implementation for board, moderation, and door
// tests. Each transaction owns a snapshot so rollback and failed commits have
// the same observable semantics as a database backend.
class MemoryStore final : public store::Store {
public:
  MemoryStore() : state_(std::make_shared<State>()) {}

  [[nodiscard]] auto begin(store::TransactionMode mode)
      -> std::expected<store::Transaction, store::Error> override {
    if (next_begin_error_) {
      auto error = std::move(*next_begin_error_);
      next_begin_error_.reset();
      return std::unexpected(std::move(error));
    }

    const auto index = state_->observations.size();
    state_->observations.push_back({.mode = mode});
    return make_transaction(mode,
                            std::make_unique<Backend>(state_, index, mode));
  }

  void fail_next_begin(store::Error error) {
    next_begin_error_ = std::move(error);
  }

  void fail_next_commit(store::Error error) {
    state_->next_commit_error = std::move(error);
  }

  void
  seed_content(store::ContentRef content,
               store::ContentStatus status = store::ContentStatus::active) {
    upsert_content(state_->contents, std::move(content), status);
  }

  void seed_message(store::MessageRecord message) {
    const auto found = std::ranges::find(state_->messages, message.message_id,
                                         &store::MessageRecord::message_id);
    if (found == state_->messages.end()) {
      state_->messages.push_back(message);
    } else {
      *found = message;
    }
    upsert_content(state_->contents,
                   {store::ContentKind::board, message.board_id},
                   store::ContentStatus::active, false);
    upsert_content(state_->contents,
                   {store::ContentKind::thread, message.thread_id},
                   store::ContentStatus::active, false);
    upsert_content(state_->contents,
                   {store::ContentKind::message, message.message_id},
                   message.status);
  }

  void seed_credential(store::CredentialRecord credential) {
    const auto existing =
        std::ranges::find(state_->credentials, credential.fingerprint,
                          &store::CredentialRecord::fingerprint);
    if (existing == state_->credentials.end()) {
      state_->credentials.push_back(credential);
    } else {
      *existing = credential;
    }
    const auto status =
        credential.status == store::CredentialStatus::active
            ? store::UserStatus::active
        : credential.status == store::CredentialStatus::pending
            ? store::UserStatus::pending
        : credential.status == store::CredentialStatus::suspended
            ? store::UserStatus::suspended
            : store::UserStatus::tombstoned;
    const auto user =
        std::ranges::find(state_->users, credential.handle, &UserEntry::handle);
    if (user == state_->users.end()) {
      state_->users.push_back({.handle = credential.handle,
                               .status = status,
                               .invite_balance = 0,
                               .next_regeneration = std::nullopt});
    } else if (credential.status != store::CredentialStatus::revoked) {
      user->status = status;
    }
  }

  void seed_invite(std::string code_hash, bool active = true) {
    const auto existing =
        std::ranges::find(state_->invites, code_hash, &InviteEntry::code_hash);
    if (existing == state_->invites.end()) {
      state_->invites.push_back(
          {.code_hash = std::move(code_hash),
           .inviter_handle = "operator",
           .claimed_by_handle = {},
           .claimed_at = std::nullopt,
           .expires_at = {std::numeric_limits<std::int64_t>::max()},
           .active = active});
    } else {
      existing->active = active;
      existing->claimed_by_handle.clear();
      existing->claimed_at.reset();
    }
  }

  [[nodiscard]] auto invite_claimant(std::string_view code_hash) const
      -> std::optional<std::string> {
    const auto invite =
        std::ranges::find(state_->invites, code_hash, &InviteEntry::code_hash);
    if (invite == state_->invites.end() || invite->claimed_by_handle.empty()) {
      return std::nullopt;
    }
    return invite->claimed_by_handle;
  }

  [[nodiscard]] auto content_status(const store::ContentRef &content) const
      -> std::optional<store::ContentStatus> {
    return status_of(state_->contents, content);
  }

  [[nodiscard]] auto observations() const noexcept
      -> const std::vector<TransactionObservation> & {
    return state_->observations;
  }

  [[nodiscard]] auto owns(store::Transaction &transaction) const noexcept
      -> bool {
    return transaction_backend(transaction) != nullptr;
  }

  [[nodiscard]] auto begin_with_null_backend()
      -> std::expected<store::Transaction, store::Error> {
    return make_transaction(store::TransactionMode::read_only, nullptr);
  }

private:
  struct ContentEntry {
    store::ContentRef content;
    store::ContentStatus status{store::ContentStatus::active};
  };

  struct UserEntry {
    std::string handle;
    store::UserStatus status{store::UserStatus::pending};
    std::uint32_t invite_balance{};
    std::optional<store::UtcEpochSeconds> next_regeneration;
  };

  struct InviteEntry {
    std::string code_hash;
    std::string inviter_handle;
    std::string claimed_by_handle;
    std::optional<store::UtcEpochSeconds> claimed_at;
    store::UtcEpochSeconds expires_at;
    bool active{true};
  };

  struct State {
    std::vector<TransactionObservation> observations;
    std::optional<store::Error> next_commit_error;
    std::vector<ContentEntry> contents;
    std::vector<store::MessageRecord> messages;
    std::vector<UserEntry> users;
    std::vector<store::CredentialRecord> credentials;
    std::vector<InviteEntry> invites;
  };

  static void upsert_content(std::vector<ContentEntry> &contents,
                             store::ContentRef content,
                             store::ContentStatus status,
                             bool replace_existing = true) {
    const auto found = std::ranges::find(
        contents, content,
        [](const ContentEntry &entry) -> const store::ContentRef & {
          return entry.content;
        });
    if (found == contents.end()) {
      contents.push_back({std::move(content), status});
    } else if (replace_existing) {
      found->status = status;
    }
  }

  [[nodiscard]] static auto status_of(const std::vector<ContentEntry> &contents,
                                      const store::ContentRef &content)
      -> std::optional<store::ContentStatus> {
    const auto found = std::ranges::find(
        contents, content,
        [](const ContentEntry &entry) -> const store::ContentRef & {
          return entry.content;
        });
    if (found == contents.end()) {
      return std::nullopt;
    }
    return found->status;
  }

  class Backend final : public store::TransactionBackend {
  public:
    Backend(std::shared_ptr<State> state, std::size_t index,
            store::TransactionMode mode)
        : state_(std::move(state)), index_(index), mode_(mode),
          contents_(state_->contents), messages_(state_->messages),
          users_(state_->users), credentials_(state_->credentials),
          invites_(state_->invites) {}

    [[nodiscard]] auto commit() -> std::expected<void, store::Error> override {
      ++state_->observations.at(index_).commit_attempts;
      if (state_->next_commit_error) {
        auto error = std::move(*state_->next_commit_error);
        state_->next_commit_error.reset();
        return std::unexpected(std::move(error));
      }
      if (mode_ == store::TransactionMode::read_write) {
        state_->contents = contents_;
        state_->messages = messages_;
        state_->users = users_;
        state_->credentials = credentials_;
        state_->invites = invites_;
      }
      return {};
    }

    void rollback() noexcept override {
      ++state_->observations[index_].rollbacks;
    }

    [[nodiscard]] auto contents() noexcept -> std::vector<ContentEntry> & {
      return contents_;
    }

    [[nodiscard]] auto contents() const noexcept
        -> const std::vector<ContentEntry> & {
      return contents_;
    }

    [[nodiscard]] auto messages() noexcept
        -> std::vector<store::MessageRecord> & {
      return messages_;
    }

    [[nodiscard]] auto users() noexcept -> std::vector<UserEntry> & {
      return users_;
    }

    [[nodiscard]] auto credentials() noexcept
        -> std::vector<store::CredentialRecord> & {
      return credentials_;
    }

    [[nodiscard]] auto invites() noexcept -> std::vector<InviteEntry> & {
      return invites_;
    }

  private:
    std::shared_ptr<State> state_;
    std::size_t index_;
    store::TransactionMode mode_;
    std::vector<ContentEntry> contents_;
    std::vector<store::MessageRecord> messages_;
    std::vector<UserEntry> users_;
    std::vector<store::CredentialRecord> credentials_;
    std::vector<InviteEntry> invites_;
  };

  [[nodiscard]] auto backend(store::Transaction &transaction) const noexcept
      -> Backend * {
    return dynamic_cast<Backend *>(transaction_backend(transaction));
  }

  [[nodiscard]] auto tombstone_impl(store::Transaction &transaction,
                                    const store::ContentRef &content)
      -> std::expected<void, store::Error> override {
    auto *active = backend(transaction);
    if (active == nullptr) {
      return std::unexpected(store::Error{store::ErrorCode::invalid_state,
                                          "invalid memory transaction"});
    }
    auto &contents = active->contents();
    const auto found = std::ranges::find(
        contents, content,
        [](const ContentEntry &entry) -> const store::ContentRef & {
          return entry.content;
        });
    if (found == contents.end()) {
      return std::unexpected(store::Error{
          store::ErrorCode::not_found, "content to tombstone does not exist"});
    }
    found->status = store::ContentStatus::tombstoned;
    if (content.kind == store::ContentKind::message) {
      const auto &identifier = std::get<std::string>(content.id);
      const auto message = std::ranges::find(active->messages(), identifier,
                                             &store::MessageRecord::message_id);
      if (message != active->messages().end()) {
        message->status = store::ContentStatus::tombstoned;
      }
    }
    return {};
  }

  [[nodiscard]] static auto visible(const Backend &active,
                                    const store::MessageRecord &message,
                                    ContentVisibility visibility) -> bool {
    if (visibility == ContentVisibility::including_tombstones) {
      return true;
    }
    const auto own = status_of(
        active.contents(), {store::ContentKind::message, message.message_id});
    const auto thread = status_of(
        active.contents(), {store::ContentKind::thread, message.thread_id});
    const auto board = status_of(active.contents(),
                                 {store::ContentKind::board, message.board_id});
    return own == store::ContentStatus::active &&
           thread == store::ContentStatus::active &&
           board == store::ContentStatus::active;
  }

  [[nodiscard]] auto find_message_impl(store::Transaction &transaction,
                                       std::string_view message_id,
                                       ContentVisibility visibility)
      -> std::expected<std::optional<store::MessageRecord>,
                       store::Error> override {
    auto *active = backend(transaction);
    if (active == nullptr) {
      return std::unexpected(store::Error{store::ErrorCode::invalid_state,
                                          "invalid memory transaction"});
    }
    const auto message = std::ranges::find(active->messages(), message_id,
                                           &store::MessageRecord::message_id);
    if (message == active->messages().end() ||
        !visible(*active, *message, visibility)) {
      return std::nullopt;
    }
    return *message;
  }

  [[nodiscard]] auto
  list_messages_for_board_impl(store::Transaction &transaction,
                               std::string_view board_id,
                               ContentVisibility visibility)
      -> std::expected<std::vector<store::MessageRecord>,
                       store::Error> override {
    auto *active = backend(transaction);
    if (active == nullptr) {
      return std::unexpected(store::Error{store::ErrorCode::invalid_state,
                                          "invalid memory transaction"});
    }
    std::vector<store::MessageRecord> result;
    for (const auto &message : active->messages()) {
      if (message.board_id == board_id &&
          visible(*active, message, visibility)) {
        result.push_back(message);
      }
    }
    return result;
  }

  [[nodiscard]] auto find_local_credential_impl(store::Transaction &transaction,
                                                std::string_view fingerprint)
      -> std::expected<std::optional<store::CredentialRecord>,
                       store::Error> override {
    auto *active = backend(transaction);
    if (active == nullptr) {
      return std::unexpected(store::Error{store::ErrorCode::invalid_state,
                                          "invalid memory transaction"});
    }
    const auto credential =
        std::ranges::find(active->credentials(), fingerprint,
                          &store::CredentialRecord::fingerprint);
    if (credential == active->credentials().end()) {
      return std::nullopt;
    }
    return *credential;
  }

  [[nodiscard]] auto provision_local_credential_impl(
      store::Transaction &transaction,
      const store::LocalCredentialProvision &provision)
      -> std::expected<void, store::Error> override {
    auto *active = backend(transaction);
    if (active == nullptr) {
      return std::unexpected(store::Error{store::ErrorCode::invalid_state,
                                          "invalid memory transaction"});
    }
    auto &credentials = active->credentials();
    const auto credential =
        std::ranges::find(credentials, provision.fingerprint,
                          &store::CredentialRecord::fingerprint);
    if (credential != credentials.end()) {
      if (provision.user_status == store::UserStatus::active &&
          credential->handle == provision.handle &&
          credential->public_key == provision.public_key &&
          credential->status == store::CredentialStatus::active) {
        return {};
      }
      return std::unexpected(
          store::Error{store::ErrorCode::conflict,
                       "credential fingerprint is already provisioned"});
    }

    auto &users = active->users();
    const auto user =
        std::ranges::find(users, provision.handle, &UserEntry::handle);
    if (user != users.end()) {
      if (provision.user_status != store::UserStatus::active ||
          user->status != store::UserStatus::active) {
        return std::unexpected(store::Error{
            store::ErrorCode::conflict, "local handle is already provisioned"});
      }
    } else {
      users.push_back({.handle = provision.handle,
                       .status = provision.user_status,
                       .invite_balance = 0,
                       .next_regeneration = std::nullopt});
    }
    const auto status = provision.user_status == store::UserStatus::active
                            ? store::CredentialStatus::active
                            : store::CredentialStatus::pending;
    credentials.push_back({provision.handle, provision.fingerprint,
                           provision.public_key, status});
    return {};
  }

  [[nodiscard]] auto claim_invite_impl(store::Transaction &transaction,
                                       const store::InviteClaim &claim)
      -> std::expected<void, store::Error> override {
    auto *active = backend(transaction);
    if (active == nullptr) {
      return std::unexpected(store::Error{store::ErrorCode::invalid_state,
                                          "invalid memory transaction"});
    }
    const auto user = std::ranges::find(
        active->users(), claim.claimed_by_handle, &UserEntry::handle);
    if (user == active->users().end() ||
        user->status != store::UserStatus::pending) {
      return std::unexpected(store::Error{store::ErrorCode::conflict,
                                          "invite claimant is not pending"});
    }
    auto &invites = active->invites();
    const auto invite =
        std::ranges::find(invites, claim.code_hash, &InviteEntry::code_hash);
    if (invite == invites.end() || !invite->active ||
        !invite->claimed_by_handle.empty() || invite->claimed_at.has_value() ||
        invite->expires_at <= claim.claimed_at) {
      return std::unexpected(
          store::Error{store::ErrorCode::conflict,
                       "invite is invalid or no longer available"});
    }
    invite->active = false;
    invite->claimed_by_handle = claim.claimed_by_handle;
    invite->claimed_at = claim.claimed_at;
    return {};
  }

  [[nodiscard]] auto issue_invite_impl(store::Transaction &transaction,
                                       const store::InviteIssue &issue)
      -> std::expected<store::InviteIssueResult, store::Error> override {
    auto *active = backend(transaction);
    if (active == nullptr) {
      return std::unexpected(store::Error{store::ErrorCode::invalid_state,
                                          "invalid memory transaction"});
    }
    auto &users = active->users();
    const auto user =
        std::ranges::find(users, issue.inviter_handle, &UserEntry::handle);
    if (user == users.end()) {
      return std::unexpected(store::Error{store::ErrorCode::not_found,
                                          "invite issuer does not exist"});
    }
    if (user->status != store::UserStatus::active) {
      return std::unexpected(
          store::Error{store::ErrorCode::conflict,
                       "only active accounts may issue invites"});
    }
    auto &invites = active->invites();
    if (std::ranges::find(invites, issue.code_hash, &InviteEntry::code_hash) !=
        invites.end()) {
      return std::unexpected(store::Error{store::ErrorCode::conflict,
                                          "invite code already exists"});
    }

    const auto cap = static_cast<std::int64_t>(issue.balance_cap);
    auto balance = std::min<std::int64_t>(user->invite_balance, cap);
    auto next = user->next_regeneration;
    if (!next) {
      balance = cap;
    }
    const auto period = static_cast<std::int64_t>(issue.regeneration_seconds);
    if (next && issue.created_at >= *next) {
      const auto elapsed = static_cast<std::uint64_t>(issue.created_at.value) -
                           static_cast<std::uint64_t>(next->value);
      const auto elapsed_intervals =
          elapsed / static_cast<std::uint64_t>(period);
      const auto credits_needed = static_cast<std::uint64_t>(cap - balance);
      if (credits_needed == 0U || elapsed_intervals >= credits_needed - 1U) {
        balance = cap;
        next.reset();
      } else {
        const auto intervals = 1 + static_cast<std::int64_t>(elapsed_intervals);
        balance += intervals;
        next->value += intervals * period;
      }
    }
    if (balance == 0) {
      return std::unexpected(store::Error{store::ErrorCode::conflict,
                                          "invite balance is exhausted"});
    }
    --balance;
    if (balance < cap && !next) {
      next = store::UtcEpochSeconds{issue.created_at.value + period};
    }
    invites.push_back({.code_hash = issue.code_hash,
                       .inviter_handle = issue.inviter_handle,
                       .claimed_by_handle = {},
                       .claimed_at = std::nullopt,
                       .expires_at = issue.expires_at,
                       .active = true});
    user->invite_balance = static_cast<std::uint32_t>(balance);
    user->next_regeneration = next;
    return store::InviteIssueResult{.remaining_balance = user->invite_balance,
                                    .next_regeneration =
                                        user->next_regeneration};
  }

  [[nodiscard]] auto find_inviter_impl(store::Transaction &transaction,
                                       std::string_view invitee_handle)
      -> std::expected<std::optional<store::InviteUser>,
                       store::Error> override {
    auto *active = backend(transaction);
    if (active == nullptr) {
      return std::unexpected(store::Error{store::ErrorCode::invalid_state,
                                          "invalid memory transaction"});
    }
    const auto invite =
        std::ranges::find(active->invites(), invitee_handle,
                          [](const InviteEntry &entry) -> const std::string & {
                            return entry.claimed_by_handle;
                          });
    if (invite == active->invites().end()) {
      return std::optional<store::InviteUser>{};
    }
    const auto inviter = std::ranges::find(
        active->users(), invite->inviter_handle, &UserEntry::handle);
    if (inviter == active->users().end()) {
      return std::unexpected(store::Error{store::ErrorCode::invalid_data,
                                          "invite graph has no inviter"});
    }
    return std::optional<store::InviteUser>{
        store::InviteUser{.handle = inviter->handle,
                          .origin = std::nullopt,
                          .status = inviter->status}};
  }

  [[nodiscard]] auto list_invite_subtree_impl(store::Transaction &transaction,
                                              std::string_view root_handle)
      -> std::expected<std::vector<store::InviteDescendant>,
                       store::Error> override {
    auto *active = backend(transaction);
    if (active == nullptr) {
      return std::unexpected(store::Error{store::ErrorCode::invalid_state,
                                          "invalid memory transaction"});
    }
    if (std::ranges::find(active->users(), root_handle, &UserEntry::handle) ==
        active->users().end()) {
      return std::unexpected(store::Error{
          store::ErrorCode::not_found, "invite subtree root does not exist"});
    }
    std::vector<std::string> frontier{std::string(root_handle)};
    std::vector<std::string> seen{std::string(root_handle)};
    std::vector<store::InviteDescendant> result;
    for (std::uint32_t depth = 1; !frontier.empty(); ++depth) {
      std::vector<std::string> next;
      for (const auto &parent : frontier) {
        for (const auto &invite : active->invites()) {
          if (invite.inviter_handle != parent ||
              invite.claimed_by_handle.empty())
            continue;
          if (std::ranges::find(seen, invite.claimed_by_handle) != seen.end())
            continue;
          const auto user = std::ranges::find(
              active->users(), invite.claimed_by_handle, &UserEntry::handle);
          if (user == active->users().end()) {
            return std::unexpected(
                store::Error{store::ErrorCode::invalid_data,
                             "invite graph descendant does not exist"});
          }
          seen.push_back(user->handle);
          next.push_back(user->handle);
          result.push_back({.user = {.handle = user->handle,
                                     .origin = std::nullopt,
                                     .status = user->status},
                            .depth = depth});
        }
      }
      std::ranges::sort(result, [](const auto &left, const auto &right) {
        if (left.depth != right.depth)
          return left.depth < right.depth;
        return left.user.handle < right.user.handle;
      });
      frontier = std::move(next);
    }
    return result;
  }

  std::shared_ptr<State> state_;
  std::optional<store::Error> next_begin_error_;
};

} // namespace anvil::testing
