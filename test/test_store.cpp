#include <anvil/store.hpp>
#include <catch2/catch_test_macros.hpp>
#include <expected>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "support/memory_store.hpp"

namespace {

using anvil::store::ContentKind;
using anvil::store::ContentRef;
using anvil::store::ContentStatus;
using anvil::store::CredentialRecord;
using anvil::store::CredentialStatus;
using anvil::store::Error;
using anvil::store::ErrorCode;
using anvil::store::LocalCredentialProvision;
using anvil::store::MessageRecord;
using anvil::store::OnelinerCreate;
using anvil::store::OnelinerPolicy;
using anvil::store::Store;
using anvil::store::TransactionMode;
using anvil::store::UserStatus;
using anvil::store::UtcEpochSeconds;

constexpr std::string_view board_id = "00000000-0000-0000-0000-000000000001";

[[nodiscard]] auto message(std::string id, std::int64_t received_at)
    -> MessageRecord {
  return {
      .message_id = std::move(id),
      .board_id = std::string(board_id),
      .thread_id = "thread-1",
      .parent_message_id = std::nullopt,
      .author_handle = "alice",
      .author_origin = std::nullopt,
      .body = "hello",
      .posted_at = {received_at - 1},
      .received_at = {received_at},
      .status = ContentStatus::active,
  };
}

[[nodiscard]] auto board_read(Store &store) -> std::expected<void, Error> {
  auto transaction = store.begin(TransactionMode::read_only);
  if (!transaction) {
    return std::unexpected(transaction.error());
  }
  return transaction->commit();
}

[[nodiscard]] auto moderation_write(Store &store)
    -> std::expected<void, Error> {
  auto transaction = store.begin(TransactionMode::read_write);
  if (!transaction) {
    return std::unexpected(transaction.error());
  }
  return transaction->commit();
}

[[nodiscard]] auto door_state_write(Store &store)
    -> std::expected<void, Error> {
  auto transaction = store.begin(TransactionMode::read_write);
  if (!transaction) {
    return std::unexpected(transaction.error());
  }
  return transaction->commit();
}

} // namespace

TEST_CASE("the store boundary uses explicit UTC epoch seconds") {
  constexpr anvil::store::UtcEpochSeconds before_epoch{-1};
  constexpr anvil::store::UtcEpochSeconds epoch{};
  constexpr anvil::store::UtcEpochSeconds after_epoch{1};

  STATIC_CHECK(before_epoch < epoch);
  STATIC_CHECK(epoch < after_epoch);
}

TEST_CASE("a committed transaction completes exactly once") {
  anvil::testing::MemoryStore store;
  auto transaction = store.begin(TransactionMode::read_write);

  REQUIRE(transaction.has_value());
  CHECK(transaction->active());
  CHECK(transaction->mode() == TransactionMode::read_write);
  CHECK(transaction->commit().has_value());
  CHECK_FALSE(transaction->active());

  const auto second_commit = transaction->commit();
  REQUIRE_FALSE(second_commit.has_value());
  CHECK(second_commit.error().code == ErrorCode::invalid_state);
  REQUIRE(store.observations().size() == 1);
  CHECK(store.observations().front().commit_attempts == 1);
  CHECK(store.observations().front().rollbacks == 0);
}

TEST_CASE("an unfinished transaction rolls back on destruction") {
  anvil::testing::MemoryStore store;
  {
    auto transaction = store.begin(TransactionMode::read_only);
    REQUIRE(transaction.has_value());
  }

  REQUIRE(store.observations().size() == 1);
  CHECK(store.observations().front().commit_attempts == 0);
  CHECK(store.observations().front().rollbacks == 1);
}

TEST_CASE("explicit rollback is idempotent") {
  anvil::testing::MemoryStore store;
  auto transaction = store.begin(TransactionMode::read_write);
  REQUIRE(transaction.has_value());

  transaction->rollback();
  transaction->rollback();

  CHECK_FALSE(transaction->active());
  REQUIRE(store.observations().size() == 1);
  CHECK(store.observations().front().rollbacks == 1);
}

TEST_CASE("a failed commit remains active and rolls back") {
  anvil::testing::MemoryStore store;
  store.fail_next_commit({ErrorCode::unavailable, "database disconnected"});
  {
    auto transaction = store.begin(TransactionMode::read_write);
    REQUIRE(transaction.has_value());

    const auto committed = transaction->commit();
    REQUIRE_FALSE(committed.has_value());
    CHECK(committed.error() ==
          Error{ErrorCode::unavailable, "database disconnected"});
    CHECK(transaction->active());
  }

  REQUIRE(store.observations().size() == 1);
  CHECK(store.observations().front().commit_attempts == 1);
  CHECK(store.observations().front().rollbacks == 1);
}

TEST_CASE("moving a transaction transfers its rollback obligation") {
  anvil::testing::MemoryStore store;
  {
    auto first = store.begin(TransactionMode::read_only);
    auto second = store.begin(TransactionMode::read_write);
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());

    *second = std::move(*first);
    CHECK_FALSE(first->active());
    CHECK(second->active());
  }

  REQUIRE(store.observations().size() == 2);
  CHECK(store.observations()[0].rollbacks == 1);
  CHECK(store.observations()[1].rollbacks == 1);
}

TEST_CASE("begin failures are values and do not create transaction state") {
  anvil::testing::MemoryStore store;
  store.fail_next_begin({ErrorCode::unavailable, "storage offline"});

  const auto transaction = store.begin(TransactionMode::read_only);

  REQUIRE_FALSE(transaction.has_value());
  CHECK(transaction.error() ==
        Error{ErrorCode::unavailable, "storage offline"});
  CHECK(store.observations().empty());
}

TEST_CASE("a store rejects null and foreign transaction backends") {
  anvil::testing::MemoryStore first_store;
  anvil::testing::MemoryStore second_store;

  const auto invalid = first_store.begin_with_null_backend();
  REQUIRE_FALSE(invalid.has_value());
  CHECK(invalid.error().code == ErrorCode::internal);

  auto transaction = first_store.begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());
  CHECK(first_store.owns(*transaction));
  CHECK_FALSE(second_store.owns(*transaction));
  transaction->rollback();
  CHECK_FALSE(first_store.owns(*transaction));
}

TEST_CASE("board moderation and door consumers need no database library") {
  anvil::testing::MemoryStore store;

  CHECK(board_read(store).has_value());
  CHECK(moderation_write(store).has_value());
  CHECK(door_state_write(store).has_value());

  REQUIRE(store.observations().size() == 3);
  CHECK(store.observations()[0].mode == TransactionMode::read_only);
  CHECK(store.observations()[1].mode == TransactionMode::read_write);
  CHECK(store.observations()[2].mode == TransactionMode::read_write);
}

TEST_CASE("ordinary memory-store reads cannot reveal a message tombstone") {
  anvil::testing::MemoryStore store;
  store.seed_message(message("message-1", 11));
  store.seed_message(message("message-2", 12));

  auto transaction = store.begin(TransactionMode::read_write);
  REQUIRE(transaction.has_value());
  REQUIRE(store.find_message(*transaction, "message-1").has_value());
  CHECK(store.find_message(*transaction, "message-1")->has_value());
  REQUIRE(store.list_messages_for_board(*transaction, board_id).has_value());
  CHECK(store.list_messages_for_board(*transaction, board_id)->size() == 2);

  const ContentRef first{ContentKind::message, std::string("message-1")};
  CHECK(store.tombstone(*transaction, first).has_value());
  CHECK(store.tombstone(*transaction, first).has_value());
  CHECK_FALSE(store.find_message(*transaction, "message-1")->has_value());
  CHECK(store.list_messages_for_board(*transaction, board_id)->size() == 1);

  const auto retained =
      store.find_message_including_tombstones(*transaction, "message-1");
  REQUIRE(retained.has_value());
  REQUIRE(retained->has_value());
  CHECK((*retained)->status == ContentStatus::tombstoned);
  CHECK((*retained)->body == "hello");
  CHECK(
      store
          .list_messages_for_board_including_tombstones(*transaction, board_id)
          ->size() == 2);
  REQUIRE(transaction->commit().has_value());

  CHECK(store.content_status(first) == ContentStatus::tombstoned);
}

TEST_CASE("memory-store tombstones obey transaction and identifier rules") {
  anvil::testing::MemoryStore first;
  anvil::testing::MemoryStore second;
  const ContentRef message_ref{ContentKind::message, std::string("message-1")};
  first.seed_message(message("message-1", 11));

  auto read = first.begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  const auto read_only = first.tombstone(*read, message_ref);
  REQUIRE_FALSE(read_only.has_value());
  CHECK(read_only.error().code == ErrorCode::invalid_state);

  const auto foreign = second.tombstone(*read, message_ref);
  REQUIRE_FALSE(foreign.has_value());
  CHECK(foreign.error().code == ErrorCode::invalid_state);
  read->rollback();
  const auto inactive = first.find_message(*read, "message-1");
  REQUIRE_FALSE(inactive.has_value());
  CHECK(inactive.error().code == ErrorCode::invalid_state);

  auto write = first.begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  const auto missing =
      first.tombstone(*write, {ContentKind::message, std::string("missing")});
  REQUIRE_FALSE(missing.has_value());
  CHECK(missing.error().code == ErrorCode::not_found);
  const auto wrong_type =
      first.tombstone(*write, {ContentKind::message, std::int64_t{1}});
  REQUIRE_FALSE(wrong_type.has_value());
  CHECK(wrong_type.error().code == ErrorCode::invalid_data);
  const auto malformed_board = first.list_messages_for_board(*write, "../db");
  REQUIRE_FALSE(malformed_board.has_value());
  CHECK(malformed_board.error().code == ErrorCode::invalid_data);
}

TEST_CASE(
    "memory-store rollback preserves content and parent tombstones hide it") {
  anvil::testing::MemoryStore store;
  store.seed_message(message("message-1", 11));
  const ContentRef message_ref{ContentKind::message, std::string("message-1")};

  {
    auto transaction = store.begin(TransactionMode::read_write);
    REQUIRE(transaction.has_value());
    REQUIRE(store.tombstone(*transaction, message_ref).has_value());
  }
  CHECK(store.content_status(message_ref) == ContentStatus::active);

  auto parent = store.begin(TransactionMode::read_write);
  REQUIRE(parent.has_value());
  REQUIRE(
      store.tombstone(*parent, {ContentKind::thread, std::string("thread-1")})
          .has_value());
  CHECK_FALSE(store.find_message(*parent, "message-1")->has_value());
  CHECK(store.find_message_including_tombstones(*parent, "message-1")
            ->has_value());
}

TEST_CASE("local credential lookup distinguishes unknown and revoked keys") {
  anvil::testing::MemoryStore store;
  store.seed_credential(CredentialRecord{
      .handle = "alice",
      .fingerprint = "SHA256:revoked",
      .public_key = "ssh-ed25519 AAAA",
      .status = CredentialStatus::revoked,
  });
  auto transaction = store.begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());

  const auto unknown =
      store.find_local_credential(*transaction, "SHA256:unknown");
  REQUIRE(unknown.has_value());
  CHECK_FALSE(unknown->has_value());
  const auto revoked =
      store.find_local_credential(*transaction, "SHA256:revoked");
  REQUIRE(revoked.has_value());
  REQUIRE(revoked->has_value());
  CHECK((*revoked)->status == CredentialStatus::revoked);

  const auto malformed = store.find_local_credential(*transaction, "MD5:bad");
  REQUIRE_FALSE(malformed.has_value());
  CHECK(malformed.error().code == ErrorCode::invalid_data);
}

TEST_CASE("pending credential provisioning is atomic and rollback-safe") {
  anvil::testing::MemoryStore store;
  const LocalCredentialProvision pending{
      .handle = "alice",
      .fingerprint = "SHA256:alice",
      .public_key = "ssh-ed25519 AAAA",
      .created_at = {10},
      .user_status = UserStatus::pending,
  };
  {
    auto transaction = store.begin(TransactionMode::read_write);
    REQUIRE(transaction.has_value());
    REQUIRE(
        store.provision_local_credential(*transaction, pending).has_value());
  }
  auto read = store.begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  CHECK_FALSE(
      store.find_local_credential(*read, pending.fingerprint)->has_value());
  read->rollback();

  auto write = store.begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  REQUIRE(store.provision_local_credential(*write, pending).has_value());
  REQUIRE(write->commit().has_value());
  auto committed = store.begin(TransactionMode::read_only);
  REQUIRE(committed.has_value());
  const auto found =
      store.find_local_credential(*committed, pending.fingerprint);
  REQUIRE(found.has_value());
  REQUIRE(found->has_value());
  CHECK((*found)->status == CredentialStatus::pending);
  CHECK((*found)->handle == "alice");
}

TEST_CASE("active bootstrap is exact, idempotent, and supports another key") {
  anvil::testing::MemoryStore store;
  const LocalCredentialProvision first{
      .handle = "operator",
      .fingerprint = "SHA256:first",
      .public_key = "ssh-ed25519 FIRST",
      .created_at = {10},
      .user_status = UserStatus::active,
  };
  const LocalCredentialProvision second{
      .handle = "operator",
      .fingerprint = "SHA256:second",
      .public_key = "ssh-ed25519 SECOND",
      .created_at = {11},
      .user_status = UserStatus::active,
  };
  auto transaction = store.begin(TransactionMode::read_write);
  REQUIRE(transaction.has_value());
  CHECK(store.provision_local_credential(*transaction, first).has_value());
  CHECK(store.provision_local_credential(*transaction, first).has_value());
  CHECK(store.provision_local_credential(*transaction, second).has_value());
  const auto changed = first;
  auto conflicting = changed;
  conflicting.public_key = "ssh-ed25519 CHANGED";
  const auto conflict =
      store.provision_local_credential(*transaction, conflicting);
  REQUIRE_FALSE(conflict.has_value());
  CHECK(conflict.error().code == ErrorCode::conflict);
}

TEST_CASE("credential provisioning enforces transaction and identity rules") {
  anvil::testing::MemoryStore first;
  anvil::testing::MemoryStore second;
  LocalCredentialProvision provision{
      .handle = "guest",
      .fingerprint = "SHA256:key",
      .public_key = "ssh-ed25519 AAAA",
      .created_at = {10},
      .user_status = UserStatus::pending,
  };
  auto read = first.begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  const auto read_only = first.provision_local_credential(*read, provision);
  REQUIRE_FALSE(read_only.has_value());
  CHECK(read_only.error().code == ErrorCode::invalid_state);
  const auto foreign = second.provision_local_credential(*read, provision);
  REQUIRE_FALSE(foreign.has_value());
  CHECK(foreign.error().code == ErrorCode::invalid_state);
  read->rollback();

  auto write = first.begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  const auto reserved = first.provision_local_credential(*write, provision);
  REQUIRE_FALSE(reserved.has_value());
  CHECK(reserved.error().code == ErrorCode::invalid_data);
  provision.handle = "alice";
  provision.user_status = UserStatus::suspended;
  const auto invalid_status =
      first.provision_local_credential(*write, provision);
  REQUIRE_FALSE(invalid_status.has_value());
  CHECK(invalid_status.error().code == ErrorCode::invalid_data);

  provision.user_status = UserStatus::pending;
  provision.fingerprint = "not-a-sha256-fingerprint";
  const auto invalid_fingerprint =
      first.provision_local_credential(*write, provision);
  REQUIRE_FALSE(invalid_fingerprint.has_value());
  CHECK(invalid_fingerprint.error().code == ErrorCode::invalid_data);

  provision.fingerprint = "SHA256:key";
  provision.public_key = std::string{"ssh-ed25519 BAD\0tail", 20};
  const auto embedded_nul = first.provision_local_credential(*write, provision);
  REQUIRE_FALSE(embedded_nul.has_value());
  CHECK(embedded_nul.error().code == ErrorCode::invalid_data);

  const auto invalid_lookup =
      first.find_local_credential(*write, std::string{"SHA256:key\0tail", 15});
  REQUIRE_FALSE(invalid_lookup.has_value());
  CHECK(invalid_lookup.error().code == ErrorCode::invalid_data);
}

TEST_CASE(
    "invite claims require a pending local user and a write transaction") {
  anvil::testing::MemoryStore first;
  anvil::testing::MemoryStore second;
  constexpr std::string_view code_hash =
      "fbaf7ba4264e2392988d8b5863e0a080bfe65b2a48d9b9f042f7cc7d4f711bb9";
  const anvil::store::InviteClaim claim{
      .code_hash = std::string(code_hash),
      .claimed_by_handle = "alice",
      .claimed_at = {11},
  };
  first.seed_invite(std::string(code_hash));

  auto read = first.begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  CHECK(first.claim_invite(*read, claim).error().code ==
        ErrorCode::invalid_state);
  CHECK(second.claim_invite(*read, claim).error().code ==
        ErrorCode::invalid_state);
  read->rollback();

  auto write = first.begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  CHECK(first.claim_invite(*write, claim).error().code == ErrorCode::conflict);
  const LocalCredentialProvision pending{
      .handle = "alice",
      .fingerprint = "SHA256:alice",
      .public_key = "ssh-ed25519 ALICE",
      .created_at = {10},
      .user_status = UserStatus::pending,
  };
  REQUIRE(first.provision_local_credential(*write, pending).has_value());
  REQUIRE(first.claim_invite(*write, claim).has_value());
  REQUIRE(write->commit().has_value());
  CHECK(first.invite_claimant(code_hash) == "alice");

  auto invalid = first.begin(TransactionMode::read_write);
  REQUIRE(invalid.has_value());
  auto malformed = claim;
  malformed.code_hash = "not-a-sha256-hash";
  CHECK(first.claim_invite(*invalid, malformed).error().code ==
        ErrorCode::invalid_data);
}

TEST_CASE(
    "TOS acceptance is append-only and atomically activates pending users") {
  anvil::testing::MemoryStore store;
  store.seed_credential(anvil::store::CredentialRecord{
      .handle = "alice",
      .fingerprint = "SHA256:alice",
      .public_key = "ssh-ed25519 ALICE",
      .status = anvil::store::CredentialStatus::pending,
  });

  auto read = store.begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  CHECK_FALSE(store.has_tos_acceptance(*read, "alice", "2026-09").value());
  CHECK_FALSE(store
                  .accept_tos(*read, {.user_handle = "alice",
                                      .tos_version = "2026-09",
                                      .accepted_at = {10}})
                  .has_value());
  read->rollback();

  auto write = store.begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  CHECK(store.accept_tos(*write, {.user_handle = "alice",
                                  .tos_version = "2026-09",
                                  .accepted_at = {10}}) == UserStatus::active);
  CHECK(store.user_status("alice") == UserStatus::pending);
  REQUIRE(write->commit().has_value());
  CHECK(store.user_status("alice") == UserStatus::active);
  CHECK(store.tos_acceptance_time("alice", "2026-09") == UtcEpochSeconds{10});

  auto repeat = store.begin(TransactionMode::read_write);
  REQUIRE(repeat.has_value());
  REQUIRE(store
              .accept_tos(*repeat, {.user_handle = "alice",
                                    .tos_version = "2026-09",
                                    .accepted_at = {99}})
              .has_value());
  REQUIRE(store
              .accept_tos(*repeat, {.user_handle = "alice",
                                    .tos_version = "2026-10",
                                    .accepted_at = {20}})
              .has_value());
  REQUIRE(repeat->commit().has_value());
  CHECK(store.tos_acceptance_time("alice", "2026-09") == UtcEpochSeconds{10});
  CHECK(store.tos_acceptance_time("alice", "2026-10") == UtcEpochSeconds{20});
}

TEST_CASE("TOS acceptance rejects invalid identities and rolls back failures") {
  anvil::testing::MemoryStore store;
  store.seed_credential(anvil::store::CredentialRecord{
      .handle = "alice",
      .fingerprint = "SHA256:alice",
      .public_key = "ssh-ed25519 ALICE",
      .status = anvil::store::CredentialStatus::pending,
  });
  auto invalid = store.begin(TransactionMode::read_write);
  REQUIRE(invalid.has_value());
  CHECK_FALSE(store
                  .accept_tos(*invalid, {.user_handle = "alice",
                                         .tos_version = "bad\nversion",
                                         .accepted_at = {1}})
                  .has_value());
  CHECK_FALSE(
      store
          .accept_tos(*invalid, {.user_handle = "alice",
                                 .tos_version = std::string{"bad\xff", 4},
                                 .accepted_at = {1}})
          .has_value());
  CHECK_FALSE(
      store
          .accept_tos(*invalid, {.user_handle = "alice",
                                 .tos_version = std::string{"v\xc2\x85", 3},
                                 .accepted_at = {1}})
          .has_value());
  CHECK_FALSE(store
                  .accept_tos(*invalid, {.user_handle = "missing",
                                         .tos_version = "v1",
                                         .accepted_at = {1}})
                  .has_value());
  invalid->rollback();

  store.fail_next_commit({ErrorCode::unavailable, "failed"});
  auto failed = store.begin(TransactionMode::read_write);
  REQUIRE(failed.has_value());
  REQUIRE(store
              .accept_tos(*failed, {.user_handle = "alice",
                                    .tos_version = "v1",
                                    .accepted_at = {2}})
              .has_value());
  CHECK_FALSE(failed->commit().has_value());
  failed->rollback();
  CHECK(store.user_status("alice") == UserStatus::pending);
  CHECK_FALSE(store.tos_acceptance_time("alice", "v1").has_value());
}

TEST_CASE("invite economics consume, cap, and regenerate atomic credits") {
  anvil::testing::MemoryStore store;
  auto provision = store.begin(TransactionMode::read_write);
  REQUIRE(provision.has_value());
  REQUIRE(store
              .provision_local_credential(*provision,
                                          {.handle = "operator",
                                           .fingerprint = "SHA256:operator",
                                           .public_key = "ssh-ed25519 OPERATOR",
                                           .created_at = {1},
                                           .user_status = UserStatus::active})
              .has_value());
  REQUIRE(provision->commit().has_value());

  const auto issue = [&](char digit, std::int64_t now) {
    auto transaction = store.begin(TransactionMode::read_write);
    REQUIRE(transaction.has_value());
    auto result =
        store.issue_invite(*transaction, {.code_hash = std::string(64, digit),
                                          .inviter_handle = "operator",
                                          .created_at = {now},
                                          .expires_at = {now + 100},
                                          .balance_cap = 2,
                                          .regeneration_seconds = 10});
    if (result) {
      REQUIRE(transaction->commit().has_value());
    }
    return result;
  };

  const auto first = issue('a', 100);
  REQUIRE(first.has_value());
  CHECK(first->remaining_balance == 1);
  CHECK(first->next_regeneration == anvil::store::UtcEpochSeconds{110});
  const auto second = issue('b', 100);
  REQUIRE(second.has_value());
  CHECK(second->remaining_balance == 0);
  CHECK(issue('c', 109).error().code == ErrorCode::conflict);
  const auto regenerated = issue('d', 110);
  REQUIRE(regenerated.has_value());
  CHECK(regenerated->remaining_balance == 0);
  CHECK(regenerated->next_regeneration == anvil::store::UtcEpochSeconds{120});

  auto invalid = store.begin(TransactionMode::read_write);
  REQUIRE(invalid.has_value());
  auto malformed = anvil::store::InviteIssue{.code_hash = std::string(64, 'e'),
                                             .inviter_handle = "operator",
                                             .created_at = {20},
                                             .expires_at = {20},
                                             .balance_cap = 2,
                                             .regeneration_seconds = 10};
  CHECK(store.issue_invite(*invalid, malformed).error().code ==
        ErrorCode::invalid_data);
}

TEST_CASE("invite graph reads retain tombstoned descendants by depth") {
  anvil::testing::MemoryStore store;
  auto seed = store.begin(TransactionMode::read_write);
  REQUIRE(seed.has_value());
  REQUIRE(store
              .provision_local_credential(*seed,
                                          {.handle = "operator",
                                           .fingerprint = "SHA256:operator",
                                           .public_key = "ssh-ed25519 OPERATOR",
                                           .created_at = {1},
                                           .user_status = UserStatus::active})
              .has_value());
  REQUIRE(store
              .issue_invite(*seed, {.code_hash = std::string(64, 'a'),
                                    .inviter_handle = "operator",
                                    .created_at = {2},
                                    .expires_at = {100},
                                    .balance_cap = 5,
                                    .regeneration_seconds = 10})
              .has_value());
  REQUIRE(store
              .provision_local_credential(*seed,
                                          {.handle = "alice",
                                           .fingerprint = "SHA256:alice",
                                           .public_key = "ssh-ed25519 ALICE",
                                           .created_at = {3},
                                           .user_status = UserStatus::pending})
              .has_value());
  REQUIRE(store
              .claim_invite(*seed, {.code_hash = std::string(64, 'a'),
                                    .claimed_by_handle = "alice",
                                    .claimed_at = {3}})
              .has_value());
  REQUIRE(seed->commit().has_value());
  store.seed_credential({.handle = "alice",
                         .fingerprint = "SHA256:alice",
                         .public_key = "ssh-ed25519 ALICE",
                         .status = CredentialStatus::active});

  auto child = store.begin(TransactionMode::read_write);
  REQUIRE(child.has_value());
  REQUIRE(store
              .issue_invite(*child, {.code_hash = std::string(64, 'b'),
                                     .inviter_handle = "alice",
                                     .created_at = {4},
                                     .expires_at = {100},
                                     .balance_cap = 5,
                                     .regeneration_seconds = 10})
              .has_value());
  REQUIRE(store
              .provision_local_credential(*child,
                                          {.handle = "bob",
                                           .fingerprint = "SHA256:bob",
                                           .public_key = "ssh-ed25519 BOB",
                                           .created_at = {5},
                                           .user_status = UserStatus::pending})
              .has_value());
  REQUIRE(store
              .claim_invite(*child, {.code_hash = std::string(64, 'b'),
                                     .claimed_by_handle = "bob",
                                     .claimed_at = {5}})
              .has_value());
  REQUIRE(child->commit().has_value());
  store.seed_credential({.handle = "bob",
                         .fingerprint = "SHA256:bob",
                         .public_key = "ssh-ed25519 BOB",
                         .status = CredentialStatus::tombstoned});

  auto read = store.begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  const auto inviter = store.find_inviter(*read, "alice");
  REQUIRE(inviter.has_value());
  REQUIRE(inviter->has_value());
  CHECK((*inviter)->handle == "operator");
  const auto subtree = store.list_invite_subtree(*read, "operator");
  REQUIRE(subtree.has_value());
  REQUIRE(subtree->size() == 2);
  CHECK((*subtree)[0] ==
        anvil::store::InviteDescendant{.user = {.handle = "alice",
                                                .origin = std::nullopt,
                                                .status = UserStatus::active},
                                       .depth = 1});
  CHECK((*subtree)[1] == anvil::store::InviteDescendant{
                             .user = {.handle = "bob",
                                      .origin = std::nullopt,
                                      .status = UserStatus::tombstoned},
                             .depth = 2});
  CHECK(store.list_invite_subtree(*read, "missing").error().code ==
        ErrorCode::not_found);
}

TEST_CASE("database-free Store implements board posting and unread contracts") {
  anvil::testing::MemoryStore store;
  store.seed_credential({.handle = "alice",
                         .fingerprint = "SHA256:alice",
                         .public_key = "ssh-ed25519 ALICE",
                         .status = CredentialStatus::active});
  store.seed_credential({.handle = "bob",
                         .fingerprint = "SHA256:bob",
                         .public_key = "ssh-ed25519 BOB",
                         .status = CredentialStatus::active});
  auto write = store.begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  REQUIRE(
      store
          .reconcile_board(
              *write, {.board_id = std::string(board_id),
                       .name = "general",
                       .title = "General",
                       .visibility = anvil::store::BoardVisibility::public_read,
                       .created_at = {1}})
          .has_value());
  REQUIRE(store
              .create_thread(*write, {.board_id = std::string(board_id),
                                      .thread_id = "thread-1",
                                      .message_id = "message-1",
                                      .author_handle = "alice",
                                      .subject = "Welcome",
                                      .body = "first",
                                      .created_at = {2}})
              .has_value());
  REQUIRE(write->commit().has_value());

  auto read = store.begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  const anvil::store::BoardReader bob{.handle = "bob",
                                      .may_read_registered = true};
  auto boards = store.list_boards(*read, bob);
  REQUIRE(boards.has_value());
  REQUIRE(boards->size() == 1);
  CHECK(boards->front().unread_messages == 1);
  auto threads = store.list_threads(*read, board_id, bob);
  REQUIRE(threads.has_value());
  REQUIRE(threads->size() == 1);
  CHECK(threads->front().unread_messages == 1);
  REQUIRE(read->commit().has_value());

  auto mark = store.begin(TransactionMode::read_write);
  REQUIRE(mark.has_value());
  REQUIRE(
      store.mark_thread_read(*mark, "bob", board_id, "thread-1").has_value());
  REQUIRE(store
              .create_reply(*mark, {.board_id = std::string(board_id),
                                    .thread_id = "thread-1",
                                    .message_id = "message-2",
                                    .parent_message_id = "message-1",
                                    .author_handle = "alice",
                                    .body = "reply",
                                    .created_at = {2}})
              .has_value());
  REQUIRE(mark->commit().has_value());

  auto exact = store.begin(TransactionMode::read_only);
  REQUIRE(exact.has_value());
  threads = store.list_threads(*exact, board_id, bob);
  REQUIRE(threads.has_value());
  REQUIRE(threads->size() == 1);
  CHECK(threads->front().unread_messages == 1);
  auto messages =
      store.list_messages_for_thread(*exact, board_id, "thread-1", bob);
  REQUIRE(messages.has_value());
  REQUIRE(messages->size() == 2);
  CHECK(messages->back().parent_message_id == "message-1");
}

TEST_CASE("database-free Store bounds one-liners by rate and retention") {
  anvil::testing::MemoryStore store;
  store.seed_credential({.handle = "alice",
                         .fingerprint = "SHA256:alice-oneliners",
                         .public_key = "ssh-ed25519 ALICE-ONELINERS",
                         .status = CredentialStatus::active});
  constexpr OnelinerPolicy policy{
      .max_posts = 3, .window_seconds = 300, .retention_seconds = 1'209'600};
  auto post = [&](std::string id, std::int64_t at) {
    auto write = store.begin(TransactionMode::read_write);
    REQUIRE(write.has_value());
    auto created =
        store.create_oneliner(*write,
                              OnelinerCreate{.oneliner_id = std::move(id),
                                             .author_handle = "alice",
                                             .body = "hello wall",
                                             .posted_at = {at},
                                             .received_at = {at}},
                              policy);
    if (created) {
      REQUIRE(write->commit().has_value());
    }
    return created;
  };

  REQUIRE(post("line-1", 100).has_value());
  REQUIRE(post("line-2", 101).has_value());
  REQUIRE(post("line-3", 102).has_value());
  const auto limited = post("line-4", 103);
  REQUIRE_FALSE(limited.has_value());
  CHECK(limited.error().code == ErrorCode::conflict);

  auto tombstone = store.begin(TransactionMode::read_write);
  REQUIRE(tombstone.has_value());
  REQUIRE(
      store
          .tombstone(*tombstone, {ContentKind::oneliner, std::string{"line-1"}})
          .has_value());
  REQUIRE(tombstone->commit().has_value());
  REQUIRE(post("line-4", 103).error().code == ErrorCode::conflict);
  REQUIRE(post("line-5", 400).has_value());

  auto read = store.begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  auto visible = store.list_oneliners(*read, {400}, policy, 100);
  REQUIRE(visible.has_value());
  REQUIRE(visible->size() == 3);
  CHECK((*visible)[0].oneliner_id == "line-5");
  CHECK((*visible)[1].oneliner_id == "line-3");
  CHECK((*visible)[2].oneliner_id == "line-2");
  REQUIRE(read->commit().has_value());

  auto purge = store.begin(TransactionMode::read_write);
  REQUIRE(purge.has_value());
  const auto purged =
      store.purge_expired_oneliners(*purge, {1'209'702}, policy);
  REQUIRE(purged.has_value());
  CHECK(*purged == 3);
  REQUIRE(purge->commit().has_value());
}

TEST_CASE("one-liner Store validation rejects unsafe and unbounded requests") {
  anvil::testing::MemoryStore store;
  store.seed_credential({.handle = "alice",
                         .fingerprint = "SHA256:alice-validation",
                         .public_key = "ssh-ed25519 ALICE-VALIDATION",
                         .status = CredentialStatus::active});
  constexpr OnelinerPolicy policy{
      .max_posts = 3, .window_seconds = 300, .retention_seconds = 1'209'600};
  auto write = store.begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  auto multiline = store.create_oneliner(*write,
                                         {.oneliner_id = "line-1",
                                          .author_handle = "alice",
                                          .body = "first\nsecond",
                                          .posted_at = {1},
                                          .received_at = {1}},
                                         policy);
  REQUIRE_FALSE(multiline.has_value());
  CHECK(multiline.error().code == ErrorCode::invalid_data);
  CHECK_FALSE(store.list_oneliners(*write, {1}, policy, 101).has_value());

  auto read = store.begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  CHECK_FALSE(store
                  .create_oneliner(*read,
                                   {.oneliner_id = "line-2",
                                    .author_handle = "alice",
                                    .body = "hello",
                                    .posted_at = {1},
                                    .received_at = {1}},
                                   policy)
                  .has_value());
  CHECK_FALSE(store.purge_expired_oneliners(*read, {1}, policy).has_value());
}
