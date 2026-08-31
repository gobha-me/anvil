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
using anvil::store::Store;
using anvil::store::TransactionMode;
using anvil::store::UserStatus;

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

}  // namespace

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
  const auto embedded_nul =
      first.provision_local_credential(*write, provision);
  REQUIRE_FALSE(embedded_nul.has_value());
  CHECK(embedded_nul.error().code == ErrorCode::invalid_data);

  const auto invalid_lookup = first.find_local_credential(
      *write, std::string{"SHA256:key\0tail", 15});
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
