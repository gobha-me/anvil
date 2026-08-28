#include <anvil/store.hpp>

#include "support/memory_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

using anvil::store::ContentKind;
using anvil::store::ContentRef;
using anvil::store::ContentStatus;
using anvil::store::Error;
using anvil::store::ErrorCode;
using anvil::store::MessageRecord;
using anvil::store::Store;
using anvil::store::TransactionMode;

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
