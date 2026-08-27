#include <anvil/store.hpp>

#include "support/memory_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <utility>

namespace {

using anvil::store::Error;
using anvil::store::ErrorCode;
using anvil::store::Store;
using anvil::store::TransactionMode;

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
