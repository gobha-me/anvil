#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <barrier>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

#include "sqlite_schema.hpp"
#include "sqlite_store.hpp"

namespace {

using anvil::store::BoardProvision;
using anvil::store::BoardReader;
using anvil::store::BoardVisibility;
using anvil::store::ContentKind;
using anvil::store::ContentRef;
using anvil::store::ContentStatus;
using anvil::store::CredentialStatus;
using anvil::store::ErrorCode;
using anvil::store::LocalCredentialProvision;
using anvil::store::OnelinerPolicy;
using anvil::store::ReplyCreate;
using anvil::store::ReportSubmission;
using anvil::store::SqliteOptions;
using anvil::store::SqliteStore;
using anvil::store::ThreadCreate;
using anvil::store::TransactionMode;
using anvil::store::UserStatus;
using anvil::store::detail::SqliteMigration;
using namespace std::chrono_literals;

class TemporaryDatabase {
public:
  TemporaryDatabase() {
    static std::atomic<unsigned int> sequence{};
    directory_ = std::filesystem::temp_directory_path() /
                 ("anvil-sqlite-" + std::to_string(::getpid()) + '-' +
                  std::to_string(sequence.fetch_add(1)));
    std::filesystem::create_directory(directory_);
    path_ = directory_ / "anvil.db";
  }

  ~TemporaryDatabase() {
    std::error_code ignored;
    std::filesystem::remove(path_.string() + "-shm", ignored);
    std::filesystem::remove(path_.string() + "-wal", ignored);
    std::filesystem::remove(path_, ignored);
    std::filesystem::remove(directory_ / "linked.db", ignored);
    std::filesystem::remove(directory_, ignored);
  }

  TemporaryDatabase(const TemporaryDatabase &) = delete;
  auto operator=(const TemporaryDatabase &) -> TemporaryDatabase & = delete;

  [[nodiscard]] auto path() const -> const std::filesystem::path & {
    return path_;
  }

  [[nodiscard]] auto directory() const -> const std::filesystem::path & {
    return directory_;
  }

private:
  std::filesystem::path directory_;
  std::filesystem::path path_;
};

constexpr std::array probe_migrations{
    SqliteMigration{1, "CREATE TABLE probe(value INTEGER NOT NULL)"},
};

[[nodiscard]] auto open_probe(const std::filesystem::path &path,
                              SqliteOptions options = {}) {
  return anvil::store::detail::open_sqlite_store(path, probe_migrations,
                                                 options);
}

} // namespace

namespace {

constexpr std::string_view board_id = "00000000-0000-0000-0000-000000000001";

void seed_messages(SqliteStore &store, anvil::store::Transaction &transaction) {
  REQUIRE(store
              .execute_for_testing(
                  transaction,
                  "INSERT INTO users(handle, status, created_at) "
                  "VALUES('alice', 'active', 10);"
                  "INSERT INTO boards(board_id, name, title, created_at) "
                  "VALUES('00000000-0000-0000-0000-000000000001', "
                  "'general', 'General', 11);"
                  "INSERT INTO threads(thread_id, board_id, author_handle, "
                  "subject, created_at, updated_at) VALUES('thread-1', "
                  "'00000000-0000-0000-0000-000000000001', 'alice', "
                  "'Welcome', 12, 12);"
                  "INSERT INTO messages(message_id, board_id, thread_id, "
                  "author_handle, body, posted_at, received_at) VALUES("
                  "'message-1', "
                  "'00000000-0000-0000-0000-000000000001', 'thread-1', "
                  "'alice', 'first', 13, 14),('message-2', "
                  "'00000000-0000-0000-0000-000000000001', 'thread-1', "
                  "'alice', 'second', 14, 15)")
              .has_value());
}

} // namespace

TEST_CASE("SQLite startup creates exactly the domain schema") {
  TemporaryDatabase database;

  auto store = SqliteStore::open(database.path());

  REQUIRE(store.has_value());
  CHECK((*store)->schema_version() == 5);
  auto transaction = (*store)->begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());
  CHECK((*store)->scalar_for_testing(*transaction, "PRAGMA application_id") ==
        0x414E564C);
  CHECK((*store)->scalar_for_testing(*transaction, "PRAGMA user_version") == 5);
  CHECK((*store)->scalar_for_testing(
            *transaction,
            "SELECT count(*) FROM sqlite_schema WHERE type='index' AND "
            "name IN ('oneliners_visible_received',"
            "'oneliners_author_received')") == 2);
  CHECK((*store)->scalar_for_testing(*transaction, "PRAGMA synchronous") == 2);
  CHECK((*store)->scalar_for_testing(*transaction,
                                     "PRAGMA wal_autocheckpoint") == 1000);
  CHECK((*store)->scalar_text_for_testing(
            *transaction,
            "SELECT group_concat(name, ',') FROM "
            "(SELECT name FROM sqlite_schema WHERE type = 'table' AND "
            "name NOT LIKE 'sqlite_%' ORDER BY name)") ==
        "blocks,board_reads,boards,files,invites,leaderboards,messages,"
        "moderation_log,oneliners,plugin_state,plugins,presence,reports,"
        "sessions_log,thread_reads,threads,tos_acceptances,user_keys,users");
  CHECK(transaction->commit().has_value());

  struct stat metadata{};
  REQUIRE(::stat(database.path().c_str(), &metadata) == 0);
  CHECK((metadata.st_mode & (S_IRWXG | S_IRWXO)) == 0);

  auto reopened = SqliteStore::open(database.path());
  REQUIRE(reopened.has_value());
  CHECK((*reopened)->schema_version() == 5);
}

TEST_CASE("SQLite board visibility is enforced inside every board read") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  auto write = (*store)->begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  REQUIRE((*store)
              ->execute_for_testing(
                  *write, "INSERT INTO users(handle,status,created_at) VALUES"
                          "('alice','active',1),('bob','active',1),"
                          "('pending','pending',1)")
              .has_value());
  REQUIRE(
      (*store)
          ->reconcile_board(
              *write, BoardProvision{.board_id = std::string(board_id),
                                     .name = "general",
                                     .title = "General",
                                     .visibility = BoardVisibility::public_read,
                                     .created_at = {2}})
          .has_value());
  constexpr std::string_view members_id =
      "00000000-0000-0000-0000-000000000002";
  REQUIRE((*store)
              ->reconcile_board(
                  *write,
                  BoardProvision{.board_id = std::string(members_id),
                                 .name = "members",
                                 .title = "Members",
                                 .visibility = BoardVisibility::registered_only,
                                 .created_at = {2}})
              .has_value());
  REQUIRE((*store)
              ->create_thread(*write,
                              ThreadCreate{.board_id = std::string(members_id),
                                           .thread_id = "private-thread",
                                           .message_id = "private-message",
                                           .author_handle = "alice",
                                           .subject = "Private",
                                           .body = "secret",
                                           .created_at = {3}})
              .has_value());

  const BoardReader guest{};
  auto public_boards = (*store)->list_boards(*write, guest);
  REQUIRE(public_boards.has_value());
  REQUIRE(public_boards->size() == 1);
  CHECK(public_boards->front().name == "general");
  auto hidden_threads = (*store)->list_threads(*write, members_id, guest);
  REQUIRE(hidden_threads.has_value());
  CHECK(hidden_threads->empty());
  auto hidden_messages = (*store)->list_messages_for_thread(
      *write, members_id, "private-thread", guest);
  REQUIRE(hidden_messages.has_value());
  CHECK(hidden_messages->empty());

  const BoardReader member{.handle = "bob", .may_read_registered = true};
  auto member_boards = (*store)->list_boards(*write, member);
  REQUIRE(member_boards.has_value());
  REQUIRE(member_boards->size() == 2);
  auto member_messages = (*store)->list_messages_for_thread(
      *write, members_id, "private-thread", member);
  REQUIRE(member_messages.has_value());
  REQUIRE(member_messages->size() == 1);
  CHECK(member_messages->front().body == "secret");
}

TEST_CASE("SQLite unread markers use exact message sequence ordering") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  auto write = (*store)->begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  REQUIRE((*store)
              ->execute_for_testing(
                  *write, "INSERT INTO users(handle,status,created_at) VALUES"
                          "('alice','active',1),('bob','active',1)")
              .has_value());
  REQUIRE((*store)
              ->reconcile_board(
                  *write, BoardProvision{.board_id = std::string(board_id),
                                         .name = "general",
                                         .title = "General",
                                         .created_at = {2}})
              .has_value());
  REQUIRE((*store)
              ->create_thread(*write,
                              ThreadCreate{.board_id = std::string(board_id),
                                           .thread_id = "thread-1",
                                           .message_id = "message-1",
                                           .author_handle = "alice",
                                           .subject = "Welcome",
                                           .body = "first",
                                           .created_at = {10}})
              .has_value());
  const BoardReader bob{.handle = "bob", .may_read_registered = true};
  auto before = (*store)->list_boards(*write, bob);
  REQUIRE(before.has_value());
  REQUIRE(before->size() == 1);
  CHECK(before->front().unread_messages == 1);
  CHECK_FALSE((*store)
                  ->mark_thread_read(*write, "pending", board_id, "thread-1")
                  .has_value());
  CHECK_FALSE(
      (*store)->catch_up_board(*write, "pending", board_id).has_value());
  REQUIRE((*store)
              ->mark_thread_read(*write, "bob", board_id, "thread-1")
              .has_value());
  REQUIRE(
      (*store)
          ->create_reply(*write, ReplyCreate{.board_id = std::string(board_id),
                                             .thread_id = "thread-1",
                                             .message_id = "message-2",
                                             .parent_message_id = std::nullopt,
                                             .author_handle = "alice",
                                             .body = "same second",
                                             .created_at = {10}})
          .has_value());
  auto exact = (*store)->list_threads(*write, board_id, bob);
  REQUIRE(exact.has_value());
  REQUIRE(exact->size() == 1);
  CHECK(exact->front().unread_messages == 1);
  REQUIRE((*store)->catch_up_board(*write, "bob", board_id).has_value());
  auto caught_up = (*store)->list_boards(*write, bob);
  REQUIRE(caught_up.has_value());
  CHECK(caught_up->front().unread_messages == 0);
  REQUIRE(
      (*store)
          ->create_reply(*write, ReplyCreate{.board_id = std::string(board_id),
                                             .thread_id = "thread-1",
                                             .message_id = "message-3",
                                             .parent_message_id = "message-1",
                                             .author_handle = "alice",
                                             .body = "structured quote",
                                             .created_at = {10}})
          .has_value());
  auto messages =
      (*store)->list_messages_for_thread(*write, board_id, "thread-1", bob);
  REQUIRE(messages.has_value());
  REQUIRE(messages->size() == 3);
  CHECK(messages->back().parent_message_id == "message-1");
  CHECK(messages->back().body == "structured quote");
}

TEST_CASE("SQLite reports preserve anonymity and obey board visibility") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  auto write = (*store)->begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  REQUIRE((*store)
              ->execute_for_testing(
                  *write, "INSERT INTO users(handle,status,created_at) VALUES"
                          "('alice','active',1),('pending','pending',1)")
              .has_value());
  REQUIRE((*store)
              ->reconcile_board(
                  *write, BoardProvision{.board_id = std::string(board_id),
                                         .name = "general",
                                         .title = "General",
                                         .created_at = {2}})
              .has_value());
  REQUIRE((*store)
              ->create_thread(*write,
                              ThreadCreate{.board_id = std::string(board_id),
                                           .thread_id = "thread-1",
                                           .message_id = "message-1",
                                           .author_handle = "alice",
                                           .subject = "Welcome",
                                           .body = "first",
                                           .created_at = {3}})
              .has_value());
  REQUIRE((*store)
              ->submit_report(
                  *write, ReportSubmission{.report_id = "guest-report",
                                           .reporter_handle = std::nullopt,
                                           .target = {ContentKind::message,
                                                      std::string("message-1")},
                                           .reason = "spam",
                                           .created_at = {4}})
              .has_value());
  REQUIRE((*store)
              ->submit_report(
                  *write, ReportSubmission{.report_id = "guest-thread-report",
                                           .reporter_handle = std::nullopt,
                                           .target = {ContentKind::thread,
                                                      std::string("thread-1")},
                                           .reason = "off topic",
                                           .created_at = {4}})
              .has_value());
  CHECK((*store)->scalar_text_for_testing(
            *write,
            "SELECT reporter_kind || ':' || coalesce(reporter_handle,'') "
            "FROM reports WHERE report_id='guest-report'") == "guest:");
  REQUIRE((*store)
              ->reconcile_board(
                  *write,
                  BoardProvision{.board_id = std::string(board_id),
                                 .name = "general",
                                 .title = "General",
                                 .visibility = BoardVisibility::registered_only,
                                 .created_at = {2}})
              .has_value());
  const auto hidden = (*store)->submit_report(
      *write, ReportSubmission{
                  .report_id = "hidden-report",
                  .reporter_handle = std::nullopt,
                  .target = {ContentKind::message, std::string("message-1")},
                  .reason = "spam",
                  .created_at = {5}});
  REQUIRE_FALSE(hidden.has_value());
  CHECK(hidden.error().code == ErrorCode::not_found);
  REQUIRE((*store)
              ->submit_report(
                  *write, ReportSubmission{.report_id = "member-hidden-report",
                                           .reporter_handle = "alice",
                                           .target = {ContentKind::message,
                                                      std::string("message-1")},
                                           .reason = "spam",
                                           .created_at = {5}})
              .has_value());
  const auto pending_hidden = (*store)->submit_report(
      *write, ReportSubmission{
                  .report_id = "pending-hidden-report",
                  .reporter_handle = "pending",
                  .target = {ContentKind::message, std::string("message-1")},
                  .reason = "spam",
                  .created_at = {5}});
  REQUIRE_FALSE(pending_hidden.has_value());
  CHECK(pending_hidden.error().code == ErrorCode::not_found);
}

TEST_CASE(
    "SQLite posting fails closed for locked and unrelated quote targets") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  auto write = (*store)->begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  REQUIRE((*store)
              ->execute_for_testing(
                  *write, "INSERT INTO users(handle,status,created_at) VALUES"
                          "('alice','active',1),('pending','pending',1)")
              .has_value());
  REQUIRE((*store)
              ->reconcile_board(
                  *write, BoardProvision{.board_id = std::string(board_id),
                                         .name = "general",
                                         .title = "General",
                                         .created_at = {2}})
              .has_value());
  REQUIRE((*store)
              ->create_thread(*write, {.board_id = std::string(board_id),
                                       .thread_id = "thread-1",
                                       .message_id = "message-1",
                                       .author_handle = "alice",
                                       .subject = "One",
                                       .body = "first",
                                       .created_at = {3}})
              .has_value());
  REQUIRE((*store)
              ->create_thread(*write, {.board_id = std::string(board_id),
                                       .thread_id = "thread-2",
                                       .message_id = "message-2",
                                       .author_handle = "alice",
                                       .subject = "Two",
                                       .body = "second",
                                       .created_at = {4}})
              .has_value());
  const auto cross_thread =
      (*store)->create_reply(*write, {.board_id = std::string(board_id),
                                      .thread_id = "thread-1",
                                      .message_id = "message-cross",
                                      .parent_message_id = "message-2",
                                      .author_handle = "alice",
                                      .body = "not allowed",
                                      .created_at = {5}});
  REQUIRE_FALSE(cross_thread.has_value());
  CHECK(cross_thread.error().code == ErrorCode::not_found);
  const auto pending =
      (*store)->create_reply(*write, {.board_id = std::string(board_id),
                                      .thread_id = "thread-1",
                                      .message_id = "message-pending",
                                      .parent_message_id = std::nullopt,
                                      .author_handle = "pending",
                                      .body = "not active",
                                      .created_at = {5}});
  REQUIRE_FALSE(pending.has_value());
  CHECK(pending.error().code == ErrorCode::not_found);
  REQUIRE((*store)
              ->execute_for_testing(
                  *write,
                  "UPDATE threads SET locked_at=6 WHERE thread_id='thread-1'")
              .has_value());
  const auto locked =
      (*store)->create_reply(*write, {.board_id = std::string(board_id),
                                      .thread_id = "thread-1",
                                      .message_id = "message-locked",
                                      .parent_message_id = std::nullopt,
                                      .author_handle = "alice",
                                      .body = "not allowed",
                                      .created_at = {7}});
  REQUIRE_FALSE(locked.has_value());
  CHECK(locked.error().code == ErrorCode::not_found);
  REQUIRE((*store)
              ->execute_for_testing(
                  *write,
                  "UPDATE messages SET local_sequence=9223372036854775807 "
                  "WHERE message_id='message-2'")
              .has_value());
  const auto exhausted =
      (*store)->create_reply(*write, {.board_id = std::string(board_id),
                                      .thread_id = "thread-2",
                                      .message_id = "message-overflow",
                                      .parent_message_id = std::nullopt,
                                      .author_handle = "alice",
                                      .body = "not allowed",
                                      .created_at = {8}});
  REQUIRE_FALSE(exhausted.has_value());
  CHECK(exhausted.error().code == ErrorCode::conflict);
}

TEST_CASE("SQLite provisions and resolves local credentials atomically") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  const LocalCredentialProvision pending{
      .handle = "alice",
      .fingerprint = "SHA256:alice",
      .public_key = "ssh-ed25519 ALICE",
      .created_at = {10},
      .user_status = UserStatus::pending,
  };

  auto write = (*store)->begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  REQUIRE((*store)->provision_local_credential(*write, pending).has_value());
  REQUIRE(write->commit().has_value());

  auto read = (*store)->begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  const auto found =
      (*store)->find_local_credential(*read, pending.fingerprint);
  REQUIRE(found.has_value());
  REQUIRE(found->has_value());
  CHECK((*found)->handle == "alice");
  CHECK((*found)->public_key == "ssh-ed25519 ALICE");
  CHECK((*found)->status == CredentialStatus::pending);
  CHECK_FALSE(
      (*store)->find_local_credential(*read, "SHA256:unknown")->has_value());
}

TEST_CASE("SQLite active bootstrap is idempotent and adds exact-user keys") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
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
  auto write = (*store)->begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  CHECK((*store)->provision_local_credential(*write, first).has_value());
  CHECK((*store)->provision_local_credential(*write, first).has_value());
  CHECK((*store)->provision_local_credential(*write, second).has_value());
  REQUIRE(write->commit().has_value());

  auto read = (*store)->begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  CHECK((*store)->scalar_for_testing(
            *read, "SELECT count(*) FROM users WHERE handle='operator'") == 1);
  CHECK((*store)->scalar_for_testing(
            *read,
            "SELECT count(*) FROM user_keys WHERE user_handle='operator'") ==
        2);
}

TEST_CASE("SQLite records versioned TOS acceptance and activates atomically") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  auto provision = (*store)->begin(TransactionMode::read_write);
  REQUIRE(provision.has_value());
  REQUIRE((*store)
              ->provision_local_credential(*provision,
                                           {.handle = "alice",
                                            .fingerprint = "SHA256:alice",
                                            .public_key = "ssh-ed25519 ALICE",
                                            .created_at = {1},
                                            .user_status = UserStatus::pending})
              .has_value());
  REQUIRE(provision->commit().has_value());

  auto accept = (*store)->begin(TransactionMode::read_write);
  REQUIRE(accept.has_value());
  REQUIRE((*store)
              ->accept_tos(*accept, {.user_handle = "alice",
                                     .tos_version = "v1",
                                     .accepted_at = {10}})
              .has_value());
  REQUIRE(accept->commit().has_value());

  auto repeat = (*store)->begin(TransactionMode::read_write);
  REQUIRE(repeat.has_value());
  REQUIRE((*store)
              ->accept_tos(*repeat, {.user_handle = "alice",
                                     .tos_version = "v1",
                                     .accepted_at = {99}})
              .has_value());
  REQUIRE((*store)
              ->accept_tos(*repeat, {.user_handle = "alice",
                                     .tos_version = "v2",
                                     .accepted_at = {20}})
              .has_value());
  REQUIRE(repeat->commit().has_value());

  auto verify = (*store)->begin(TransactionMode::read_only);
  REQUIRE(verify.has_value());
  CHECK((*store)->has_tos_acceptance(*verify, "alice", "v1").value());
  CHECK((*store)->has_tos_acceptance(*verify, "alice", "v2").value());
  CHECK_FALSE((*store)->has_tos_acceptance(*verify, "alice", "v3").value());
  CHECK((*store)->scalar_text_for_testing(
            *verify, "SELECT status FROM users WHERE handle='alice'") ==
        "active");
  CHECK((*store)->scalar_for_testing(
            *verify, "SELECT count(*) FROM tos_acceptances") == 2);
  CHECK((*store)->scalar_for_testing(
            *verify,
            "SELECT accepted_at FROM tos_acceptances WHERE tos_version='v1'") ==
        10);
}

TEST_CASE("SQLite revoked credentials never become unknown registrations") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  auto write = (*store)->begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  REQUIRE((*store)
              ->execute_for_testing(
                  *write,
                  "INSERT INTO users(handle,status,created_at) "
                  "VALUES('alice','active',10);"
                  "INSERT INTO user_keys(fingerprint,user_handle,public_key,"
                  "added_at,revoked_at) VALUES('SHA256:revoked','alice',"
                  "'ssh-ed25519 REVOKED',10,11)")
              .has_value());
  REQUIRE(write->commit().has_value());

  auto read = (*store)->begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  const auto revoked = (*store)->find_local_credential(*read, "SHA256:revoked");
  REQUIRE(revoked.has_value());
  REQUIRE(revoked->has_value());
  CHECK((*revoked)->status == CredentialStatus::revoked);

  auto conflicting = LocalCredentialProvision{
      .handle = "mallory",
      .fingerprint = "SHA256:revoked",
      .public_key = "ssh-ed25519 REVOKED",
      .created_at = {12},
      .user_status = UserStatus::pending,
  };
  read->rollback();
  auto attempt = (*store)->begin(TransactionMode::read_write);
  REQUIRE(attempt.has_value());
  const auto reprovision =
      (*store)->provision_local_credential(*attempt, conflicting);
  REQUIRE_FALSE(reprovision.has_value());
  CHECK(reprovision.error().code == ErrorCode::conflict);
}

TEST_CASE("SQLite serializes concurrent redemption of one invite") {
  TemporaryDatabase database;
  auto seed_store = SqliteStore::open(database.path());
  REQUIRE(seed_store.has_value());
  auto seed = (*seed_store)->begin(TransactionMode::read_write);
  REQUIRE(seed.has_value());
  REQUIRE((*seed_store)
              ->execute_for_testing(
                  *seed, "INSERT INTO users(handle,status,created_at) "
                         "VALUES('operator','active',1);"
                         "INSERT INTO invites(code_hash,inviter_handle,status,"
                         "created_at,expires_at) VALUES("
                         "'fbaf7ba4264e2392988d8b5863e0a080bfe65b2a48d9b9f042f7"
                         "cc7d4f711bb9',"
                         "'operator','active',2,100)")
              .has_value());
  REQUIRE(seed->commit().has_value());
  seed_store->reset();

  auto first_store = SqliteStore::open(database.path());
  auto second_store = SqliteStore::open(database.path());
  REQUIRE(first_store.has_value());
  REQUIRE(second_store.has_value());
  std::barrier start(2);
  std::atomic<int> successes{};
  std::atomic<int> conflicts{};
  const auto redeem = [&](SqliteStore &store, std::string handle,
                          std::string fingerprint) {
    start.arrive_and_wait();
    auto transaction = store.begin(TransactionMode::read_write);
    if (!transaction) {
      return;
    }
    const LocalCredentialProvision pending{
        .handle = handle,
        .fingerprint = fingerprint,
        .public_key = "ssh-ed25519 " + handle,
        .created_at = {10},
        .user_status = UserStatus::pending,
    };
    if (!store.provision_local_credential(*transaction, pending)) {
      return;
    }
    const auto claimed = store.claim_invite(
        *transaction, anvil::store::InviteClaim{
                          .code_hash = "fbaf7ba4264e2392988d8b5863e0a080bfe65b2"
                                       "a48d9b9f042f7cc7d4f711bb9",
                          .claimed_by_handle = handle,
                          .claimed_at = {11},
                      });
    if (!claimed) {
      if (claimed.error().code == ErrorCode::conflict) {
        ++conflicts;
      }
      return;
    }
    if (transaction->commit()) {
      ++successes;
    }
  };

  std::jthread first(redeem, std::ref(**first_store), "alice", "SHA256:alice");
  std::jthread second(redeem, std::ref(**second_store), "bob", "SHA256:bob");
  first.join();
  second.join();
  CHECK(successes == 1);
  CHECK(conflicts == 1);

  auto verify = (*first_store)->begin(TransactionMode::read_only);
  REQUIRE(verify.has_value());
  CHECK((*first_store)
            ->scalar_for_testing(
                *verify, "SELECT count(*) FROM users WHERE status='pending'") ==
        1);
  CHECK((*first_store)
            ->scalar_for_testing(*verify, "SELECT count(*) FROM user_keys") ==
        1);
  CHECK((*first_store)
            ->scalar_for_testing(
                *verify,
                "SELECT count(*) FROM invites WHERE status='claimed' AND "
                "claimed_by_handle IS NOT NULL") == 1);
}

TEST_CASE("SQLite serializes issuance of the final invite credit") {
  TemporaryDatabase database;
  auto seed_store = SqliteStore::open(database.path());
  REQUIRE(seed_store.has_value());
  auto seed = (*seed_store)->begin(TransactionMode::read_write);
  REQUIRE(seed.has_value());
  REQUIRE((*seed_store)
              ->execute_for_testing(
                  *seed, "INSERT INTO users(handle,status,created_at) "
                         "VALUES('operator','active',1)")
              .has_value());
  REQUIRE(seed->commit().has_value());
  seed_store->reset();

  auto first_store = SqliteStore::open(database.path());
  auto second_store = SqliteStore::open(database.path());
  REQUIRE(first_store.has_value());
  REQUIRE(second_store.has_value());
  std::barrier start(2);
  std::atomic<int> successes{};
  std::atomic<int> conflicts{};
  const auto issue = [&](SqliteStore &store, char digit) {
    start.arrive_and_wait();
    auto transaction = store.begin(TransactionMode::read_write);
    if (!transaction)
      return;
    auto result =
        store.issue_invite(*transaction, {.code_hash = std::string(64, digit),
                                          .inviter_handle = "operator",
                                          .created_at = {10},
                                          .expires_at = {20},
                                          .balance_cap = 1,
                                          .regeneration_seconds = 100});
    if (!result) {
      if (result.error().code == ErrorCode::conflict)
        ++conflicts;
      return;
    }
    if (transaction->commit())
      ++successes;
  };
  std::jthread first(issue, std::ref(**first_store), 'a');
  std::jthread second(issue, std::ref(**second_store), 'b');
  first.join();
  second.join();
  CHECK(successes == 1);
  CHECK(conflicts == 1);

  auto verify = (*first_store)->begin(TransactionMode::read_only);
  REQUIRE(verify.has_value());
  CHECK((*first_store)
            ->scalar_for_testing(*verify, "SELECT count(*) FROM invites") == 1);
  CHECK((*first_store)
            ->scalar_for_testing(
                *verify,
                "SELECT invite_balance FROM users WHERE handle='operator'") ==
        0);
}

TEST_CASE("SQLite invite regeneration saturates hostile stored timestamps") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  auto write = (*store)->begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  REQUIRE((*store)
              ->execute_for_testing(
                  *write,
                  "INSERT INTO users(handle,status,created_at,invite_balance,"
                  "invite_next_regeneration) VALUES('operator','active',1,0,"
                  "-9223372036854775807 - 1)")
              .has_value());
  REQUIRE(write->commit().has_value());

  auto issue = (*store)->begin(TransactionMode::read_write);
  REQUIRE(issue.has_value());
  const auto result =
      (*store)->issue_invite(*issue, {.code_hash = std::string(64, 'a'),
                                      .inviter_handle = "operator",
                                      .created_at = {0},
                                      .expires_at = {2},
                                      .balance_cap = 2,
                                      .regeneration_seconds = 1});
  REQUIRE(result.has_value());
  CHECK(result->remaining_balance == 1);
  CHECK(result->next_regeneration == anvil::store::UtcEpochSeconds{1});
  REQUIRE(issue->commit().has_value());
}

TEST_CASE("SQLite invite graph includes tombstones and enforces one edge") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  auto write = (*store)->begin(TransactionMode::read_write);
  REQUIRE(write.has_value());
  REQUIRE((*store)
              ->execute_for_testing(
                  *write,
                  "INSERT INTO users(handle,status,created_at) VALUES"
                  "('operator','active',1),('alice','active',2),"
                  "('bob','tombstoned',3);"
                  "INSERT INTO invites(code_hash,inviter_handle,"
                  "claimed_by_handle,status,created_at,claimed_at,expires_at) "
                  "VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                  "aaaaaaaaaaaaaaaa','operator','alice','claimed',2,3,10),"
                  "('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                  "bbbbbbbb','alice','bob','claimed',3,4,10)")
              .has_value());
  const auto duplicate = (*store)->execute_for_testing(
      *write,
      "INSERT INTO invites(code_hash,inviter_handle,claimed_by_handle,status,"
      "created_at,claimed_at,expires_at) VALUES('cccccccccccccccccccccccccccc"
      "cccccccccccccccccccccccccccccccccccc','operator','alice','claimed',"
      "4,5,10)");
  REQUIRE_FALSE(duplicate.has_value());
  CHECK(duplicate.error().code == ErrorCode::constraint_violation);
  REQUIRE(write->commit().has_value());

  auto read = (*store)->begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  const auto inviter = (*store)->find_inviter(*read, "alice");
  REQUIRE(inviter.has_value());
  REQUIRE(inviter->has_value());
  CHECK((*inviter)->handle == "operator");
  const auto subtree = (*store)->list_invite_subtree(*read, "operator");
  REQUIRE(subtree.has_value());
  REQUIRE(subtree->size() == 2);
  CHECK((*subtree)[0].user.handle == "alice");
  CHECK((*subtree)[0].depth == 1);
  CHECK((*subtree)[1].user.handle == "bob");
  CHECK((*subtree)[1].user.status == UserStatus::tombstoned);
  CHECK((*subtree)[1].depth == 2);
}

TEST_CASE("SQLite version-three migration expires legacy bearer codes") {
  TemporaryDatabase database;
  constexpr std::array version_two_migrations{
      SqliteMigration{1, {}},
      SqliteMigration{2, anvil::store::detail::domain_schema_v2},
  };
  auto old = anvil::store::detail::open_sqlite_store(database.path(),
                                                     version_two_migrations);
  REQUIRE(old.has_value());
  auto seed = (*old)->begin(TransactionMode::read_write);
  REQUIRE(seed.has_value());
  REQUIRE((*old)
              ->execute_for_testing(
                  *seed,
                  "INSERT INTO users(handle,status,created_at) VALUES"
                  "('operator','active',1),('alice','pending',2);"
                  "INSERT INTO invites(code_hash,inviter_handle,status,"
                  "created_at) VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaa','operator','active',2)")
              .has_value());
  REQUIRE(seed->commit().has_value());
  old->reset();

  auto upgraded = SqliteStore::open(database.path());
  REQUIRE(upgraded.has_value());
  CHECK((*upgraded)->schema_version() == 5);
  auto claim = (*upgraded)->begin(TransactionMode::read_write);
  REQUIRE(claim.has_value());
  const auto expired =
      (*upgraded)->claim_invite(*claim, {.code_hash = std::string(64, 'a'),
                                         .claimed_by_handle = "alice",
                                         .claimed_at = {3}});
  REQUIRE_FALSE(expired.has_value());
  CHECK(expired.error().code == ErrorCode::conflict);
  CHECK((*upgraded)->scalar_for_testing(*claim,
                                        "SELECT expires_at FROM invites") == 0);
}

TEST_CASE("SQLite version-four migration preserves boards reports and order") {
  TemporaryDatabase database;
  constexpr std::array version_three_migrations{
      SqliteMigration{1, {}},
      SqliteMigration{2, anvil::store::detail::domain_schema_v2},
      SqliteMigration{3, anvil::store::detail::invite_economics_v3},
  };
  auto old = anvil::store::detail::open_sqlite_store(database.path(),
                                                     version_three_migrations);
  REQUIRE(old.has_value());
  auto seed = (*old)->begin(TransactionMode::read_write);
  REQUIRE(seed.has_value());
  REQUIRE((*old)
              ->execute_for_testing(
                  *seed,
                  "INSERT INTO users(handle,status,created_at) VALUES"
                  "('alice','active',1);"
                  "INSERT INTO boards(board_id,name,title,created_at) VALUES"
                  "('00000000-0000-0000-0000-000000000001','general',"
                  "'General',2);"
                  "INSERT INTO threads(thread_id,board_id,author_handle,"
                  "subject,created_at,updated_at) VALUES"
                  "('thread-1','00000000-0000-0000-0000-000000000001',"
                  "'alice','Welcome',3,3);"
                  "INSERT INTO messages(message_id,board_id,thread_id,"
                  "author_handle,body,posted_at,received_at) VALUES"
                  "('message-b','00000000-0000-0000-0000-000000000001',"
                  "'thread-1','alice','second',4,5),"
                  "('message-a','00000000-0000-0000-0000-000000000001',"
                  "'thread-1','alice','first',4,5);"
                  "INSERT INTO reports(report_id,reporter_handle,target_kind,"
                  "target_id,evidence,created_at) VALUES"
                  "('report-1','alice','message','message-a','reason',6)")
              .has_value());
  REQUIRE(seed->commit().has_value());
  old->reset();

  auto upgraded = SqliteStore::open(database.path());
  REQUIRE(upgraded.has_value());
  CHECK((*upgraded)->schema_version() == 5);
  auto read = (*upgraded)->begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  CHECK((*upgraded)->scalar_for_testing(
            *read, "SELECT guest_readable FROM boards") == 1);
  CHECK((*upgraded)->scalar_text_for_testing(
            *read,
            "SELECT group_concat(message_id, ',') FROM "
            "(SELECT message_id FROM messages ORDER BY local_sequence)") ==
        "message-a,message-b");
  CHECK((*upgraded)->scalar_text_for_testing(
            *read, "SELECT reporter_kind || ':' || reporter_handle || ':' || "
                   "evidence FROM reports") == "registered:alice:reason");
  CHECK((*upgraded)->scalar_for_testing(
            *read, "SELECT count(*) FROM pragma_foreign_key_check") == 0);
}

TEST_CASE("SQLite upgrades the claimed version-one database") {
  TemporaryDatabase database;
  constexpr std::array claimed{SqliteMigration{1, {}}};
  auto version_one =
      anvil::store::detail::open_sqlite_store(database.path(), claimed);
  REQUIRE(version_one.has_value());
  CHECK((*version_one)->schema_version() == 1);
  version_one->reset();

  auto upgraded = SqliteStore::open(database.path());

  REQUIRE(upgraded.has_value());
  CHECK((*upgraded)->schema_version() == 5);
  auto transaction = (*upgraded)->begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());
  CHECK((*upgraded)->scalar_for_testing(
            *transaction,
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND "
            "name NOT LIKE 'sqlite_%'") == 19);
}

TEST_CASE("domain schema preserves federation-safe storage contracts") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  auto transaction = (*store)->begin(TransactionMode::read_write);
  REQUIRE(transaction.has_value());

  CHECK((*store)->scalar_for_testing(
            *transaction,
            "SELECT count(*) FROM pragma_table_info('messages') WHERE "
            "(name IN ('posted_at', 'received_at') AND type = 'INTEGER') OR "
            "(name = 'body' AND type = 'TEXT') OR name = 'status'") == 4);
  CHECK((*store)->scalar_for_testing(
            *transaction,
            "SELECT count(*) FROM pragma_table_info('plugin_state') WHERE "
            "name IN ('plugin_id', 'user_handle', 'user_origin')") == 3);
  CHECK((*store)->scalar_for_testing(
            *transaction,
            "SELECT count(*) FROM pragma_table_info('presence') WHERE "
            "name = 'screen'") == 0);
  CHECK((*store)->scalar_for_testing(
            *transaction,
            "SELECT count(*) FROM sqlite_schema AS schema, "
            "pragma_table_info(schema.name) AS column WHERE "
            "schema.type = 'table' AND schema.name NOT LIKE 'sqlite_%' AND "
            "column.name GLOB '*_at' AND column.type != 'INTEGER'") == 0);
  CHECK((*store)->scalar_for_testing(
            *transaction, "SELECT count(*) FROM pragma_foreign_key_check") ==
        0);
  constexpr std::array tombstoned_content{
      "boards",       "threads",   "messages", "files",
      "leaderboards", "oneliners", "blocks",   "reports",
  };
  for (const std::string_view table : tombstoned_content) {
    CAPTURE(table);
    CHECK((*store)->scalar_for_testing(
              *transaction, "SELECT count(*) FROM pragma_table_info('" +
                                std::string(table) +
                                "') WHERE name = 'status'") == 1);
  }

  REQUIRE((*store)
              ->execute_for_testing(
                  *transaction,
                  "INSERT INTO users(handle, origin, status, created_at) "
                  "VALUES('alice', NULL, 'active', 10),"
                  "('alice', 'remote.example', 'active', 11)")
              .has_value());
  const auto duplicate_local = (*store)->execute_for_testing(
      *transaction, "INSERT INTO users(handle, origin, status, created_at) "
                    "VALUES('alice', NULL, 'active', 12)");
  REQUIRE_FALSE(duplicate_local.has_value());
  CHECK(duplicate_local.error().code == ErrorCode::constraint_violation);

  const auto orphan_key = (*store)->execute_for_testing(
      *transaction,
      "INSERT INTO user_keys(fingerprint, user_handle, public_key, added_at) "
      "VALUES('SHA256:orphan', 'missing', 'ssh-ed25519 AAAA', 12)");
  REQUIRE_FALSE(orphan_key.has_value());
  CHECK(orphan_key.error().code == ErrorCode::constraint_violation);

  const auto empty_origin = (*store)->execute_for_testing(
      *transaction,
      "INSERT INTO user_keys(fingerprint, user_handle, user_origin, "
      "public_key, added_at) VALUES('SHA256:empty-origin', 'alice', '', "
      "'ssh-ed25519 AAAA', 12)");
  REQUIRE_FALSE(empty_origin.has_value());
  CHECK(empty_origin.error().code == ErrorCode::constraint_violation);

  const auto invalid_board = (*store)->execute_for_testing(
      *transaction,
      "INSERT INTO boards(board_id, name, title, status, created_at) "
      "VALUES('not-a-guid', 'general', 'General', 'active', 13)");
  REQUIRE_FALSE(invalid_board.has_value());
  CHECK(invalid_board.error().code == ErrorCode::constraint_violation);

  const auto extra_hyphen_board = (*store)->execute_for_testing(
      *transaction,
      "INSERT INTO boards(board_id, name, title, status, created_at) "
      "VALUES('-0000000-0000-0000-0000-000000000001', 'general', "
      "'General', 'active', 13)");
  REQUIRE_FALSE(extra_hyphen_board.has_value());
  CHECK(extra_hyphen_board.error().code == ErrorCode::constraint_violation);

  const auto invalid_status = (*store)->execute_for_testing(
      *transaction,
      "INSERT INTO boards(board_id, name, title, status, created_at) "
      "VALUES('00000000-0000-0000-0000-000000000001', 'general', "
      "'General', 'deleted', 13)");
  REQUIRE_FALSE(invalid_status.has_value());
  CHECK(invalid_status.error().code == ErrorCode::constraint_violation);

  REQUIRE((*store)
              ->execute_for_testing(
                  *transaction,
                  "INSERT INTO boards(board_id, name, title, created_at) "
                  "VALUES('00000000-0000-0000-0000-000000000001', "
                  "'general', 'General', 13);"
                  "INSERT INTO threads(thread_id, board_id, author_handle, "
                  "subject, created_at, updated_at) VALUES('thread-1', "
                  "'00000000-0000-0000-0000-000000000001', 'alice', "
                  "'Welcome', 14, 14);"
                  "INSERT INTO messages(message_id, board_id, thread_id, "
                  "author_handle, body, posted_at, received_at) VALUES("
                  "'message-1', '00000000-0000-0000-0000-000000000001', "
                  "'thread-1', 'alice', 'hello', 15, 16)")
              .has_value());
  REQUIRE((*store)
              ->execute_for_testing(
                  *transaction,
                  "INSERT INTO reports(report_id, reporter_handle, "
                  "target_kind, target_id, target_origin, created_at) "
                  "VALUES('report-1', 'alice', 'user', 'alice', "
                  "'remote.example', 16);"
                  "INSERT INTO moderation_log(entry_id, moderator_handle, "
                  "action, target_kind, target_id, target_origin, "
                  "created_at) VALUES('moderation-1', 'alice', 'warn', "
                  "'user', 'alice', 'remote.example', 17)")
              .has_value());
  const auto orphan_user_target = (*store)->execute_for_testing(
      *transaction,
      "INSERT INTO moderation_log(entry_id, moderator_handle, action, "
      "target_kind, target_id, target_origin, created_at) VALUES("
      "'moderation-2', 'alice', 'warn', 'user', 'missing', "
      "'remote.example', 18)");
  REQUIRE_FALSE(orphan_user_target.has_value());
  CHECK(orphan_user_target.error().code == ErrorCode::constraint_violation);
  const auto duplicate_message = (*store)->execute_for_testing(
      *transaction,
      "INSERT INTO messages(message_id, board_id, thread_id, author_handle, "
      "body, posted_at, received_at) VALUES('message-1', "
      "'00000000-0000-0000-0000-000000000001', 'thread-1', 'alice', "
      "'again', 17, 18)");
  REQUIRE_FALSE(duplicate_message.has_value());
  CHECK(duplicate_message.error().code == ErrorCode::constraint_violation);
}

TEST_CASE("SQLite ordinary reads cannot reveal tombstoned messages") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  auto transaction = (*store)->begin(TransactionMode::read_write);
  REQUIRE(transaction.has_value());
  seed_messages(**store, *transaction);

  const auto before = (*store)->find_message(*transaction, "message-1");
  REQUIRE(before.has_value());
  REQUIRE(before->has_value());
  CHECK((*before)->body == "first");
  const auto before_list =
      (*store)->list_messages_for_board(*transaction, board_id);
  REQUIRE(before_list.has_value());
  REQUIRE(before_list->size() == 2);
  CHECK(before_list->front().message_id == "message-1");

  const ContentRef message{ContentKind::message, std::string("message-1")};
  CHECK((*store)->tombstone(*transaction, message).has_value());
  CHECK((*store)->tombstone(*transaction, message).has_value());
  CHECK_FALSE((*store)->find_message(*transaction, "message-1")->has_value());
  const auto filtered =
      (*store)->list_messages_for_board(*transaction, board_id);
  REQUIRE(filtered.has_value());
  REQUIRE(filtered->size() == 1);
  CHECK(filtered->front().message_id == "message-2");

  const auto retained =
      (*store)->find_message_including_tombstones(*transaction, "message-1");
  REQUIRE(retained.has_value());
  REQUIRE(retained->has_value());
  CHECK((*retained)->body == "first");
  CHECK((*retained)->status == ContentStatus::tombstoned);
  CHECK(
      (*store)
          ->list_messages_for_board_including_tombstones(*transaction, board_id)
          ->size() == 2);

  REQUIRE((*store)
              ->tombstone(*transaction,
                          {ContentKind::thread, std::string("thread-1")})
              .has_value());
  CHECK_FALSE((*store)->find_message(*transaction, "message-2")->has_value());
  CHECK((*store)
            ->find_message_including_tombstones(*transaction, "message-2")
            ->has_value());
  CHECK(transaction->commit().has_value());
}

TEST_CASE("SQLite tombstones every content kind without deleting rows") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  auto transaction = (*store)->begin(TransactionMode::read_write);
  REQUIRE(transaction.has_value());
  REQUIRE((*store)
              ->execute_for_testing(
                  *transaction,
                  "INSERT INTO users(handle, status, created_at) VALUES"
                  "('alice', 'active', 10),('bob', 'active', 10);"
                  "INSERT INTO boards(board_id, name, title, created_at) "
                  "VALUES('00000000-0000-0000-0000-000000000001', "
                  "'general', 'General', 11);"
                  "INSERT INTO threads(thread_id, board_id, author_handle, "
                  "subject, created_at, updated_at) VALUES('thread-1', "
                  "'00000000-0000-0000-0000-000000000001', 'alice', "
                  "'Welcome', 12, 12);"
                  "INSERT INTO messages(message_id, board_id, thread_id, "
                  "author_handle, body, posted_at, received_at) VALUES("
                  "'message-1', "
                  "'00000000-0000-0000-0000-000000000001', 'thread-1', "
                  "'alice', 'hello', 13, 14);"
                  "INSERT INTO files(file_id, board_id, uploader_handle, "
                  "name, storage_path, content_hash, byte_count, published_at) "
                  "VALUES('file-1', "
                  "'00000000-0000-0000-0000-000000000001', 'alice', "
                  "'readme.txt', '/files/readme.txt', 'sha256:1', 4, 15);"
                  "INSERT INTO plugins(plugin_id, author, version, updated_at) "
                  "VALUES('org.example.game', 'Example', '1.0.0', 16);"
                  "INSERT INTO leaderboards(entry_id, plugin_id, user_handle, "
                  "board_id, category, score, submitted_at) VALUES("
                  "'entry-1', 'org.example.game', 'alice', "
                  "'00000000-0000-0000-0000-000000000001', 'score', 10, 17);"
                  "INSERT INTO oneliners(oneliner_id, author_handle, body, "
                  "posted_at, received_at) VALUES('oneliner-1', 'alice', "
                  "'hi', 18, 18);"
                  "INSERT INTO blocks(block_id, blocker_handle, "
                  "blocked_handle, created_at) VALUES(1, 'alice', 'bob', 19);"
                  "INSERT INTO reports(report_id, reporter_handle, "
                  "target_kind, target_id, status, created_at) VALUES("
                  "'report-1', 'alice', 'message', 'message-1', "
                  "'resolved', 20)")
              .has_value());

  struct Case {
    ContentRef content;
    std::string_view status_query;
  };
  const std::array cases{
      Case{{ContentKind::board, std::string(board_id)},
           "SELECT count(*) FROM boards WHERE board_id="
           "'00000000-0000-0000-0000-000000000001' AND "
           "status='tombstoned'"},
      Case{{ContentKind::thread, std::string("thread-1")},
           "SELECT count(*) FROM threads WHERE thread_id='thread-1' AND "
           "status='tombstoned'"},
      Case{{ContentKind::message, std::string("message-1")},
           "SELECT count(*) FROM messages WHERE message_id='message-1' AND "
           "status='tombstoned'"},
      Case{{ContentKind::file, std::string("file-1")},
           "SELECT count(*) FROM files WHERE file_id='file-1' AND "
           "status='tombstoned'"},
      Case{{ContentKind::leaderboard_entry, std::string("entry-1")},
           "SELECT count(*) FROM leaderboards WHERE entry_id='entry-1' AND "
           "status='tombstoned'"},
      Case{{ContentKind::oneliner, std::string("oneliner-1")},
           "SELECT count(*) FROM oneliners WHERE oneliner_id='oneliner-1' "
           "AND status='tombstoned'"},
      Case{{ContentKind::block, std::int64_t{1}},
           "SELECT count(*) FROM blocks WHERE block_id=1 AND "
           "status='tombstoned'"},
      Case{{ContentKind::report, std::string("report-1")},
           "SELECT count(*) FROM reports WHERE report_id='report-1' AND "
           "status='tombstoned'"},
  };

  for (const auto &test : cases) {
    REQUIRE((*store)->tombstone(*transaction, test.content).has_value());
    CHECK((*store)->scalar_for_testing(*transaction, test.status_query) == 1);
  }
  CHECK((*store)->scalar_for_testing(
            *transaction,
            "SELECT count(*) FROM boards,threads,messages,files,leaderboards,"
            "oneliners,blocks,reports") == 1);
}

TEST_CASE("SQLite tombstone failures are values and rollback is atomic") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  {
    auto seed = (*store)->begin(TransactionMode::read_write);
    REQUIRE(seed.has_value());
    seed_messages(**store, *seed);
    REQUIRE(seed->commit().has_value());
  }

  auto read = (*store)->begin(TransactionMode::read_only);
  REQUIRE(read.has_value());
  const auto read_only = (*store)->tombstone(
      *read, {ContentKind::message, std::string("message-1")});
  REQUIRE_FALSE(read_only.has_value());
  CHECK(read_only.error().code == ErrorCode::invalid_state);
  read->rollback();

  {
    auto write = (*store)->begin(TransactionMode::read_write);
    REQUIRE(write.has_value());
    const auto missing = (*store)->tombstone(
        *write, {ContentKind::message, std::string("x'; DROP TABLE users;--")});
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error().code == ErrorCode::not_found);
    const auto wrong_type =
        (*store)->tombstone(*write, {ContentKind::message, std::int64_t{1}});
    REQUIRE_FALSE(wrong_type.has_value());
    CHECK(wrong_type.error().code == ErrorCode::invalid_data);
    REQUIRE((*store)
                ->tombstone(*write,
                            {ContentKind::message, std::string("message-1")})
                .has_value());
  }

  auto verify = (*store)->begin(TransactionMode::read_only);
  REQUIRE(verify.has_value());
  CHECK((*store)->find_message(*verify, "message-1")->has_value());
  CHECK((*store)->scalar_for_testing(
            *verify, "SELECT count(*) FROM sqlite_schema WHERE name='users'") ==
        1);
}

TEST_CASE("SQLite one-liners enforce rate, order, reports, and retention") {
  TemporaryDatabase database;
  auto store = SqliteStore::open(database.path());
  REQUIRE(store.has_value());
  {
    auto seed = (*store)->begin(TransactionMode::read_write);
    REQUIRE(seed.has_value());
    REQUIRE((*store)
                ->execute_for_testing(
                    *seed, "INSERT INTO users(handle,status,created_at) "
                           "VALUES('alice','active',1),('bob','active',1)")
                .has_value());
    REQUIRE(seed->commit().has_value());
  }
  constexpr OnelinerPolicy policy{
      .max_posts = 3, .window_seconds = 300, .retention_seconds = 1'209'600};
  const auto post = [&](std::string id, std::string handle, std::int64_t at) {
    auto write = (*store)->begin(TransactionMode::read_write);
    REQUIRE(write.has_value());
    auto created =
        (*store)->create_oneliner(*write,
                                  {.oneliner_id = std::move(id),
                                   .author_handle = std::move(handle),
                                   .body = "hello wall",
                                   .posted_at = {at},
                                   .received_at = {at}},
                                  policy);
    if (created) {
      REQUIRE(write->commit().has_value());
    }
    return created;
  };

  REQUIRE(post("line-a", "alice", 100).has_value());
  REQUIRE(post("line-b", "alice", 101).has_value());
  REQUIRE(post("line-c", "alice", 102).has_value());
  REQUIRE(post("line-z", "bob", 102).has_value());
  const auto limited = post("line-d", "alice", 103);
  REQUIRE_FALSE(limited.has_value());
  CHECK(limited.error().code == ErrorCode::conflict);

  {
    auto tombstone = (*store)->begin(TransactionMode::read_write);
    REQUIRE(tombstone.has_value());
    REQUIRE((*store)
                ->tombstone(*tombstone,
                            {ContentKind::oneliner, std::string{"line-a"}})
                .has_value());
    REQUIRE(tombstone->commit().has_value());
  }
  REQUIRE(post("line-d", "alice", 103).error().code == ErrorCode::conflict);
  REQUIRE(post("line-e", "alice", 400).has_value());

  {
    auto read = (*store)->begin(TransactionMode::read_only);
    REQUIRE(read.has_value());
    auto visible = (*store)->list_oneliners(*read, {400}, policy, 100);
    REQUIRE(visible.has_value());
    REQUIRE(visible->size() == 4);
    CHECK((*visible)[0].oneliner_id == "line-e");
    CHECK((*visible)[1].oneliner_id == "line-z");
    CHECK((*visible)[2].oneliner_id == "line-c");
    CHECK((*visible)[3].oneliner_id == "line-b");
    REQUIRE(read->commit().has_value());
  }

  {
    auto report = (*store)->begin(TransactionMode::read_write);
    REQUIRE(report.has_value());
    REQUIRE((*store)
                ->submit_report(
                    *report, ReportSubmission{.report_id = "report-line",
                                              .reporter_handle = std::nullopt,
                                              .target = {ContentKind::oneliner,
                                                         std::string{"line-e"}},
                                              .reason = "needs review",
                                              .created_at = {401}})
                .has_value());
    REQUIRE(report->commit().has_value());
  }

  {
    auto purge = (*store)->begin(TransactionMode::read_write);
    REQUIRE(purge.has_value());
    auto purged =
        (*store)->purge_expired_oneliners(*purge, {1'209'702}, policy);
    REQUIRE(purged.has_value());
    CHECK(*purged == 4);
    REQUIRE(purge->commit().has_value());
  }
  auto verify = (*store)->begin(TransactionMode::read_only);
  REQUIRE(verify.has_value());
  CHECK((*store)->scalar_for_testing(*verify,
                                     "SELECT count(*) FROM oneliners") == 1);
  CHECK((*store)->scalar_for_testing(
            *verify,
            "SELECT count(*) FROM reports WHERE target_kind='oneliner' AND "
            "target_id='line-e'") == 1);
  const auto minimum_time = (*store)->list_oneliners(
      *verify, {std::numeric_limits<std::int64_t>::min()}, policy, 100);
  REQUIRE(minimum_time.has_value());
  CHECK(minimum_time->size() == 1);
}

TEST_CASE("SQLite migrations are ordered and atomic") {
  TemporaryDatabase database;
  constexpr std::array migrations{
      SqliteMigration{1, "CREATE TABLE probe(value INTEGER NOT NULL)"},
      SqliteMigration{2, "INSERT INTO probe(value) VALUES(7)"},
  };

  auto store =
      anvil::store::detail::open_sqlite_store(database.path(), migrations);

  REQUIRE(store.has_value());
  CHECK((*store)->schema_version() == 2);
  auto transaction = (*store)->begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());
  CHECK((*store)->scalar_for_testing(*transaction, "SELECT value FROM probe") ==
        7);
  CHECK(transaction->commit().has_value());
}

TEST_CASE("a failed SQLite migration rolls back the whole pending chain") {
  TemporaryDatabase database;
  constexpr std::array broken{
      SqliteMigration{1, "CREATE TABLE probe(value INTEGER NOT NULL)"},
      SqliteMigration{2, "THIS IS NOT SQL"},
  };

  const auto failed =
      anvil::store::detail::open_sqlite_store(database.path(), broken);

  REQUIRE_FALSE(failed.has_value());
  auto recovered = open_probe(database.path());
  REQUIRE(recovered.has_value());
  auto transaction = (*recovered)->begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());
  CHECK((*recovered)
            ->scalar_for_testing(*transaction, "SELECT count(*) FROM probe") ==
        0);
  CHECK(transaction->commit().has_value());
}

TEST_CASE("SQLite startup rejects newer and foreign databases") {
  SECTION("newer schema") {
    TemporaryDatabase database;
    auto store = SqliteStore::open(database.path());
    REQUIRE(store.has_value());
    auto transaction = (*store)->begin(TransactionMode::read_write);
    REQUIRE(transaction.has_value());
    REQUIRE((*store)
                ->execute_for_testing(*transaction, "PRAGMA user_version=6")
                .has_value());
    REQUIRE(transaction->commit().has_value());

    const auto reopened = SqliteStore::open(database.path());
    REQUIRE_FALSE(reopened.has_value());
    CHECK(reopened.error().code == ErrorCode::invalid_data);
  }

  SECTION("foreign application ID") {
    TemporaryDatabase database;
    auto store = SqliteStore::open(database.path());
    REQUIRE(store.has_value());
    auto transaction = (*store)->begin(TransactionMode::read_write);
    REQUIRE(transaction.has_value());
    REQUIRE((*store)
                ->execute_for_testing(*transaction, "PRAGMA application_id=1")
                .has_value());
    REQUIRE(transaction->commit().has_value());

    const auto reopened = SqliteStore::open(database.path());
    REQUIRE_FALSE(reopened.has_value());
    CHECK(reopened.error().code == ErrorCode::invalid_data);
  }
}

TEST_CASE("SQLite refuses non-persistent and symlink database paths") {
  const auto in_memory = SqliteStore::open(":memory:");
  REQUIRE_FALSE(in_memory.has_value());
  CHECK(in_memory.error().code == ErrorCode::invalid_data);

  TemporaryDatabase database;
  REQUIRE(SqliteStore::open(database.path()).has_value());
  const auto link = database.directory() / "linked.db";
  std::filesystem::create_symlink(database.path(), link);

  const auto linked = SqliteStore::open(link);
  REQUIRE_FALSE(linked.has_value());
  CHECK(linked.error().code == ErrorCode::unavailable);
}

TEST_CASE("WAL readers and writers use independent transaction connections") {
  TemporaryDatabase database;
  auto reader_store = open_probe(database.path());
  auto writer_store = open_probe(database.path());
  REQUIRE(reader_store.has_value());
  REQUIRE(writer_store.has_value());

  auto slow_reader = (*reader_store)->begin(TransactionMode::read_only);
  REQUIRE(slow_reader.has_value());
  REQUIRE((*reader_store)
              ->scalar_for_testing(*slow_reader,
                                   "SELECT count(*) FROM probe") == 0);

  auto writer = (*writer_store)->begin(TransactionMode::read_write);
  REQUIRE(writer.has_value());
  REQUIRE(
      (*writer_store)
          ->execute_for_testing(*writer, "INSERT INTO probe(value) VALUES(1)")
          .has_value());
  CHECK(writer->commit().has_value());
  CHECK((*reader_store)
            ->scalar_for_testing(*slow_reader, "SELECT count(*) FROM probe") ==
        0);
  CHECK(slow_reader->commit().has_value());

  auto uncommitted_writer = (*writer_store)->begin(TransactionMode::read_write);
  REQUIRE(uncommitted_writer.has_value());
  REQUIRE((*writer_store)
              ->execute_for_testing(*uncommitted_writer,
                                    "INSERT INTO probe(value) VALUES(2)")
              .has_value());
  auto unrelated_reader = (*reader_store)->begin(TransactionMode::read_only);
  REQUIRE(unrelated_reader.has_value());
  CHECK((*reader_store)
            ->scalar_for_testing(*unrelated_reader,
                                 "SELECT count(*) FROM probe") == 1);
  CHECK(unrelated_reader->commit().has_value());
  uncommitted_writer->rollback();
}

TEST_CASE("a competing SQLite writer times out as a conflict") {
  TemporaryDatabase database;
  const SqliteOptions short_wait{50ms};
  auto first = open_probe(database.path(), short_wait);
  auto second = open_probe(database.path(), short_wait);
  REQUIRE(first.has_value());
  REQUIRE(second.has_value());

  auto held = (*first)->begin(TransactionMode::read_write);
  REQUIRE(held.has_value());
  const auto blocked = (*second)->begin(TransactionMode::read_write);

  REQUIRE_FALSE(blocked.has_value());
  CHECK(blocked.error().code == ErrorCode::conflict);
  held->rollback();
}

TEST_CASE("read-only SQLite transactions reject writes") {
  TemporaryDatabase database;
  auto store = open_probe(database.path());
  REQUIRE(store.has_value());
  auto transaction = (*store)->begin(TransactionMode::read_only);
  REQUIRE(transaction.has_value());

  const auto written = (*store)->execute_for_testing(
      *transaction, "INSERT INTO probe(value) VALUES(1)");

  REQUIRE_FALSE(written.has_value());
  CHECK(written.error().code == ErrorCode::unavailable);
}

TEST_CASE(
    "a SQLite store constructed before fork opens only child-local handles") {
  TemporaryDatabase database;
  auto store = open_probe(database.path());
  REQUIRE(store.has_value());

  const auto child = ::fork();
  REQUIRE(child >= 0);
  if (child == 0) {
    auto transaction = (*store)->begin(TransactionMode::read_only);
    const bool passed = transaction.has_value() &&
                        (*store)->scalar_for_testing(
                            *transaction, "SELECT count(*) FROM probe") == 0 &&
                        transaction->commit().has_value();
    ::_exit(passed ? 0 : 1);
  }

  int status = 0;
  REQUIRE(::waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status));
  CHECK(WEXITSTATUS(status) == 0);

  auto parent_transaction = (*store)->begin(TransactionMode::read_only);
  REQUIRE(parent_transaction.has_value());
  CHECK(parent_transaction->commit().has_value());
}
