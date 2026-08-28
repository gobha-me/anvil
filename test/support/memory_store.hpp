#pragma once

#include <anvil/store.hpp>

#include <algorithm>
#include <cstddef>
#include <expected>
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

  struct State {
    std::vector<TransactionObservation> observations;
    std::optional<store::Error> next_commit_error;
    std::vector<ContentEntry> contents;
    std::vector<store::MessageRecord> messages;
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
          contents_(state_->contents), messages_(state_->messages) {}

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

  private:
    std::shared_ptr<State> state_;
    std::size_t index_;
    store::TransactionMode mode_;
    std::vector<ContentEntry> contents_;
    std::vector<store::MessageRecord> messages_;
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

  std::shared_ptr<State> state_;
  std::optional<store::Error> next_begin_error_;
};

} // namespace anvil::testing
