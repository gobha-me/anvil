#pragma once

#include <anvil/store.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace anvil::testing {

struct TransactionObservation {
  store::TransactionMode mode{store::TransactionMode::read_only};
  std::size_t commit_attempts{};
  std::size_t rollbacks{};
};

// Reusable database-free Store implementation for board, moderation, and door
// tests. Domain records will be added alongside the interfaces that own them.
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
    return make_transaction(std::make_unique<Backend>(state_, index));
  }

  void fail_next_begin(store::Error error) {
    next_begin_error_ = std::move(error);
  }

  void fail_next_commit(store::Error error) {
    state_->next_commit_error = std::move(error);
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
    return make_transaction(nullptr);
  }

private:
  struct State {
    std::vector<TransactionObservation> observations;
    std::optional<store::Error> next_commit_error;
  };

  class Backend final : public store::TransactionBackend {
  public:
    Backend(std::shared_ptr<State> state, std::size_t index) noexcept
        : state_(std::move(state)), index_(index) {}

    [[nodiscard]] auto commit() -> std::expected<void, store::Error> override {
      ++state_->observations.at(index_).commit_attempts;
      if (state_->next_commit_error) {
        auto error = std::move(*state_->next_commit_error);
        state_->next_commit_error.reset();
        return std::unexpected(std::move(error));
      }
      return {};
    }

    void rollback() noexcept override {
      ++state_->observations[index_].rollbacks;
    }

  private:
    std::shared_ptr<State> state_;
    std::size_t index_;
  };

  std::shared_ptr<State> state_;
  std::optional<store::Error> next_begin_error_;
};

} // namespace anvil::testing
