#include <anvil/loader.hpp>
#include <anvil/sdk.hpp>
#include <anvil/store.hpp>

#include <expected>
#include <memory>
#include <string>
#include <vector>

namespace anvil {

IPlugin::~IPlugin() noexcept = default;
IDoor::~IDoor() noexcept = default;

} // namespace anvil

namespace {

class ConsumerTransaction final : public anvil::store::TransactionBackend {
public:
  [[nodiscard]] auto commit()
      -> std::expected<void, anvil::store::Error> override {
    return {};
  }
  void rollback() noexcept override {}
};

class ConsumerStore final : public anvil::store::Store {
public:
  [[nodiscard]] auto begin(anvil::store::TransactionMode mode)
      -> std::expected<anvil::store::Transaction,
                       anvil::store::Error> override {
    return make_transaction(mode, std::make_unique<ConsumerTransaction>());
  }

private:
  [[nodiscard]] auto tombstone_impl(anvil::store::Transaction &,
                                    const anvil::store::ContentRef &)
      -> std::expected<void, anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no content backend"});
  }

  [[nodiscard]] auto find_message_impl(anvil::store::Transaction &,
                                       std::string_view, ContentVisibility)
      -> std::expected<std::optional<anvil::store::MessageRecord>,
                       anvil::store::Error> override {
    return std::nullopt;
  }

  [[nodiscard]] auto list_messages_for_board_impl(anvil::store::Transaction &,
                                                  std::string_view,
                                                  ContentVisibility)
      -> std::expected<std::vector<anvil::store::MessageRecord>,
                       anvil::store::Error> override {
    return std::vector<anvil::store::MessageRecord>{};
  }

  [[nodiscard]] auto find_local_credential_impl(anvil::store::Transaction &,
                                                std::string_view)
      -> std::expected<std::optional<anvil::store::CredentialRecord>,
                       anvil::store::Error> override {
    return std::nullopt;
  }

  [[nodiscard]] auto provision_local_credential_impl(
      anvil::store::Transaction &,
      const anvil::store::LocalCredentialProvision &)
      -> std::expected<void, anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no identity backend"});
  }

  [[nodiscard]] auto has_tos_acceptance_impl(anvil::store::Transaction &,
                                             std::string_view, std::string_view)
      -> std::expected<bool, anvil::store::Error> override {
    return false;
  }

  [[nodiscard]] auto accept_tos_impl(anvil::store::Transaction &,
                                     const anvil::store::TosAcceptance &)
      -> std::expected<anvil::store::UserStatus, anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no TOS backend"});
  }

  [[nodiscard]] auto claim_invite_impl(anvil::store::Transaction &,
                                       const anvil::store::InviteClaim &)
      -> std::expected<void, anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no invite backend"});
  }

  [[nodiscard]] auto issue_invite_impl(anvil::store::Transaction &,
                                       const anvil::store::InviteIssue &)
      -> std::expected<anvil::store::InviteIssueResult,
                       anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no invite backend"});
  }

  [[nodiscard]] auto find_inviter_impl(anvil::store::Transaction &,
                                       std::string_view)
      -> std::expected<std::optional<anvil::store::InviteUser>,
                       anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no invite backend"});
  }

  [[nodiscard]] auto list_invite_subtree_impl(anvil::store::Transaction &,
                                              std::string_view)
      -> std::expected<std::vector<anvil::store::InviteDescendant>,
                       anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no invite backend"});
  }

  [[nodiscard]] auto reconcile_board_impl(anvil::store::Transaction &,
                                          const anvil::store::BoardProvision &)
      -> std::expected<anvil::store::BoardRecord,
                       anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no board backend"});
  }

  [[nodiscard]] auto list_boards_impl(anvil::store::Transaction &,
                                      const anvil::store::BoardReader &)
      -> std::expected<std::vector<anvil::store::BoardRecord>,
                       anvil::store::Error> override {
    return std::vector<anvil::store::BoardRecord>{};
  }

  [[nodiscard]] auto list_threads_impl(anvil::store::Transaction &,
                                       std::string_view,
                                       const anvil::store::BoardReader &)
      -> std::expected<std::vector<anvil::store::ThreadRecord>,
                       anvil::store::Error> override {
    return std::vector<anvil::store::ThreadRecord>{};
  }

  [[nodiscard]] auto
  list_messages_for_thread_impl(anvil::store::Transaction &, std::string_view,
                                std::string_view,
                                const anvil::store::BoardReader &)
      -> std::expected<std::vector<anvil::store::MessageRecord>,
                       anvil::store::Error> override {
    return std::vector<anvil::store::MessageRecord>{};
  }

  [[nodiscard]] auto create_thread_impl(anvil::store::Transaction &,
                                        const anvil::store::ThreadCreate &)
      -> std::expected<anvil::store::MessageRecord,
                       anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no board backend"});
  }

  [[nodiscard]] auto create_reply_impl(anvil::store::Transaction &,
                                       const anvil::store::ReplyCreate &)
      -> std::expected<anvil::store::MessageRecord,
                       anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no board backend"});
  }

  [[nodiscard]] auto mark_thread_read_impl(anvil::store::Transaction &,
                                           std::string_view, std::string_view,
                                           std::string_view)
      -> std::expected<void, anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no board backend"});
  }

  [[nodiscard]] auto catch_up_board_impl(anvil::store::Transaction &,
                                         std::string_view, std::string_view)
      -> std::expected<void, anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no board backend"});
  }

  [[nodiscard]] auto submit_report_impl(anvil::store::Transaction &,
                                        const anvil::store::ReportSubmission &)
      -> std::expected<void, anvil::store::Error> override {
    return std::unexpected(
        anvil::store::Error{anvil::store::ErrorCode::unavailable,
                            "consumer fixture has no board backend"});
  }
};

} // namespace

auto main() -> int {
  ConsumerStore store;
  auto transaction = store.begin(anvil::store::TransactionMode::read_only);
  if (!transaction || !transaction->commit()) {
    return 1;
  }

  const std::string text{"external consumer"};
  const auto borrowed = anvil::sdk::as_str(text);
  std::vector<unsigned int> values{1, 2, 3};
  const auto range = anvil::sdk::as_span(values);
  if (anvil::sdk::as_string_view(borrowed) != text || range.len != 3) {
    return 1;
  }

  auto result = anvil::loader::load<anvil::IPlugin>(
      ANVIL_CONSUMER_PLUGIN,
      anvil::loader::AbiRequirement<anvil::AnvilAbiTag>{
          anvil::current_abi_tag, anvil::loader::verify_abi_tag,
          anvil::kAbiTagPrefixSize, anvil::loader::abi_tag_declared_size});
  if (!result) {
    return 1;
  }

  anvil::PluginManifest manifest{};
  if (result->instance->manifest(&manifest) != anvil::PluginStatus::ok ||
      anvil::sdk::as_string_view(manifest.id.value) != "org.example.consumer") {
    return 1;
  }

  auto *door = dynamic_cast<anvil::IDoor *>(result->instance.get());
  return door == nullptr ? 1 : 0;
}
