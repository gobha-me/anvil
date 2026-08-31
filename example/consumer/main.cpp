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

  [[nodiscard]] auto find_local_credential_impl(
      anvil::store::Transaction &, std::string_view)
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
