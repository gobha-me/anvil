#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

namespace anvil::loader {

enum class ErrorCode : std::uint8_t {
  invalid_request,
  open_failed,
  symbol_missing,
  symbol_null,
  abi_rejected,
  factory_returned_null,
};

struct Error {
  ErrorCode code{};
  std::filesystem::path plugin;
  std::string symbol;
  std::string detail;

  [[nodiscard]] auto message() const -> std::string;
};

struct SymbolNames {
  std::string abi_tag{"anvil_abi_tag"};
  std::string create{"anvil_plugin_create"};
  std::string destroy{"anvil_plugin_destroy"};
};

using Handle = std::shared_ptr<void>;

// The instance keeps the DSO mapped independently of the returned handle.
template <typename Interface> struct Loaded {
  Handle handle;
  std::shared_ptr<Interface> instance;
};

template <typename Tag>
using TagVerifier = auto (*)(const Tag &expected, const Tag &found)
    -> std::expected<void, std::string>;

template <typename Tag> struct AbiRequirement {
  // The plugin's data symbol must contain at least sizeof(Tag) readable bytes.
  Tag expected;
  TagVerifier<Tag> verify{};
};

namespace detail {

[[nodiscard]] auto open_library(const std::filesystem::path &plugin)
    -> std::expected<Handle, Error>;

[[nodiscard]] auto find_symbol(const Handle &handle,
                               const std::filesystem::path &plugin,
                               const std::string &symbol)
    -> std::expected<void *, Error>;

[[nodiscard]] auto symbol_storage_size(void *address,
                                       const std::filesystem::path &plugin,
                                       const std::string &symbol)
    -> std::expected<std::size_t, Error>;

template <typename Function>
[[nodiscard]] auto to_function_pointer(void *address) noexcept -> Function {
  static_assert(std::is_pointer_v<Function>);
  static_assert(sizeof(Function) == sizeof(address));

  Function result{};
  std::memcpy(&result, &address, sizeof(result));
  return result;
}

} // namespace detail

template <typename Interface, typename Tag>
[[nodiscard]] auto load(const std::filesystem::path &plugin,
                        const AbiRequirement<Tag> &requirement,
                        const SymbolNames &symbols = {})
    -> std::expected<Loaded<Interface>, Error> {
  static_assert(std::is_trivially_copyable_v<Tag>,
                "an ABI tag must be trivially copyable");
  static_assert(std::is_standard_layout_v<Tag>,
                "an ABI tag must have standard layout");

  if (requirement.verify == nullptr) {
    return std::unexpected(Error{ErrorCode::invalid_request, plugin,
                                 symbols.abi_tag, "the ABI verifier is null"});
  }

  auto handle = detail::open_library(plugin);
  if (!handle)
    return std::unexpected(std::move(handle.error()));

  auto tag_symbol = detail::find_symbol(*handle, plugin, symbols.abi_tag);
  if (!tag_symbol)
    return std::unexpected(std::move(tag_symbol.error()));
  if (*tag_symbol == nullptr) {
    return std::unexpected(
        Error{ErrorCode::symbol_null, plugin, symbols.abi_tag,
              "the ABI tag symbol resolved to address zero"});
  }

  auto tag_size =
      detail::symbol_storage_size(*tag_symbol, plugin, symbols.abi_tag);
  if (!tag_size)
    return std::unexpected(std::move(tag_size.error()));
  if (*tag_size < sizeof(Tag)) {
    return std::unexpected(
        Error{ErrorCode::abi_rejected, plugin, symbols.abi_tag,
              "the ABI tag is " + std::to_string(*tag_size) +
                  " bytes; expected at least " + std::to_string(sizeof(Tag))});
  }

  Tag found{};
  std::memcpy(&found, *tag_symbol, sizeof(found));
  auto verified = requirement.verify(requirement.expected, found);
  if (!verified) {
    return std::unexpected(Error{ErrorCode::abi_rejected, plugin,
                                 symbols.abi_tag, std::move(verified.error())});
  }

  auto destroy_symbol = detail::find_symbol(*handle, plugin, symbols.destroy);
  if (!destroy_symbol) {
    return std::unexpected(std::move(destroy_symbol.error()));
  }
  if (*destroy_symbol == nullptr) {
    return std::unexpected(
        Error{ErrorCode::symbol_null, plugin, symbols.destroy,
              "the destroy symbol resolved to address zero"});
  }

  auto create_symbol = detail::find_symbol(*handle, plugin, symbols.create);
  if (!create_symbol)
    return std::unexpected(std::move(create_symbol.error()));
  if (*create_symbol == nullptr) {
    return std::unexpected(
        Error{ErrorCode::symbol_null, plugin, symbols.create,
              "the factory symbol resolved to address zero"});
  }

  using Create = Interface *(*)() noexcept;
  using Destroy = void (*)(Interface *) noexcept;
  const auto create = detail::to_function_pointer<Create>(*create_symbol);
  const auto destroy = detail::to_function_pointer<Destroy>(*destroy_symbol);

  Interface *raw = create();
  if (raw == nullptr) {
    return std::unexpected(Error{ErrorCode::factory_returned_null, plugin,
                                 symbols.create,
                                 "the plugin factory returned null"});
  }

  auto instance = std::shared_ptr<Interface>{
      raw, [destroy, keep_alive = *handle](Interface *value) noexcept {
        static_cast<void>(keep_alive);
        destroy(value);
      }};

  return Loaded<Interface>{std::move(*handle), std::move(instance)};
}

} // namespace anvil::loader
