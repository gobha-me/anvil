#pragma once

#include <anvil/sdk/abi.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
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

struct InterfaceVersionRange {
  InterfaceVersion minimum;
  InterfaceVersion maximum;
};

inline constexpr std::array<InterfaceVersionRange, 1>
    kAcceptedPluginInterfaceVersions{InterfaceVersionRange{
        kPluginInterfaceVersion, kPluginInterfaceVersion}};

[[nodiscard]] auto supports_interface_version(
    InterfaceVersion version,
    std::span<const InterfaceVersionRange> accepted) noexcept -> bool;

[[nodiscard]] auto verify_abi_tag(const AnvilAbiTag &expected,
                                  const AnvilAbiTag &found,
                                  std::size_t readable_size)
    -> std::expected<void, std::string>;

[[nodiscard]] constexpr auto
abi_tag_declared_size(const AnvilAbiTag &tag) noexcept -> std::size_t {
  return tag.struct_size;
}

[[nodiscard]] constexpr auto
abi_tag_field_available(const AnvilAbiTag &tag, std::size_t available_size,
                        std::size_t offset, std::size_t field_size) noexcept
    -> bool {
  return offset <= available_size && field_size <= available_size - offset &&
         offset <= tag.struct_size && field_size <= tag.struct_size - offset;
}

// The instance keeps the DSO mapped independently of the returned handle.
template <typename Interface> struct Loaded {
  Handle handle;
  std::shared_ptr<Interface> instance;
};

template <typename Tag>
using TagVerifier = auto (*)(const Tag &expected, const Tag &found,
                             std::size_t readable_size)
    -> std::expected<void, std::string>;

template <typename Tag>
using TagSizeReader = auto (*)(const Tag &prefix) noexcept -> std::size_t;

template <typename Tag> struct AbiRequirement {
  Tag expected;
  TagVerifier<Tag> verify{};
  // The plugin's data symbol may be shorter than Tag when later versions only
  // append fields. Missing trailing bytes are copied as zero.
  std::size_t minimum_size{sizeof(Tag)};
  // When supplied, this reads the tag's logical size from the already-copied
  // prefix. It prevents sanitizer padding in the ELF symbol from being treated
  // as tag data.
  TagSizeReader<Tag> declared_size{};
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
  if (requirement.minimum_size == 0 || requirement.minimum_size > sizeof(Tag)) {
    return std::unexpected(
        Error{ErrorCode::invalid_request, plugin, symbols.abi_tag,
              "the minimum ABI tag size must be between 1 and sizeof(Tag)"});
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
  if (*tag_size < requirement.minimum_size) {
    return std::unexpected(Error{ErrorCode::abi_rejected, plugin,
                                 symbols.abi_tag,
                                 "the ABI tag is " + std::to_string(*tag_size) +
                                     " bytes; expected at least " +
                                     std::to_string(requirement.minimum_size)});
  }

  Tag found{};
  std::memcpy(&found, *tag_symbol, requirement.minimum_size);
  auto readable_size = *tag_size;
  if (requirement.declared_size != nullptr) {
    readable_size = requirement.declared_size(found);
    if (readable_size < requirement.minimum_size || readable_size > *tag_size) {
      return std::unexpected(Error{
          ErrorCode::abi_rejected, plugin, symbols.abi_tag,
          "the ABI tag declares " + std::to_string(readable_size) +
              " bytes, but its symbol contains " + std::to_string(*tag_size)});
    }
  }
  std::memcpy(&found, *tag_symbol, std::min(readable_size, sizeof(found)));
  auto verified =
      requirement.verify(requirement.expected, found, readable_size);
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
