#pragma once

#include <anvil/sdk/abi.hpp>
#include <anvil/sdk/plugin.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace anvil::sdk {

[[nodiscard]] inline auto as_str(std::string_view value) noexcept -> Str {
  return Str{value.data(), static_cast<uint64_t>(value.size())};
}

[[nodiscard]] inline auto as_str(const std::string &value) noexcept -> Str {
  return as_str(std::string_view{value});
}

auto as_str(std::string &&) -> Str = delete;

template <std::size_t Size>
[[nodiscard]] constexpr auto as_str(const char (&value)[Size]) noexcept -> Str {
  const auto length = Size != 0 && value[Size - 1] == '\0' ? Size - 1 : Size;
  return Str{value, static_cast<uint64_t>(length)};
}

[[nodiscard]] inline auto as_str(const char *value) -> Str {
  if (value == nullptr) {
    throw std::invalid_argument{"a string borrow cannot have a null pointer"};
  }
  return as_str(std::string_view{value});
}

[[nodiscard]] inline auto as_string_view(Str value) -> std::string_view {
  if (value.data == nullptr && value.len != 0) {
    throw std::invalid_argument{
        "a non-empty string borrow cannot have a null pointer"};
  }
  if (value.len > std::numeric_limits<std::size_t>::max()) {
    throw std::length_error{"a string borrow is too large for this host"};
  }
  return std::string_view{value.data == nullptr ? "" : value.data,
                          static_cast<std::size_t>(value.len)};
}

template <typename Range>
concept StableContiguousRange =
    std::ranges::contiguous_range<Range> && std::ranges::sized_range<Range> &&
    std::is_trivially_copyable_v<
        std::remove_cv_t<std::ranges::range_value_t<Range>>> &&
    std::is_standard_layout_v<
        std::remove_cv_t<std::ranges::range_value_t<Range>>>;

template <typename Range>
  requires StableContiguousRange<Range> && std::is_lvalue_reference_v<Range &&>
[[nodiscard]] auto as_span(Range &&value)
    -> Span<std::remove_reference_t<std::ranges::range_reference_t<Range>>> {
  using Element =
      std::remove_reference_t<std::ranges::range_reference_t<Range>>;
  const auto size = std::ranges::size(value);
  if (size > std::numeric_limits<uint64_t>::max()) {
    throw std::length_error{"a range is too large for an Anvil span"};
  }
  return Span<Element>{std::ranges::data(value), static_cast<uint64_t>(size)};
}

template <typename Range>
  requires StableContiguousRange<Range> &&
               (!std::is_lvalue_reference_v<Range &&>)
auto as_span(Range &&) = delete;

template <typename Element>
[[nodiscard]] auto as_std_span(Span<Element> value) -> std::span<Element> {
  if (value.data == nullptr && value.len != 0) {
    throw std::invalid_argument{
        "a non-empty span borrow cannot have a null pointer"};
  }
  if (value.len > std::numeric_limits<std::size_t>::max()) {
    throw std::length_error{"a span borrow is too large for this host"};
  }
  return std::span<Element>{value.data, static_cast<std::size_t>(value.len)};
}

struct PluginManifest {
  std::string id;
  std::string name;
  std::string description;
  std::string author;
  Version version;
  PluginKind kind{PluginKind::door};
};

struct DoorManifest {
  CapabilityTier min_tier{CapabilityTier::teletype};
  bool persists_state{};
  bool has_leaderboard{};
  bool audio_enhanced{};
};

class DoorContext {
public:
  explicit DoorContext(const ::anvil::DoorContext &value) noexcept
      : m_value{value} {}

  [[nodiscard]] auto user() const noexcept -> UserId { return m_value.user; }
  [[nodiscard]] auto capabilities() const noexcept -> Capabilities {
    return m_value.caps;
  }
  [[nodiscard]] auto limits() const noexcept -> ResourceLimits {
    return m_value.limits;
  }
  [[nodiscard]] auto session() const noexcept -> ISession * {
    return m_value.session;
  }
  [[nodiscard]] auto state() const noexcept -> IStateStore * {
    return m_value.state;
  }

private:
  ::anvil::DoorContext m_value;
};

template <typename Implementation> class Door : public IDoor {
public:
  Door(PluginManifest plugin, DoorManifest door)
      : m_plugin{std::move(plugin)}, m_door{door} {}

protected:
  ~Door() noexcept override = default;

private:
  [[nodiscard]] auto manifest(::anvil::PluginManifest *output) const noexcept
      -> PluginStatus final {
    if (output == nullptr) {
      return PluginStatus::invalid_argument;
    }
    try {
      *output = ::anvil::PluginManifest{
          sizeof(::anvil::PluginManifest),
          PluginId{as_str(m_plugin.id)},
          as_str(m_plugin.name),
          as_str(m_plugin.description),
          as_str(m_plugin.author),
          m_plugin.version,
          m_plugin.kind,
      };
      return PluginStatus::ok;
    } catch (...) {
      return PluginStatus::exception;
    }
  }

  [[nodiscard]] auto door_manifest(::anvil::DoorManifest *output) const noexcept
      -> PluginStatus final {
    if (output == nullptr) {
      return PluginStatus::invalid_argument;
    }
    try {
      *output = ::anvil::DoorManifest{
          sizeof(::anvil::DoorManifest),
          m_door.min_tier,
          static_cast<uint8_t>(m_door.persists_state),
          static_cast<uint8_t>(m_door.has_leaderboard),
          static_cast<uint8_t>(m_door.audio_enhanced),
          0,
      };
      return PluginStatus::ok;
    } catch (...) {
      return PluginStatus::exception;
    }
  }

  [[nodiscard]] auto run(const ::anvil::DoorContext *context) noexcept
      -> PluginStatus final {
    if (!valid(context)) {
      return PluginStatus::invalid_argument;
    }
    try {
      static_assert(
          std::same_as<decltype(std::declval<Implementation &>().run_door(
                           std::declval<DoorContext>())),
                       void>,
          "a door implementation must provide void "
          "run_door(DoorContext)");
      static_cast<Implementation &>(*this).run_door(DoorContext{*context});
      return PluginStatus::ok;
    } catch (...) {
      return PluginStatus::exception;
    }
  }

  [[nodiscard]] static auto valid(const ::anvil::DoorContext *context) noexcept
      -> bool {
    return context != nullptr &&
           context->struct_size >= sizeof(::anvil::DoorContext) &&
           context->caps.struct_size >= sizeof(Capabilities) &&
           context->limits.struct_size >= sizeof(ResourceLimits);
  }

  const PluginManifest m_plugin;
  const DoorManifest m_door;
};

} // namespace anvil::sdk

#if defined(__GNUC__) || defined(__clang__)
#define ANVIL_PLUGIN(Type)                                                     \
  ANVIL_PLUGIN_ABI_TAG();                                                      \
  extern "C" __attribute__((visibility("default"))) auto                       \
  anvil_plugin_create() noexcept -> ::anvil::IPlugin * {                       \
    static_assert(std::derived_from<Type, ::anvil::IPlugin>);                  \
    static_assert(std::is_nothrow_destructible_v<Type>);                       \
    try {                                                                      \
      return new Type{};                                                       \
    } catch (...) {                                                            \
      return nullptr;                                                          \
    }                                                                          \
  }                                                                            \
  extern "C" __attribute__((visibility("default"))) void anvil_plugin_destroy( \
      ::anvil::IPlugin *plugin) noexcept {                                     \
    delete static_cast<Type *>(plugin);                                        \
  }
#else
#define ANVIL_PLUGIN(Type)                                                     \
  ANVIL_PLUGIN_ABI_TAG();                                                      \
  extern "C" auto anvil_plugin_create() noexcept -> ::anvil::IPlugin * {       \
    static_assert(std::derived_from<Type, ::anvil::IPlugin>);                  \
    static_assert(std::is_nothrow_destructible_v<Type>);                       \
    try {                                                                      \
      return new Type{};                                                       \
    } catch (...) {                                                            \
      return nullptr;                                                          \
    }                                                                          \
  }                                                                            \
  extern "C" void anvil_plugin_destroy(::anvil::IPlugin *plugin) noexcept {    \
    delete static_cast<Type *>(plugin);                                        \
  }
#endif
