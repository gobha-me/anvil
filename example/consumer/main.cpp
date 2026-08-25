#include <anvil/loader.hpp>

#include <cstdint>
#include <expected>
#include <string>

namespace {

struct Tag {
  std::uint32_t magic;
};

struct Plugin {
  virtual ~Plugin() = default;
};

auto verify(const Tag &, const Tag &) -> std::expected<void, std::string> {
  return {};
}

} // namespace

auto main() -> int {
  const auto result = anvil::loader::load<Plugin>(
      "/anvil/consumer/this-plugin-does-not-exist.so",
      anvil::loader::AbiRequirement<Tag>{Tag{0x414E564CUL}, verify});

  return !result && result.error().code == anvil::loader::ErrorCode::open_failed
             ? 0
             : 1;
}
