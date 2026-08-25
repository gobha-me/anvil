#pragma once

#include <cstdint>

#if defined(__GNUC__) || defined(__clang__)
#define ANVIL_TEST_EXPORT __attribute__((visibility("default")))
#else
#define ANVIL_TEST_EXPORT
#endif

struct TestTag {
  std::uint32_t magic;
  std::uint32_t interface_version;
};

inline constexpr TestTag kExpectedTag{0x414E564CUL, 1};

class TestPlugin {
public:
  ANVIL_TEST_EXPORT virtual ~TestPlugin();
  [[nodiscard]] virtual auto value() const noexcept -> int = 0;
};
