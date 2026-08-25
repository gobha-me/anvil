#pragma once

#include <anvil/sdk/abi.hpp>

#if defined(__GNUC__) || defined(__clang__)
#define ANVIL_TEST_EXPORT __attribute__((visibility("default")))
#else
#define ANVIL_TEST_EXPORT
#endif

class TestPlugin {
public:
  ANVIL_TEST_EXPORT virtual ~TestPlugin();
  [[nodiscard]] virtual auto value() const noexcept -> int = 0;
};
