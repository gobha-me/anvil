#include "plugin_api.hpp"

extern "C" ANVIL_TEST_EXPORT const TestTag anvil_abi_tag = kExpectedTag;

extern "C" ANVIL_TEST_EXPORT auto
anvil_plugin_destroy(TestPlugin *plugin) noexcept -> void {
  delete plugin;
}
