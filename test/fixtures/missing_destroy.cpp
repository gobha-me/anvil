#include "events.hpp"
#include "plugin_api.hpp"

ANVIL_PLUGIN_ABI_TAG();

extern "C" ANVIL_TEST_EXPORT auto anvil_plugin_create() noexcept
    -> TestPlugin * {
  append_event("factory");
  return nullptr;
}
