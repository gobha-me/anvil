#include "events.hpp"
#include "plugin_api.hpp"

extern "C" ANVIL_TEST_EXPORT auto anvil_plugin_create() noexcept
    -> TestPlugin * {
  append_event("factory");
  return nullptr;
}

extern "C" ANVIL_TEST_EXPORT auto
anvil_plugin_destroy(TestPlugin *plugin) noexcept -> void {
  delete plugin;
}
