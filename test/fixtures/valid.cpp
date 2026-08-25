#include "events.hpp"
#include "plugin_api.hpp"

namespace {

class ValidPlugin final : public TestPlugin {
public:
  [[nodiscard]] auto value() const noexcept -> int override { return 42; }
};

__attribute__((destructor)) auto on_unload() noexcept -> void {
  append_event("unload");
}

} // namespace

ANVIL_PLUGIN_ABI_TAG();

extern "C" ANVIL_TEST_EXPORT auto anvil_plugin_create() noexcept
    -> TestPlugin * {
  return new ValidPlugin;
}

extern "C" ANVIL_TEST_EXPORT auto
anvil_plugin_destroy(TestPlugin *plugin) noexcept -> void {
  append_event("destroy");
  delete plugin;
}
