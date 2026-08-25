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

extern "C" ANVIL_TEST_EXPORT const TestTag anvil_abi_tag = kExpectedTag;

extern "C" ANVIL_TEST_EXPORT auto anvil_plugin_create() noexcept
    -> TestPlugin * {
  return new ValidPlugin;
}

extern "C" ANVIL_TEST_EXPORT auto
anvil_plugin_destroy(TestPlugin *plugin) noexcept -> void {
  append_event("destroy");
  delete plugin;
}
