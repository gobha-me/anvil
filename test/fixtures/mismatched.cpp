#include "events.hpp"
#include "plugin_api.hpp"

namespace {

class MismatchedPlugin final : public TestPlugin {
public:
  [[nodiscard]] auto value() const noexcept -> int override { return -1; }
};

__attribute__((constructor)) auto on_load() noexcept -> void {
  append_event("initializer");
}

} // namespace

extern "C" ANVIL_TEST_EXPORT const TestTag anvil_abi_tag{0x414E564CUL, 2};

extern "C" ANVIL_TEST_EXPORT auto anvil_plugin_create() noexcept
    -> TestPlugin * {
  append_event("factory");
  return new MismatchedPlugin;
}

extern "C" ANVIL_TEST_EXPORT auto
anvil_plugin_destroy(TestPlugin *plugin) noexcept -> void {
  append_event("destroy");
  delete plugin;
}
