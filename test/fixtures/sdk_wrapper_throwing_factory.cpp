#include <anvil/sdk.hpp>

#include <stdexcept>

namespace {

class ThrowingDoor final : public anvil::sdk::Door<ThrowingDoor> {
public:
  ThrowingDoor()
      : Door(
            anvil::sdk::PluginManifest{
                "org.example.throwing-factory",
                "Throwing factory",
                "The constructor fails deliberately",
                "Anvil",
                anvil::Version{0, 6, 0},
                anvil::PluginKind::door,
            },
            anvil::sdk::DoorManifest{}) {
    throw std::runtime_error{"deliberate factory failure"};
  }

  void run_door(anvil::sdk::DoorContext) {}
};

} // namespace

ANVIL_PLUGIN(ThrowingDoor);
