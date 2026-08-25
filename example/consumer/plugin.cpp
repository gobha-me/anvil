#include <anvil/sdk.hpp>

#include <stdexcept>
#include <string>
#include <vector>

namespace {

class ConsumerDoor final : public anvil::sdk::Door<ConsumerDoor> {
public:
  ConsumerDoor()
      : Door(
            anvil::sdk::PluginManifest{
                "org.example.consumer",
                "Consumer",
                "Installed SDK wrapper check",
                "Anvil",
                anvil::Version{0, 6, 0},
                anvil::PluginKind::door,
            },
            anvil::sdk::DoorManifest{}) {}

  void run_door(anvil::sdk::DoorContext) {
    std::vector<std::string> ordinary_cpp{"one", "two"};
    if (ordinary_cpp.size() != 2) {
      throw std::logic_error{"consumer fixture failed"};
    }
  }
};

} // namespace

ANVIL_PLUGIN(ConsumerDoor);
