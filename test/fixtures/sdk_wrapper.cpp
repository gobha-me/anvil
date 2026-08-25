#include <anvil/sdk.hpp>

#include <algorithm>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

class ExampleDoor final : public anvil::sdk::Door<ExampleDoor> {
public:
  ExampleDoor()
      : Door(
            anvil::sdk::PluginManifest{
                "org.example.wrapper",
                "Wrapper example",
                "A nontrivial door written with ordinary C++",
                "Anvil",
                anvil::Version{0, 6, 0},
                anvil::PluginKind::door,
            },
            anvil::sdk::DoorManifest{
                anvil::CapabilityTier::ansi,
                true,
                false,
                false,
            }) {}

  void run_door(anvil::sdk::DoorContext context) {
    std::vector<std::string> messages{"gamma", "alpha", "beta"};
    std::ranges::sort(messages);

    std::vector<unsigned int> scores{3, 1, 4, 1, 5};
    const auto borrowed = anvil::sdk::as_span(scores);
    const auto view = anvil::sdk::as_std_span(borrowed);
    const auto total = std::accumulate(view.begin(), view.end(), 0U);

    if (context.user().value == 13) {
      throw std::runtime_error{"deliberate wrapper fixture failure"};
    }
    if (messages.front() != "alpha" || total != 14U) {
      throw std::logic_error{"ordinary C++ fixture work produced a bad result"};
    }
  }
};

} // namespace

ANVIL_PLUGIN(ExampleDoor);
