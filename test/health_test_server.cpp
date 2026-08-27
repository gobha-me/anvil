#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>

#include "health.hpp"

int main(int argc, char **argv) {
  if (argc != 3) {
    std::cerr << "usage: anvil-health-test-server PORT MODE\n";
    return 2;
  }
  try {
    const auto parsed = std::stoul(argv[1]);
    if (parsed == 0UL || parsed > 65535UL) {
      throw std::runtime_error("invalid port");
    }
    auto monitor = anvil::server::HealthMonitor::start(
        {"127.0.0.1", static_cast<std::uint16_t>(parsed), 4, {}});
    const std::string mode(argv[2]);
    if (mode == "storage-failed") {
      monitor->set_component({anvil::server::ComponentKind::storage,
                              anvil::server::ComponentState::failed, "database", {},
                              "database unreachable"});
    } else if (mode == "plugin-failed") {
      monitor->set_component({anvil::server::ComponentKind::plugin,
                              anvil::server::ComponentState::failed, "hostile\"plugin", "2.0",
                              "ABI tag mismatch"});
    } else if (mode != "ready") {
      throw std::runtime_error("invalid mode");
    }
    monitor->heartbeat(true);
    std::cout << "ready\n";
    std::cout.flush();
    std::string ignored;
    std::getline(std::cin, ignored);
    monitor->heartbeat(false);
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
