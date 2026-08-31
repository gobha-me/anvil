#include "server.hpp"

#include <atomic>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view failure_marker{"anvil-test-throw"};
constexpr std::string_view memory_marker{"anvil-test-memory"};
constexpr std::string_view cpu_marker{"anvil-test-cpu"};
constexpr std::string_view output_marker{"anvil-test-output"};
constexpr std::string_view image_marker{"anvil-test-image"};

void inject_failure(std::string_view input, anvil::server::SessionResources &resources) {
  if (input == failure_marker) {
    throw std::runtime_error("injected terminal session failure");
  }
  if (input == memory_marker &&
      !resources.reserve_memory(resources.limits().memory_bytes + 1U)) {
    throw anvil::server::ResourceLimitError(anvil::server::ResourceLimitReason::memory);
  }
  if (input == output_marker) {
    const auto result = resources.output_delay(
        static_cast<std::size_t>(resources.limits().output_bytes_per_second + 1U),
        anvil::server::SessionResources::Clock::now());
    if (!result) {
      throw anvil::server::ResourceLimitError(result.error());
    }
  }
  if (input == image_marker &&
      !resources.reserve_image(resources.limits().image_bytes + 1U)) {
    throw anvil::server::ResourceLimitError(anvil::server::ResourceLimitReason::image);
  }
  if (input == cpu_marker) {
    for (;;) {
      std::atomic_signal_fence(std::memory_order_seq_cst);
    }
  }
}

}  // namespace

int main(int argc, char **argv) {
  try {
    std::vector<std::string_view> arguments;
    arguments.reserve(static_cast<std::size_t>(argc > 1 ? argc - 1 : 0));
    for (int index = 1; index < argc; ++index) {
      arguments.emplace_back(argv[index]);
    }

    auto parsed = anvil::server::parse_arguments(arguments);
    if (parsed.show_help) {
      std::cout << anvil::server::usage();
      return 0;
    }
    parsed.config.session_input_hook_for_testing = inject_failure;
    return anvil::server::run(parsed.config);
  } catch (const std::exception &error) {
    std::cerr << "anvil: " << error.what() << '\n';
    std::cerr << anvil::server::usage();
    return 2;
  }
}
