#include "server.hpp"

#include <exception>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view failure_marker{"anvil-test-throw"};

void inject_failure(std::string_view input) {
  if (input == failure_marker) {
    throw std::runtime_error("injected terminal session failure");
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
