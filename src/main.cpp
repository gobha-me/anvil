#include "server.hpp"

#include <exception>
#include <iostream>
#include <string_view>
#include <vector>

int main(int argc, char** argv) {
  try {
    std::vector<std::string_view> arguments;
    arguments.reserve(static_cast<std::size_t>(argc > 1 ? argc - 1 : 0));
    for (int index = 1; index < argc; ++index) {
      arguments.emplace_back(argv[index]);
    }

    const auto parsed = anvil::server::parse_arguments(arguments);
    if (parsed.show_help) {
      std::cout << anvil::server::usage();
      return 0;
    }
    return anvil::server::run(parsed.config);
  } catch (const std::exception& error) {
    std::cerr << "anvil: " << error.what() << '\n';
    std::cerr << anvil::server::usage();
    return 2;
  }
}
