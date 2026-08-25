#include <anvil/sdk.hpp>

#include <string>

auto main() -> int {
  const auto borrowed = anvil::sdk::as_str(std::string{"temporary"});
  return static_cast<int>(borrowed.len);
}
