#include <anvil/sdk.hpp>

#include <vector>

auto main() -> int {
  const auto borrowed =
      anvil::sdk::as_span(std::vector<unsigned int>{1, 2, 3});
  return static_cast<int>(borrowed.len);
}
