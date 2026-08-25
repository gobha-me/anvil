#include <anvil/sdk/types.hpp>

struct NonPod {
  virtual ~NonPod() = default;
};

anvil::Span<NonPod> invalid_span;
