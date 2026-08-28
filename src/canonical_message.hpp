#pragma once

#include <anvil/store.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace anvil::store::detail {

struct CanonicalMessage {
  std::string message_id;
  std::string board_id;
  std::string thread_id;
  std::optional<std::string> parent_message_id;
  std::string author_handle;
  std::optional<std::string> author_origin;
  std::string body;
  UtcEpochSeconds posted_at;
};

// ANVILMSG, a big-endian uint32 version, then the fields above in declaration
// order. Strings are exact stored UTF-8 bytes prefixed by a big-endian uint64
// length. Optional strings add a one-byte 0/1 presence marker. Local receipt
// time and mutable lifecycle state are deliberately not part of an origin's
// attestation.
[[nodiscard]] auto canonical_message_bytes(const CanonicalMessage &message)
    -> std::vector<std::byte>;

} // namespace anvil::store::detail
