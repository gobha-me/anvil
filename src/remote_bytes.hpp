#pragma once

#include <cstddef>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

namespace anvil::server {

enum class RemoteBytesError {
  null_data,
  missing_terminator,
  capacity_exceeded,
};

// A non-owning view whose type records that the bytes came from a remote
// peer. External callback adapters construct this type; parsers retain the
// provenance instead of accepting an unmarked pointer-and-length pair.
class RemoteBytes {
 public:
  [[nodiscard]] static auto from_raw(const void *data, std::size_t size) noexcept
      -> std::expected<RemoteBytes, RemoteBytesError> {
    if (data == nullptr) {
      if (size != 0U) {
        return std::unexpected(RemoteBytesError::null_data);
      }
      return RemoteBytes(std::span<const std::byte>{});
    }
    return RemoteBytes(
        std::span<const std::byte>{static_cast<const std::byte *>(data), size});
  }

  [[nodiscard]] static RemoteBytes from_span(
      std::span<const std::byte> bytes) noexcept {
    return RemoteBytes(bytes);
  }

  [[nodiscard]] static RemoteBytes from_text(std::string_view text) noexcept {
    return RemoteBytes(std::as_bytes(std::span{text.data(), text.size()}));
  }

  [[nodiscard]] static auto from_bounded_c_string(
      const char *data, std::size_t maximum_size) noexcept
      -> std::expected<RemoteBytes, RemoteBytesError> {
    if (data == nullptr) {
      return std::unexpected(RemoteBytesError::null_data);
    }
    for (std::size_t size = 0; size <= maximum_size; ++size) {
      if (data[size] == '\0') {
        return from_raw(data, size);
      }
    }
    return std::unexpected(RemoteBytesError::missing_terminator);
  }

  [[nodiscard]] std::span<const std::byte> bytes() const noexcept {
    return bytes_;
  }

  [[nodiscard]] std::string_view text() const noexcept {
    if (bytes_.empty()) {
      return {};
    }
    return {reinterpret_cast<const char *>(bytes_.data()), bytes_.size()};
  }

  [[nodiscard]] bool empty() const noexcept { return bytes_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }

 private:
  explicit RemoteBytes(std::span<const std::byte> bytes) noexcept
      : bytes_(bytes) {}

  std::span<const std::byte> bytes_;
};

[[nodiscard]] inline auto append_remote_bytes(
    std::vector<std::byte> &destination, RemoteBytes input,
    std::size_t maximum_size) -> std::expected<void, RemoteBytesError> {
  if (destination.size() > maximum_size ||
      input.size() > maximum_size - destination.size()) {
    return std::unexpected(RemoteBytesError::capacity_exceeded);
  }
  destination.insert(destination.end(), input.bytes().begin(),
                     input.bytes().end());
  return {};
}

}  // namespace anvil::server
