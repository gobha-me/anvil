#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <thread>

#include "session_sink.hpp"

using namespace std::chrono_literals;

namespace {

class SocketPair {
public:
  SocketPair() {
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                         descriptors_.data()) == 0);
  }

  ~SocketPair() {
    for (const auto descriptor : descriptors_) {
      if (descriptor >= 0) {
        static_cast<void>(::close(descriptor));
      }
    }
  }

  SocketPair(const SocketPair &) = delete;
  auto operator=(const SocketPair &) -> SocketPair & = delete;

  [[nodiscard]] int sender() const noexcept { return descriptors_[0]; }
  [[nodiscard]] int receiver() const noexcept { return descriptors_[1]; }

  void close_receiver() noexcept {
    static_cast<void>(::close(descriptors_[1]));
    descriptors_[1] = -1;
  }

private:
  std::array<int, 2> descriptors_{-1, -1};
};

[[nodiscard]] auto as_bytes(std::string_view text) -> std::span<const char> {
  return {text.data(), text.size()};
}

void fill_send_buffer(int descriptor) {
  std::array<char, 4096> bytes{};
  while (::send(descriptor, bytes.data(), bytes.size(), MSG_NOSIGNAL) > 0) {
  }
  REQUIRE((errno == EAGAIN || errno == EWOULDBLOCK));
}

} // namespace

TEST_CASE("session sink sends one admitted frame completely") {
  SocketPair sockets;
  anvil::server::SessionResources resources({});
  std::atomic<bool> stop_requested{false};
  anvil::server::detail::SessionSink sink(sockets.sender(), resources,
                                          stop_requested);

  REQUIRE(sink.write(as_bytes("frame")));
  std::array<char, 5> received{};
  REQUIRE(::recv(sockets.receiver(), received.data(), received.size(), 0) ==
          static_cast<ssize_t>(received.size()));
  CHECK(std::string_view(received.data(), received.size()) == "frame");
}

TEST_CASE("session sink rejects a frame larger than the one-second burst") {
  SocketPair sockets;
  anvil::server::SessionResources resources({.output_bytes_per_second = 4U});
  std::atomic<bool> stop_requested{false};
  anvil::server::detail::SessionSink sink(sockets.sender(), resources,
                                          stop_requested);

  const auto written = sink.write(as_bytes("large"));
  REQUIRE_FALSE(written);
  CHECK(written.error().source == "resource.output");
  CHECK(written.error().message ==
        "session output frame exceeds the configured one-second burst");
}

TEST_CASE("session sink stops without consuming a delayed frame") {
  SocketPair sockets;
  anvil::server::SessionResources resources({.output_bytes_per_second = 100U});
  resources.consume_output(100U);
  std::atomic<bool> stop_requested{true};
  anvil::server::detail::SessionSink sink(sockets.sender(), resources,
                                          stop_requested);

  const auto written = sink.write(as_bytes("x"));
  REQUIRE_FALSE(written);
  CHECK(written.error().source == "ssh");
  CHECK(written.error().message == "session output stopped");
}

TEST_CASE("session sink reports a closed peer without SIGPIPE") {
  SocketPair sockets;
  anvil::server::SessionResources resources({});
  std::atomic<bool> stop_requested{false};
  anvil::server::detail::SessionSink sink(sockets.sender(), resources,
                                          stop_requested);
  sockets.close_receiver();

  const auto written = sink.write(as_bytes("frame"));
  REQUIRE_FALSE(written);
  CHECK(written.error().source == "ssh");
  CHECK(written.error().message == "SSH output channel closed");
}

TEST_CASE("session sink bounds a nonblocking socket stall") {
  SocketPair sockets;
  fill_send_buffer(sockets.sender());
  anvil::server::SessionResources resources({});
  std::atomic<bool> stop_requested{false};
  anvil::server::detail::SessionSink sink(sockets.sender(), resources,
                                          stop_requested, 5ms);

  const auto written = sink.write(as_bytes("x"));
  REQUIRE_FALSE(written);
  CHECK(written.error().source == "ssh");
  CHECK(written.error().message ==
        "SSH output stalled before a complete frame could be queued");
}

TEST_CASE("session sink retries when a nonblocking socket becomes writable") {
  SocketPair sockets;
  fill_send_buffer(sockets.sender());
  anvil::server::SessionResources resources({});
  std::atomic<bool> stop_requested{false};
  anvil::server::detail::SessionSink sink(sockets.sender(), resources,
                                          stop_requested, 1s);
  std::jthread drainer([descriptor = sockets.receiver()] {
    std::this_thread::sleep_for(10ms);
    std::array<char, 64 * 1024> discarded{};
    while (::recv(descriptor, discarded.data(), discarded.size(), 0) > 0) {
    }
  });

  CHECK(sink.write(as_bytes("x")));
}
