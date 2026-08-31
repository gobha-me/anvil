#include "terminal_session.hpp"

#include "text_sanitization.hpp"

#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <mutex>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <termforge/core/app.hpp>
#include <termforge/core/byte_sink.hpp>
#include <termforge/widgets/text_input.hpp>
#include <thread>
#include <utility>
#include <variant>

namespace anvil::server {
namespace {

using namespace std::chrono_literals;

constexpr int max_cell_dimension = 1000;
constexpr int max_pixel_dimension = 65'535;
constexpr std::size_t max_echo_size = 4096;
constexpr auto sink_stall_timeout = 5s;

[[nodiscard]] bool valid_cells(int columns, int rows) noexcept {
  return columns > 0 && rows > 0 && columns <= max_cell_dimension && rows <= max_cell_dimension;
}

[[nodiscard]] std::pair<int, int> normalize_pixels(int width, int height) noexcept {
  if (width == 0 && height == 0) {
    return {0, 0};
  }
  if (width <= 0 || height <= 0 || width > max_pixel_dimension || height > max_pixel_dimension) {
    return {0, 0};
  }
  return {width, height};
}

class SocketSink final : public termforge::ByteSink {
 public:
  SocketSink(int descriptor, SessionResources &resources,
             const std::atomic<bool> &stop_requested) noexcept
      : descriptor_(descriptor), resources_(resources), stop_requested_(stop_requested) {}

  [[nodiscard]] auto write(std::span<const char> bytes)
      -> std::expected<void, termforge::ErrorEvent> override {
    for (;;) {
      const auto delay = resources_.output_delay(bytes.size(), std::chrono::steady_clock::now());
      if (!delay) {
        return std::unexpected(termforge::ErrorEvent{
            termforge::Severity::Error, "resource.output",
            "session output frame exceeds the configured one-second burst"});
      }
      if (*delay <= std::chrono::steady_clock::duration::zero()) {
        resources_.consume_output(bytes.size());
        break;
      }
      if (stop_requested_.load(std::memory_order_acquire)) {
        return std::unexpected(termforge::ErrorEvent{
            termforge::Severity::Error, "ssh", "session output stopped"});
      }
      std::this_thread::sleep_for(std::min(
          *delay, std::chrono::duration_cast<std::chrono::steady_clock::duration>(10ms)));
    }

    const auto deadline = std::chrono::steady_clock::now() + sink_stall_timeout;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
      const auto count =
          ::send(descriptor_, bytes.data() + offset, bytes.size() - offset, MSG_NOSIGNAL);
      if (count > 0) {
        offset += static_cast<std::size_t>(count);
        continue;
      }
      if (count < 0 && errno == EINTR) {
        continue;
      }
      if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining <= 0ms) {
          return std::unexpected(
              termforge::ErrorEvent{termforge::Severity::Error, "ssh",
                                    "SSH output stalled before a complete frame could be queued"});
        }
        pollfd descriptor{.fd = descriptor_, .events = POLLOUT, .revents = 0};
        const auto ready = ::poll(&descriptor, 1, static_cast<int>(remaining.count()));
        if (ready > 0) {
          continue;
        }
        if (ready < 0 && errno == EINTR) {
          continue;
        }
        return std::unexpected(termforge::ErrorEvent{
            termforge::Severity::Error, "ssh",
            ready == 0 ? "SSH output stalled before a complete frame could be queued"
                       : "SSH output wait failed"});
      }
      return std::unexpected(
          termforge::ErrorEvent{termforge::Severity::Error, "ssh", "SSH output channel closed"});
    }
    return {};
  }

 private:
  int descriptor_;
  SessionResources &resources_;
  const std::atomic<bool> &stop_requested_;
};

struct SharedState {
  SharedState(TerminalDimensions initial_dimensions, SessionResourceLimits resource_limits)
      : dimensions(initial_dimensions), resources(resource_limits) {}

  std::mutex mutex;
  TerminalDimensions dimensions;
  std::string notice;
  SessionTelemetry telemetry;
  SessionResources resources;
  std::atomic<std::uint64_t> progress_generation{};
  std::atomic<bool> stop_requested{false};
};

class EchoApp final : public termforge::App {
 public:
  EchoApp(int descriptor, std::string terminal_type, TerminalDimensions dimensions,
          std::chrono::steady_clock::time_point channel_opened, SharedState &shared,
          SessionInputHook input_hook_for_testing)
      : sink_(descriptor, shared.resources, shared.stop_requested),
        channel_opened_(channel_opened), shared_(shared) {
    const auto io = terminal().set_io(termforge::TerminalIo{descriptor, descriptor});
    if (!io) {
      throw std::runtime_error(io.error().message);
    }
    const auto env = terminal().set_env(termforge::TerminalEnv{std::move(terminal_type), {}});
    if (!env) {
      throw std::runtime_error(env.error().message);
    }
    // Capability probing is deliberately deferred to the bounded, cached
    // negotiation work in #42. An eager probe consumes bytes that may already
    // contain the user's first keystrokes; M0 starts from the safe baseline.
    const auto capabilities = terminal().set_capabilities(termforge::Capabilities{});
    if (!capabilities) {
      throw std::runtime_error(capabilities.error().message);
    }
    const auto size = set_size(termforge::App::Size{
        dimensions.columns, dimensions.rows, dimensions.pixel_width, dimensions.pixel_height});
    if (!size) {
      throw std::runtime_error(size.error().message);
    }

    input_.set_focused(true);
    input_.set_placeholder("Type here");
    input_.on_change([this, input_hook_for_testing](const std::string &text) {
      auto sanitized = sanitize_prose_for_render(text);
      if (text.size() <= max_echo_size && sanitized.size() <= max_echo_size) {
        accepted_input_ = std::move(sanitized);
        if (accepted_input_ != text) {
          input_.set_text(accepted_input_);
        }
      } else {
        input_.set_text(accepted_input_);
      }
      if (input_hook_for_testing != nullptr) {
        input_hook_for_testing(text, shared_.resources);
      }
    });
    set_render_mode(termforge::RenderMode::Demand);
    set_frame_observer([this](const termforge::FrameObservation &observation) {
      std::lock_guard lock(shared_.mutex);
      auto &telemetry = shared_.telemetry;
      ++telemetry.frames;
      if (observation.output_accepted) {
        ++telemetry.accepted_frames;
        if (telemetry.accepted_frames == 1U) {
          telemetry.first_frame_latency = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - channel_opened_);
        }
      }
      telemetry.cell_bytes += observation.bytes.cells;
      telemetry.image_transmit_bytes += observation.bytes.image_transmit;
      telemetry.image_edit_bytes += observation.bytes.image_edit;
      telemetry.last_frame_cell_bytes = observation.bytes.cells;
      telemetry.last_frame_image_transmit_bytes = observation.bytes.image_transmit;
      telemetry.last_frame_image_edit_bytes = observation.bytes.image_edit;
      if (observation.output_accepted) {
        shared_.resources.reconcile_image(driver().residency().source_payload_bytes);
      }
      shared_.progress_generation.fetch_add(1U, std::memory_order_release);
      if (shared_.resources.limit_reason() == ResourceLimitReason::image) {
        quit();
      }
    });
  }

  auto on_start() -> void override { driver().set_output(&sink_); }

  auto on_event(const termforge::Event &event) -> void override {
    if (shared_.stop_requested.load(std::memory_order_acquire)) {
      quit();
      return;
    }

    if (const auto *key = std::get_if<termforge::KeyEvent>(&event)) {
      if (key->action == termforge::KeyAction::Press &&
          (key->key == termforge::Key::Escape ||
           (key->ctrl && (key->ch == U'c' || key->ch == U'C')))) {
        quit();
        return;
      }
      // A piped OpenSSH client commonly sends LF as Ctrl+J rather than CR.
      // It is a submit key, never a printable "j" in the echo field.
      if (key->action == termforge::KeyAction::Press && key->ctrl &&
          (key->ch == U'j' || key->ch == U'J' || key->ch == U'm' || key->ch == U'M')) {
        return;
      }
    }

    if (std::holds_alternative<termforge::ResizeEvent>(event)) {
      TerminalDimensions dimensions;
      {
        std::lock_guard lock(shared_.mutex);
        dimensions = shared_.dimensions;
      }
      const auto current = current_size();
      const termforge::App::Size wanted{dimensions.columns, dimensions.rows, dimensions.pixel_width,
                                        dimensions.pixel_height};
      if (current != wanted) {
        if (const auto resized = set_size(wanted); !resized) {
          status_ = resized.error().message;
        }
      }
      return;
    }

    if (const auto *error = std::get_if<termforge::ErrorEvent>(&event)) {
      if (error->source == "ssh") {
        std::lock_guard lock(shared_.mutex);
        status_ = shared_.notice;
        return;
      }
      status_ = error->message;
      if (error->severity == termforge::Severity::Error) {
        quit();
      }
      return;
    }

    if (input_.on_event(event)) {
      return;
    }
    termforge::App::on_event(event);
  }

  auto on_render(termforge::Screen &screen) -> void override {
    constexpr termforge::Rgb foreground{0xE0, 0xE0, 0xF0};
    constexpr termforge::Rgb accent{0x70, 0xC0, 0xFF};
    constexpr termforge::Rgb background{0x0A, 0x0A, 0x14};
    screen.clear(foreground, background);

    const auto title = "Anvil M0 echo session " + std::to_string(::getpid());
    static_cast<void>(screen.write_text(0, 0, title, accent, background));
    const auto dimensions = std::to_string(screen.cols()) + "x" + std::to_string(screen.rows());
    static_cast<void>(screen.write_text(0, 1, "Terminal: " + dimensions, foreground, background));
    static_cast<void>(screen.write_text(0, 2, "Type to echo. Esc or Ctrl-C disconnects.",
                                        foreground, background));
    if (screen.rows() > 3) {
      input_.set_geometry(termforge::Rect{0, 3, screen.cols(), 1});
      input_.draw(screen);
    }
    if (!status_.empty() && screen.rows() > 4) {
      const auto status = sanitize_prose_for_render(status_);
      static_cast<void>(screen.write_text(0, screen.rows() - 1, status, accent, background));
    }
  }

 private:
  SocketSink sink_;
  std::chrono::steady_clock::time_point channel_opened_;
  SharedState &shared_;
  termforge::TextInput input_;
  std::string accepted_input_;
  std::string status_;
};

}  // namespace

TerminalDimensions normalize_initial_dimensions(int columns, int rows, int pixel_width,
                                                int pixel_height) noexcept {
  const auto [width, height] = normalize_pixels(pixel_width, pixel_height);
  if (!valid_cells(columns, rows)) {
    return TerminalDimensions{80, 24, width, height};
  }
  return TerminalDimensions{columns, rows, width, height};
}

std::optional<TerminalDimensions> normalize_resize_dimensions(int columns, int rows,
                                                              int pixel_width,
                                                              int pixel_height) noexcept {
  if (!valid_cells(columns, rows)) {
    return std::nullopt;
  }
  const auto [width, height] = normalize_pixels(pixel_width, pixel_height);
  return TerminalDimensions{columns, rows, width, height};
}

std::string normalize_terminal_type(RemoteBytes remote_terminal_type) {
  const auto terminal_type = remote_terminal_type.text();
  if (terminal_type.empty() ||
      terminal_type.size() > max_remote_terminal_type_size) {
    return {};
  }
  std::string result;
  result.reserve(terminal_type.size());
  for (const auto character : terminal_type) {
    const auto byte = static_cast<unsigned char>(character);
    if (byte < 0x20U || byte > 0x7EU) {
      return {};
    }
    result.push_back(character);
  }
  return result;
}

class TerminalSession::Impl {
 public:
  Impl(int io_descriptor, std::string terminal_type, TerminalDimensions dimensions,
       std::chrono::steady_clock::time_point channel_opened,
       SessionResourceLimits resource_limits,
       SessionInputHook input_hook_for_testing)
      : shared_(dimensions, resource_limits),
        app_(io_descriptor, std::move(terminal_type), dimensions, channel_opened, shared_,
             input_hook_for_testing) {}

  ~Impl() {
    request_stop();
    join();
  }

  void start() {
    if (thread_.joinable()) {
      throw std::logic_error("terminal session already started");
    }
    thread_ = std::thread([this] {
      clockid_t clock{};
      if (::pthread_getcpuclockid(::pthread_self(), &clock) == 0) {
        cpu_clock_ = clock;
        cpu_clock_ready_.store(true, std::memory_order_release);
      }
      try {
        if (app_.run() != 0) {
          failure_reason_.store(SessionFailureReason::app_returned_failure,
                                std::memory_order_release);
        }
      } catch (const ResourceLimitError &error) {
        shared_.resources.mark_exceeded(error.reason());
        failure_reason_.store(failure_reason_for(error.reason()), std::memory_order_release);
      } catch (const std::bad_alloc &) {
        shared_.resources.mark_exceeded(ResourceLimitReason::memory);
        failure_reason_.store(SessionFailureReason::memory_limit, std::memory_order_release);
      } catch (const std::exception &) {
        failure_reason_.store(SessionFailureReason::standard_exception,
                              std::memory_order_release);
      } catch (...) {
        failure_reason_.store(SessionFailureReason::unknown_exception,
                              std::memory_order_release);
      }
      if (const auto limit = shared_.resources.limit_reason();
          limit != ResourceLimitReason::none) {
        failure_reason_.store(failure_reason_for(limit), std::memory_order_release);
      }
      finished_.store(true, std::memory_order_release);
    });
  }

  void post_resize(TerminalDimensions dimensions) {
    {
      std::lock_guard lock(shared_.mutex);
      shared_.dimensions = dimensions;
    }
    app_.post(termforge::Event{termforge::ResizeEvent{dimensions.columns, dimensions.rows}});
  }

  void post_notice(std::string notice) {
    {
      std::lock_guard lock(shared_.mutex);
      shared_.notice = std::move(notice);
    }
    app_.post(termforge::Event{
        termforge::ErrorEvent{termforge::Severity::Info, "ssh", "session notice changed"}});
  }

  void request_stop() {
    if (shared_.stop_requested.exchange(true, std::memory_order_acq_rel)) {
      return;
    }
    app_.post(termforge::Event{
        termforge::ErrorEvent{termforge::Severity::Info, "ssh", "session stopping"}});
  }

  void join() {
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  [[nodiscard]] bool finished() const noexcept { return finished_.load(std::memory_order_acquire); }

  [[nodiscard]] bool failed() const noexcept {
    return failure_reason() != SessionFailureReason::none;
  }

  [[nodiscard]] SessionFailureReason failure_reason() const noexcept {
    return failure_reason_.load(std::memory_order_acquire);
  }

  [[nodiscard]] ResourceLimitReason limit_reason() const noexcept {
    return shared_.resources.limit_reason();
  }

  [[nodiscard]] SessionCpuProgress cpu_progress() const noexcept {
    SessionCpuProgress result;
    result.generation = shared_.progress_generation.load(std::memory_order_acquire);
    if (!cpu_clock_ready_.load(std::memory_order_acquire)) {
      return result;
    }
    timespec consumed{};
    if (::clock_gettime(cpu_clock_, &consumed) != 0 || consumed.tv_sec < 0 ||
        consumed.tv_nsec < 0) {
      return result;
    }
    constexpr auto billion = std::int64_t{1'000'000'000};
    if (consumed.tv_sec > std::numeric_limits<std::int64_t>::max() / billion) {
      result.consumed = std::chrono::nanoseconds::max();
    } else {
      result.consumed = std::chrono::seconds(consumed.tv_sec) +
                        std::chrono::nanoseconds(consumed.tv_nsec);
    }
    result.ready = true;
    return result;
  }

  [[nodiscard]] SessionTelemetry telemetry() const noexcept {
    std::lock_guard lock(shared_.mutex);
    return shared_.telemetry;
  }

 private:
  [[nodiscard]] static SessionFailureReason failure_reason_for(
      ResourceLimitReason reason) noexcept {
    switch (reason) {
      case ResourceLimitReason::memory:
        return SessionFailureReason::memory_limit;
      case ResourceLimitReason::output:
        return SessionFailureReason::output_limit;
      case ResourceLimitReason::image:
        return SessionFailureReason::image_limit;
      case ResourceLimitReason::none:
      case ResourceLimitReason::cpu:
      case ResourceLimitReason::duration:
        return SessionFailureReason::unknown_exception;
    }
    return SessionFailureReason::unknown_exception;
  }

  mutable SharedState shared_;
  EchoApp app_;
  std::thread thread_;
  clockid_t cpu_clock_{};
  std::atomic<bool> cpu_clock_ready_{false};
  std::atomic<bool> finished_{false};
  std::atomic<SessionFailureReason> failure_reason_{SessionFailureReason::none};
};

TerminalSession::TerminalSession(int io_descriptor, std::string terminal_type,
                                 TerminalDimensions dimensions,
                                 std::chrono::steady_clock::time_point channel_opened,
                                 SessionResourceLimits resource_limits,
                                 SessionInputHook input_hook_for_testing)
    : impl_(std::make_unique<Impl>(io_descriptor, std::move(terminal_type), dimensions,
                                   channel_opened, resource_limits, input_hook_for_testing)) {}

TerminalSession::~TerminalSession() = default;

void TerminalSession::start() { impl_->start(); }

void TerminalSession::post_resize(TerminalDimensions dimensions) { impl_->post_resize(dimensions); }

void TerminalSession::post_notice(std::string notice) { impl_->post_notice(std::move(notice)); }

void TerminalSession::request_stop() { impl_->request_stop(); }

void TerminalSession::join() { impl_->join(); }

bool TerminalSession::finished() const noexcept { return impl_->finished(); }

bool TerminalSession::failed() const noexcept { return impl_->failed(); }

SessionFailureReason TerminalSession::failure_reason() const noexcept {
  return impl_->failure_reason();
}

ResourceLimitReason TerminalSession::limit_reason() const noexcept {
  return impl_->limit_reason();
}

SessionCpuProgress TerminalSession::cpu_progress() const noexcept {
  return impl_->cpu_progress();
}

SessionTelemetry TerminalSession::telemetry() const noexcept { return impl_->telemetry(); }

}  // namespace anvil::server
