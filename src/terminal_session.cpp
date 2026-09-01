#include "terminal_session.hpp"

#include <poll.h>
#include <pthread.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
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
#include <termforge/widgets/composer.hpp>
#include <termforge/widgets/list_widget.hpp>
#include <termforge/widgets/text_box.hpp>
#include <termforge/widgets/text_input.hpp>
#include <thread>
#include <utility>
#include <variant>

#include "authentication.hpp"
#include "server.hpp"
#include "text_sanitization.hpp"

namespace anvil::server {
namespace {

using namespace std::chrono_literals;

constexpr int max_cell_dimension = 1000;
constexpr int max_pixel_dimension = 65'535;
constexpr std::size_t max_echo_size = 4096;
constexpr auto sink_stall_timeout = 5s;

[[nodiscard]] store::UtcEpochSeconds utc_now() {
  return {std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count()};
}

[[nodiscard]] std::string random_content_id(std::string_view prefix) {
  std::array<unsigned char, 16> bytes{};
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count =
        ::getrandom(bytes.data() + offset, bytes.size() - offset, 0);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      throw std::runtime_error("cannot obtain message identifier randomness");
    }
    offset += static_cast<std::size_t>(count);
  }
  constexpr std::string_view digits = "0123456789abcdef";
  std::string result(prefix);
  result.reserve(prefix.size() + bytes.size() * 2U);
  for (const auto byte : bytes) {
    result.push_back(digits[byte >> 4U]);
    result.push_back(digits[byte & 0x0fU]);
  }
  return result;
}

[[nodiscard]] bool valid_cells(int columns, int rows) noexcept {
  return columns > 0 && rows > 0 && columns <= max_cell_dimension &&
         rows <= max_cell_dimension;
}

[[nodiscard]] std::pair<int, int> normalize_pixels(int width,
                                                   int height) noexcept {
  if (width == 0 && height == 0) {
    return {0, 0};
  }
  if (width <= 0 || height <= 0 || width > max_pixel_dimension ||
      height > max_pixel_dimension) {
    return {0, 0};
  }
  return {width, height};
}

class SocketSink final : public termforge::ByteSink {
public:
  SocketSink(int descriptor, SessionResources &resources,
             const std::atomic<bool> &stop_requested) noexcept
      : descriptor_(descriptor), resources_(resources),
        stop_requested_(stop_requested) {}

  [[nodiscard]] auto write(std::span<const char> bytes)
      -> std::expected<void, termforge::ErrorEvent> override {
    for (;;) {
      const auto delay = resources_.output_delay(
          bytes.size(), std::chrono::steady_clock::now());
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
          *delay,
          std::chrono::duration_cast<std::chrono::steady_clock::duration>(
              10ms)));
    }

    const auto deadline = std::chrono::steady_clock::now() + sink_stall_timeout;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
      const auto count = ::send(descriptor_, bytes.data() + offset,
                                bytes.size() - offset, MSG_NOSIGNAL);
      if (count > 0) {
        offset += static_cast<std::size_t>(count);
        continue;
      }
      if (count < 0 && errno == EINTR) {
        continue;
      }
      if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
        if (remaining <= 0ms) {
          return std::unexpected(termforge::ErrorEvent{
              termforge::Severity::Error, "ssh",
              "SSH output stalled before a complete frame could be queued"});
        }
        pollfd descriptor{.fd = descriptor_, .events = POLLOUT, .revents = 0};
        const auto ready =
            ::poll(&descriptor, 1, static_cast<int>(remaining.count()));
        if (ready > 0) {
          continue;
        }
        if (ready < 0 && errno == EINTR) {
          continue;
        }
        return std::unexpected(termforge::ErrorEvent{
            termforge::Severity::Error, "ssh",
            ready == 0
                ? "SSH output stalled before a complete frame could be queued"
                : "SSH output wait failed"});
      }
      return std::unexpected(termforge::ErrorEvent{
          termforge::Severity::Error, "ssh", "SSH output channel closed"});
    }
    return {};
  }

private:
  int descriptor_;
  SessionResources &resources_;
  const std::atomic<bool> &stop_requested_;
};

struct SharedState {
  SharedState(TerminalDimensions initial_dimensions,
              SessionResourceLimits resource_limits)
      : dimensions(initial_dimensions), resources(resource_limits) {}

  std::mutex mutex;
  TerminalDimensions dimensions;
  std::string notice;
  SessionTelemetry telemetry;
  SessionResources resources;
  std::atomic<std::uint64_t> progress_generation{};
  std::atomic<bool> stop_requested{false};
  std::atomic<bool> oneliner_wall_visible{false};
  std::atomic<bool> oneliners_dirty{false};
};

class EchoApp final : public termforge::App {
public:
  EchoApp(int descriptor, std::string terminal_type,
          TerminalDimensions dimensions,
          std::chrono::steady_clock::time_point channel_opened,
          SharedState &shared, SessionIdentity identity,
          store::Store &identity_store, RegistrationMode registration_mode,
          InvitePolicy invite_policy, TosPolicy tos_policy,
          SessionInputHook input_hook_for_testing,
          int guest_report_permit_descriptor,
          store::OnelinerPolicy oneliner_policy,
          OnelinerPublishedHook oneliner_published_hook,
          int worker_report_descriptor, std::uint64_t session_id)
      : sink_(descriptor, shared.resources, shared.stop_requested),
        channel_opened_(channel_opened), shared_(shared),
        identity_(std::move(identity)), identity_store_(identity_store),
        registration_mode_(registration_mode), invite_policy_(invite_policy),
        tos_policy_(std::move(tos_policy)),
        guest_report_permit_descriptor_(guest_report_permit_descriptor),
        oneliner_policy_(oneliner_policy),
        oneliner_published_hook_(oneliner_published_hook),
        worker_report_descriptor_(worker_report_descriptor),
        session_id_(session_id),
        screen_mode_((identity_.kind == IdentityKind::pending ||
                      identity_.kind == IdentityKind::tos_required)
                         ? ScreenMode::tos
                         : ScreenMode::boards) {
    const auto io =
        terminal().set_io(termforge::TerminalIo{descriptor, descriptor});
    if (!io) {
      throw std::runtime_error(io.error().message);
    }
    const auto env = terminal().set_env(
        termforge::TerminalEnv{std::move(terminal_type), {}});
    if (!env) {
      throw std::runtime_error(env.error().message);
    }
    // Capability probing is deliberately deferred to the bounded, cached
    // negotiation work in #42. An eager probe consumes bytes that may already
    // contain the user's first keystrokes; M0 starts from the safe baseline.
    const auto capabilities =
        terminal().set_capabilities(termforge::Capabilities{});
    if (!capabilities) {
      throw std::runtime_error(capabilities.error().message);
    }
    const auto size = set_size(
        termforge::App::Size{dimensions.columns, dimensions.rows,
                             dimensions.pixel_width, dimensions.pixel_height});
    if (!size) {
      throw std::runtime_error(size.error().message);
    }

    input_.set_focused(true);
    board_list_.set_focused(true);
    oneliner_list_.set_focused(false);
    thread_list_.set_focused(true);
    message_box_.set_focused(true);
    composer_.set_focused(true);
    input_.set_placeholder("Type here");
    append_tos_text();
    input_.on_change([this, input_hook_for_testing](const std::string &text) {
      clear_issued_invite_code();
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
    composer_.set_enter_mode(termforge::ComposerEnterMode::Submit);
    composer_.set_max_height(8);
    if (screen_mode_ == ScreenMode::boards) {
      load_boards();
      load_oneliners();
    }
    set_render_mode(termforge::RenderMode::Demand);
    set_frame_observer([this](const termforge::FrameObservation &observation) {
      std::lock_guard lock(shared_.mutex);
      auto &telemetry = shared_.telemetry;
      ++telemetry.frames;
      if (observation.output_accepted) {
        ++telemetry.accepted_frames;
        if (telemetry.accepted_frames == 1U) {
          telemetry.first_frame_latency =
              std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - channel_opened_);
        }
      }
      telemetry.cell_bytes += observation.bytes.cells;
      telemetry.image_transmit_bytes += observation.bytes.image_transmit;
      telemetry.image_edit_bytes += observation.bytes.image_edit;
      telemetry.last_frame_cell_bytes = observation.bytes.cells;
      telemetry.last_frame_image_transmit_bytes =
          observation.bytes.image_transmit;
      telemetry.last_frame_image_edit_bytes = observation.bytes.image_edit;
      if (observation.output_accepted) {
        shared_.resources.reconcile_image(
            driver().residency().source_payload_bytes);
      }
      shared_.progress_generation.fetch_add(1U, std::memory_order_release);
      if (shared_.resources.limit_reason() == ResourceLimitReason::image) {
        quit();
      }
    });
  }

  ~EchoApp() override {
    clear_invite_code();
    clear_issued_invite_code();
  }

  auto on_start() -> void override { driver().set_output(&sink_); }

  auto on_event(const termforge::Event &event) -> void override {
    if (shared_.stop_requested.load(std::memory_order_acquire)) {
      quit();
      return;
    }

    if (const auto *key = std::get_if<termforge::KeyEvent>(&event)) {
      if (key->action == termforge::KeyAction::Press &&
          key->key == termforge::Key::Escape) {
        if (screen_mode_ == ScreenMode::oneliner) {
          screen_mode_ = ScreenMode::boards;
          status_.clear();
          return;
        }
        if (screen_mode_ == ScreenMode::thread ||
            screen_mode_ == ScreenMode::subject ||
            screen_mode_ == ScreenMode::compose ||
            screen_mode_ == ScreenMode::report) {
          composer_.clear();
          input_.set_text({});
          if (screen_mode_ == ScreenMode::report) {
            report_target_.reset();
            screen_mode_ = report_return_mode_;
            return;
          }
          if (screen_mode_ == ScreenMode::thread) {
            open_selected_board();
          } else {
            screen_mode_ = ScreenMode::threads;
          }
          return;
        }
        if (screen_mode_ == ScreenMode::threads) {
          load_boards();
          load_oneliners();
          screen_mode_ = ScreenMode::boards;
          return;
        }
        quit();
        return;
      }
      if (key->action == termforge::KeyAction::Press &&
          key->key == termforge::Key::Tab &&
          screen_mode_ == ScreenMode::boards) {
        entry_focus_ = entry_focus_ == EntryFocus::boards
                           ? EntryFocus::oneliners
                           : EntryFocus::boards;
        board_list_.set_focused(entry_focus_ == EntryFocus::boards);
        oneliner_list_.set_focused(entry_focus_ == EntryFocus::oneliners);
        status_.clear();
        return;
      }
      if (key->action == termforge::KeyAction::Press && key->ctrl &&
          (key->ch == U'c' || key->ch == U'C')) {
        quit();
        return;
      }
      // A piped OpenSSH client commonly sends LF as Ctrl+J rather than CR.
      // It is a submit key, never a printable "j" in the echo field.
      if (key->action == termforge::KeyAction::Press &&
          (key->key == termforge::Key::Enter ||
           (key->ctrl && (key->ch == U'j' || key->ch == U'J' ||
                          key->ch == U'm' || key->ch == U'M'))) &&
          !(screen_mode_ == ScreenMode::compose && (key->shift || key->alt))) {
        if (screen_mode_ == ScreenMode::subject) {
          begin_new_thread_body();
        } else if (screen_mode_ == ScreenMode::compose) {
          submit_composition();
        } else if (screen_mode_ == ScreenMode::report) {
          submit_report();
        } else if (screen_mode_ == ScreenMode::boards &&
                   input_.text().empty()) {
          if (entry_focus_ == EntryFocus::oneliners) {
            open_selected_oneliner();
          } else {
            open_selected_board();
          }
        } else if (screen_mode_ == ScreenMode::threads &&
                   input_.text().empty()) {
          open_selected_thread();
        } else if (identity_.kind == IdentityKind::registration) {
          submit_registration();
        } else if (screen_mode_ == ScreenMode::tos &&
                   (identity_.kind == IdentityKind::pending ||
                    identity_.kind == IdentityKind::tos_required)) {
          submit_tos_command();
        } else if (identity_.kind == IdentityKind::tos_required) {
          submit_restricted_command();
        } else if (identity_.kind == IdentityKind::active) {
          submit_active_command();
        }
        return;
      }
      if (key->action == termforge::KeyAction::Press &&
          screen_mode_ == ScreenMode::boards && !key->ctrl && !key->alt &&
          key->ch == U'!' && input_.text().empty()) {
        begin_oneliner_report();
        return;
      }
      if (key->action == termforge::KeyAction::Press &&
          screen_mode_ == ScreenMode::threads && !key->ctrl && !key->alt) {
        if ((key->ch == U'n' || key->ch == U'N') && may_post()) {
          input_.set_text({});
          screen_mode_ = ScreenMode::subject;
          status_.clear();
          return;
        }
        if ((key->ch == U'c' || key->ch == U'C') &&
            identity_.kind != IdentityKind::guest) {
          catch_up_selected_board();
          return;
        }
      }
      if (key->action == termforge::KeyAction::Press &&
          screen_mode_ == ScreenMode::thread && !key->ctrl && !key->alt) {
        if ((key->ch == U'r' || key->ch == U'R') && may_post()) {
          begin_reply(false);
          return;
        }
        if ((key->ch == U'q' || key->ch == U'Q') && may_post()) {
          begin_reply(true);
          return;
        }
        if (key->ch == U'!') {
          if (messages_.empty()) {
            status_ = "There is no post to report.";
            return;
          }
          report_target_ = store::ContentRef{store::ContentKind::message,
                                             messages_.back().message_id};
          report_return_mode_ = ScreenMode::thread;
          composer_.clear();
          screen_mode_ = ScreenMode::report;
          status_.clear();
          return;
        }
        if (key->ch == U'T' && selected_thread_ < threads_.size()) {
          report_target_ = store::ContentRef{
              store::ContentKind::thread, threads_[selected_thread_].thread_id};
          report_return_mode_ = ScreenMode::thread;
          composer_.clear();
          screen_mode_ = ScreenMode::report;
          status_.clear();
          return;
        }
      }
    }

    if (std::holds_alternative<termforge::ResizeEvent>(event)) {
      TerminalDimensions dimensions;
      {
        std::lock_guard lock(shared_.mutex);
        dimensions = shared_.dimensions;
      }
      const auto current = current_size();
      const termforge::App::Size wanted{dimensions.columns, dimensions.rows,
                                        dimensions.pixel_width,
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
        notice_ = shared_.notice;
        return;
      }
      if (error->source == "oneliners") {
        if (screen_mode_ == ScreenMode::boards) {
          shared_.oneliners_dirty.store(false, std::memory_order_release);
          load_oneliners();
        }
        return;
      }
      status_ = error->message;
      if (error->severity == termforge::Severity::Error) {
        quit();
      }
      return;
    }

    if (screen_mode_ == ScreenMode::tos && tos_box_.on_event(event)) {
      return;
    }

    if (screen_mode_ == ScreenMode::boards) {
      auto &entry_list =
          entry_focus_ == EntryFocus::oneliners ? oneliner_list_ : board_list_;
      if (entry_list.on_event(event)) {
        return;
      }
    }
    if (screen_mode_ == ScreenMode::threads && thread_list_.on_event(event)) {
      return;
    }
    if (screen_mode_ == ScreenMode::thread && message_box_.on_event(event)) {
      return;
    }
    if (screen_mode_ == ScreenMode::oneliner && oneliner_box_.on_event(event)) {
      return;
    }
    if ((screen_mode_ == ScreenMode::compose ||
         screen_mode_ == ScreenMode::report) &&
        composer_.on_event(event)) {
      return;
    }

    if (((identity_.kind == IdentityKind::registration &&
          registration_mode_ != RegistrationMode::closed) ||
         identity_.kind == IdentityKind::pending ||
         identity_.kind == IdentityKind::tos_required ||
         identity_.kind == IdentityKind::active ||
         screen_mode_ == ScreenMode::subject) &&
        input_.on_event(event)) {
      return;
    }
    termforge::App::on_event(event);
  }

  auto on_render(termforge::Screen &screen) -> void override {
    shared_.oneliner_wall_visible.store(screen_mode_ == ScreenMode::boards,
                                        std::memory_order_release);
    if (screen_mode_ == ScreenMode::boards &&
        shared_.oneliners_dirty.exchange(false, std::memory_order_acq_rel)) {
      load_oneliners();
    }
    constexpr termforge::Rgb foreground{0xE0, 0xE0, 0xF0};
    constexpr termforge::Rgb accent{0x70, 0xC0, 0xFF};
    constexpr termforge::Rgb background{0x0A, 0x0A, 0x14};
    screen.clear(foreground, background);

    const auto title = "Anvil board session " + std::to_string(::getpid());
    static_cast<void>(screen.write_text(0, 0, title, accent, background));
    const auto dimensions =
        std::to_string(screen.cols()) + "x" + std::to_string(screen.rows());
    static_cast<void>(screen.write_text(0, 1, "Terminal: " + dimensions,
                                        foreground, background));
    if (identity_.kind == IdentityKind::registration) {
      render_registration(screen, foreground, accent, background);
    } else if ((identity_.kind == IdentityKind::pending ||
                identity_.kind == IdentityKind::tos_required) &&
               screen_mode_ == ScreenMode::tos) {
      render_tos(screen, foreground, accent, background);
    } else {
      render_board_screen(screen, foreground, accent, background);
    }
    auto issued_message =
        issued_invite_code_.empty()
            ? std::string{}
            : "Invite: " + issued_invite_code_ + " (" +
                  std::to_string(issued_invite_balance_) +
                  " remaining; expires in " +
                  std::to_string(invite_policy_.expiration.count()) +
                  " seconds)";
    const auto &message = !notice_.empty()          ? notice_
                          : !issued_message.empty() ? issued_message
                                                    : status_;
    if (!message.empty() && screen.rows() > 4) {
      const auto status = sanitize_prose_for_render(message);
      static_cast<void>(
          screen.write_text(0, screen.rows() - 1, status, accent, background));
    }
  }

private:
  enum class RegistrationStep { invite_code, handle };
  enum class ScreenMode {
    boards,
    oneliner,
    threads,
    thread,
    subject,
    compose,
    report,
    tos,
  };
  enum class EntryFocus { boards, oneliners };
  enum class ComposeAction { new_thread, reply };

  void append_tos_text() {
    std::size_t start = 0;
    while (start <= tos_policy_.text.size()) {
      const auto end = tos_policy_.text.find('\n', start);
      auto line = tos_policy_.text.substr(
          start, end == std::string::npos ? std::string::npos : end - start);
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      tos_box_.append(std::move(line));
      if (end == std::string::npos) {
        break;
      }
      start = end + 1U;
    }
  }

  [[nodiscard]] auto board_reader() const -> store::BoardReader {
    if (identity_.kind == IdentityKind::active ||
        identity_.kind == IdentityKind::tos_required) {
      return {.handle = identity_.handle, .may_read_registered = true};
    }
    return {};
  }

  [[nodiscard]] bool may_post() const noexcept {
    return identity_.kind == IdentityKind::active;
  }

  void load_boards() {
    auto read = identity_store_.begin(store::TransactionMode::read_only);
    if (!read) {
      status_ = "Boards are temporarily unavailable.";
      return;
    }
    auto boards = identity_store_.list_boards(*read, board_reader());
    if (!boards || !read->commit()) {
      status_ = "Boards are temporarily unavailable.";
      return;
    }
    boards_ = std::move(*boards);
    std::vector<std::string> items;
    items.reserve(boards_.size());
    for (const auto &board : boards_) {
      auto item = board.title;
      if (board.unread_messages > 0U) {
        item += " (" + std::to_string(board.unread_messages) + " new)";
      }
      items.push_back(std::move(item));
    }
    board_list_.set_items(std::move(items));
    if (!boards_.empty()) {
      board_list_.set_selected(
          static_cast<int>(std::min(selected_board_, boards_.size() - 1U)));
    }
  }

  void load_oneliners() {
    const auto selected = oneliner_list_.selected();
    const auto selected_id =
        selected >= 0 && static_cast<std::size_t>(selected) < oneliners_.size()
            ? oneliners_[static_cast<std::size_t>(selected)].oneliner_id
            : std::string{};
    auto read = identity_store_.begin(store::TransactionMode::read_only);
    if (!read) {
      status_ = "One-liners are temporarily unavailable.";
      return;
    }
    auto oneliners =
        identity_store_.list_oneliners(*read, utc_now(), oneliner_policy_, 100);
    if (!oneliners || !read->commit()) {
      status_ = "One-liners are temporarily unavailable.";
      return;
    }
    oneliners_ = std::move(*oneliners);
    std::vector<std::string> items;
    items.reserve(oneliners_.size());
    for (const auto &oneliner : oneliners_) {
      items.push_back("@" + sanitize_prose_for_render(oneliner.author_handle) +
                      ": " + sanitize_prose_for_render(oneliner.body));
    }
    oneliner_list_.set_items(std::move(items));
    if (!selected_id.empty()) {
      const auto match = std::ranges::find(oneliners_, selected_id,
                                           &store::OnelinerRecord::oneliner_id);
      if (match != oneliners_.end()) {
        oneliner_list_.set_selected(
            static_cast<int>(std::distance(oneliners_.begin(), match)));
      }
    }
  }

  void open_selected_oneliner() {
    const auto selected = oneliner_list_.selected();
    if (selected < 0 ||
        static_cast<std::size_t>(selected) >= oneliners_.size()) {
      status_ = "No one-liner is selected.";
      return;
    }
    const auto &oneliner = oneliners_[static_cast<std::size_t>(selected)];
    oneliner_box_.clear();
    oneliner_box_.append("@" +
                         sanitize_prose_for_render(oneliner.author_handle));
    oneliner_box_.append(std::string{});
    oneliner_box_.append(sanitize_prose_for_render(oneliner.body));
    screen_mode_ = ScreenMode::oneliner;
    status_.clear();
  }

  void begin_oneliner_report() {
    if (entry_focus_ != EntryFocus::oneliners) {
      status_ = "Select the one-liner wall with Tab before reporting.";
      return;
    }
    const auto selected = oneliner_list_.selected();
    if (selected < 0 ||
        static_cast<std::size_t>(selected) >= oneliners_.size()) {
      status_ = "There is no one-liner to report.";
      return;
    }
    report_target_ = store::ContentRef{
        store::ContentKind::oneliner,
        oneliners_[static_cast<std::size_t>(selected)].oneliner_id};
    report_return_mode_ = ScreenMode::boards;
    composer_.clear();
    screen_mode_ = ScreenMode::report;
    status_.clear();
  }

  void open_selected_board() {
    const auto selected = board_list_.selected();
    if (selected < 0 || static_cast<std::size_t>(selected) >= boards_.size()) {
      status_ = "No board is selected.";
      return;
    }
    selected_board_ = static_cast<std::size_t>(selected);
    auto read = identity_store_.begin(store::TransactionMode::read_only);
    if (!read) {
      status_ = "Threads are temporarily unavailable.";
      return;
    }
    auto threads = identity_store_.list_threads(
        *read, boards_[selected_board_].board_id, board_reader());
    if (!threads || !read->commit()) {
      status_ = "Threads are temporarily unavailable.";
      return;
    }
    threads_ = std::move(*threads);
    std::vector<std::string> items;
    items.reserve(threads_.size());
    for (const auto &thread : threads_) {
      auto item =
          thread.subject + " [" + std::to_string(thread.message_count) + "]";
      if (thread.unread_messages > 0U) {
        item += " (" + std::to_string(thread.unread_messages) + " new)";
      }
      if (thread.locked) {
        item += " [locked]";
      }
      items.push_back(std::move(item));
    }
    thread_list_.set_items(std::move(items));
    selected_thread_ = 0U;
    screen_mode_ = ScreenMode::threads;
    status_.clear();
  }

  void open_selected_thread() {
    const auto selected = thread_list_.selected();
    if (selected < 0 || static_cast<std::size_t>(selected) >= threads_.size()) {
      status_ = "No thread is selected.";
      return;
    }
    selected_thread_ = static_cast<std::size_t>(selected);
    const auto mode = identity_.kind == IdentityKind::guest
                          ? store::TransactionMode::read_only
                          : store::TransactionMode::read_write;
    auto transaction = identity_store_.begin(mode);
    if (!transaction) {
      status_ = "Messages are temporarily unavailable.";
      return;
    }
    const auto &thread = threads_[selected_thread_];
    auto messages = identity_store_.list_messages_for_thread(
        *transaction, thread.board_id, thread.thread_id, board_reader());
    if (!messages) {
      status_ = "Messages are temporarily unavailable.";
      return;
    }
    if (identity_.kind != IdentityKind::guest) {
      auto marked = identity_store_.mark_thread_read(
          *transaction, identity_.handle, thread.board_id, thread.thread_id);
      if (!marked) {
        status_ = "Could not save the read position.";
        return;
      }
    }
    if (!transaction->commit()) {
      status_ = "Messages are temporarily unavailable.";
      return;
    }
    messages_ = std::move(*messages);
    message_box_.clear();
    for (const auto &message : messages_) {
      if (message.parent_message_id) {
        const auto parent = std::ranges::find_if(
            messages_, [&](const store::MessageRecord &candidate) {
              return candidate.message_id == *message.parent_message_id;
            });
        const auto quoted_author = parent == messages_.end()
                                       ? std::string{"unknown"}
                                       : parent->author_handle;
        message_box_.append("Reply to @" + quoted_author + " [" +
                            *message.parent_message_id + "]");
      }
      message_box_.append("@" + message.author_handle + ": " + message.body);
      message_box_.append(std::string{});
    }
    screen_mode_ = ScreenMode::thread;
    status_.clear();
  }

  void catch_up_selected_board() {
    if (selected_board_ >= boards_.size()) {
      return;
    }
    auto write = identity_store_.begin(store::TransactionMode::read_write);
    if (!write ||
        !identity_store_.catch_up_board(*write, identity_.handle,
                                        boards_[selected_board_].board_id) ||
        !write->commit()) {
      status_ = "Could not catch up this board.";
      return;
    }
    load_boards();
    open_selected_board();
    status_ = "Board marked read through the latest message.";
  }

  void begin_new_thread_body() {
    auto subject = prepare_user_text_for_ingest(
        UserTextField::subject, RemoteBytes::from_text(input_.text()));
    if (!subject || subject->empty()) {
      status_ = "Subject must contain 1 to 120 graphemes.";
      return;
    }
    pending_subject_ = std::move(*subject);
    input_.set_text({});
    composer_.clear();
    compose_action_ = ComposeAction::new_thread;
    quote_parent_.reset();
    screen_mode_ = ScreenMode::compose;
    status_.clear();
  }

  void begin_reply(bool quote) {
    quote_parent_.reset();
    if (quote && !messages_.empty()) {
      quote_parent_ = messages_.back().message_id;
    }
    composer_.clear();
    compose_action_ = ComposeAction::reply;
    screen_mode_ = ScreenMode::compose;
    status_.clear();
  }

  void submit_composition() {
    auto body = prepare_user_text_for_ingest(
        UserTextField::post_body, RemoteBytes::from_text(composer_.text()));
    if (!body || body->empty()) {
      status_ = "Post body must contain 1 to 16384 graphemes.";
      return;
    }
    if (selected_board_ >= boards_.size()) {
      status_ = "The selected board is no longer available.";
      return;
    }
    auto write = identity_store_.begin(store::TransactionMode::read_write);
    if (!write) {
      status_ = "Posting is temporarily unavailable.";
      return;
    }
    const auto now = utc_now();
    std::expected<store::MessageRecord, store::Error> created =
        std::unexpected(store::Error{});
    if (compose_action_ == ComposeAction::new_thread) {
      created = identity_store_.create_thread(
          *write, {.board_id = boards_[selected_board_].board_id,
                   .thread_id = random_content_id("thread-"),
                   .message_id = random_content_id("message-"),
                   .author_handle = identity_.handle,
                   .subject = pending_subject_,
                   .body = *body,
                   .created_at = now});
    } else if (selected_thread_ < threads_.size()) {
      created = identity_store_.create_reply(
          *write, {.board_id = boards_[selected_board_].board_id,
                   .thread_id = threads_[selected_thread_].thread_id,
                   .message_id = random_content_id("message-"),
                   .parent_message_id = quote_parent_,
                   .author_handle = identity_.handle,
                   .body = *body,
                   .created_at = now});
    }
    if (!created || !write->commit()) {
      status_ = "Posting failed; no partial post was saved.";
      return;
    }
    composer_.push_history(*body);
    composer_.clear();
    if (compose_action_ == ComposeAction::new_thread) {
      open_selected_board();
      open_selected_thread();
      status_ = "Thread posted.";
    } else {
      open_selected_thread();
      status_ = "Reply posted.";
    }
  }

  [[nodiscard]] bool request_guest_report_permit() const noexcept {
    if (guest_report_permit_descriptor_ < 0) {
      return false;
    }
    constexpr std::uint8_t request = 1U;
    ssize_t sent{};
    do {
      sent = ::send(guest_report_permit_descriptor_, &request, sizeof(request),
                    MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent != static_cast<ssize_t>(sizeof(request))) {
      return false;
    }
    pollfd descriptor{
        .fd = guest_report_permit_descriptor_, .events = POLLIN, .revents = 0};
    int ready{};
    do {
      ready = ::poll(&descriptor, 1, 1500);
    } while (ready < 0 && errno == EINTR);
    if (ready <= 0 || (descriptor.revents & POLLIN) == 0) {
      return false;
    }
    std::uint8_t allowed{};
    const auto received =
        ::recv(guest_report_permit_descriptor_, &allowed, sizeof(allowed), 0);
    return received == static_cast<ssize_t>(sizeof(allowed)) && allowed == 1U;
  }

  void submit_report() {
    auto reason =
        prepare_user_text_for_ingest(UserTextField::file_description,
                                     RemoteBytes::from_text(composer_.text()));
    if (!reason || reason->empty() || !report_target_) {
      status_ = "Report reason must contain 1 to 1024 graphemes.";
      return;
    }
    if (identity_.kind == IdentityKind::guest &&
        !request_guest_report_permit()) {
      status_ = "Anonymous report limit reached; try again later.";
      return;
    }
    auto write = identity_store_.begin(store::TransactionMode::read_write);
    const auto reporter = identity_.kind == IdentityKind::guest
                              ? std::nullopt
                              : std::optional<std::string>{identity_.handle};
    if (!write ||
        !identity_store_.submit_report(
            *write, {.report_id = random_content_id("report-"),
                     .reporter_handle = reporter,
                     .target = *report_target_,
                     .reason = *reason,
                     .created_at = utc_now()}) ||
        !write->commit()) {
      status_ = "Report failed; no partial report was saved.";
      return;
    }
    composer_.clear();
    report_target_.reset();
    screen_mode_ = report_return_mode_;
    status_ = "Report submitted.";
  }

  void render_board_screen(termforge::Screen &screen, termforge::Rgb foreground,
                           termforge::Rgb accent, termforge::Rgb background) {
    const auto identity_line =
        identity_.kind == IdentityKind::guest
            ? std::string{"Guest access: boards and doors are read-only."}
        : identity_.kind == IdentityKind::tos_required
            ? std::string{"TOS changed: read-only until accepted (/tos)."}
            : "Signed in as " + identity_.handle +
                  ". Type /invite to issue an invite code.";
    static_cast<void>(
        screen.write_text(0, 2, identity_line, foreground, background));
    const auto body_height = std::max(1, screen.rows() - 7);
    if (screen_mode_ == ScreenMode::boards) {
      static_cast<void>(screen.write_text(
          0, 3, "One-liners - Tab focus, arrows move, Enter opens, ! reports",
          accent, background));
      oneliner_list_.set_geometry(termforge::Rect{0, 4, screen.cols(), 4});
      oneliner_list_.draw(screen);
      static_cast<void>(screen.write_text(
          0, 8, "Boards - Tab focus, arrows move, Enter opens, Esc exits",
          accent, background));
      board_list_.set_geometry(termforge::Rect{
          0, 9, screen.cols(), std::max(1, screen.rows() - 12)});
      board_list_.draw(screen);
      if (identity_.kind != IdentityKind::guest && screen.rows() > 2) {
        input_.set_geometry(
            termforge::Rect{0, screen.rows() - 2, screen.cols(), 1});
        input_.draw(screen);
      }
    } else if (screen_mode_ == ScreenMode::oneliner) {
      static_cast<void>(screen.write_text(0, 3, "One-liner detail - Esc back",
                                          accent, background));
      oneliner_box_.set_geometry(
          termforge::Rect{0, 4, screen.cols(), body_height + 1});
      oneliner_box_.draw(screen);
    } else if (screen_mode_ == ScreenMode::threads) {
      const auto board_title = selected_board_ < boards_.size()
                                   ? boards_[selected_board_].title
                                   : std::string{"Board"};
      const auto help = may_post()
                            ? " - Enter opens, n new, c catch up, Esc back"
                        : identity_.kind == IdentityKind::guest
                            ? " - Enter opens, Esc back"
                            : " - Enter opens, c catch up, Esc back";
      static_cast<void>(
          screen.write_text(0, 3, board_title + help, accent, background));
      thread_list_.set_geometry(
          termforge::Rect{0, 4, screen.cols(), body_height + 1});
      thread_list_.draw(screen);
    } else if (screen_mode_ == ScreenMode::thread) {
      const auto subject = selected_thread_ < threads_.size()
                               ? threads_[selected_thread_].subject
                               : std::string{"Thread"};
      const auto help =
          may_post()
              ? " - r reply, q quote, ! post report, T thread report, Esc back"
              : " - ! post report, T thread report, Esc back";
      static_cast<void>(
          screen.write_text(0, 3, subject + help, accent, background));
      message_box_.set_geometry(
          termforge::Rect{0, 4, screen.cols(), body_height + 1});
      message_box_.draw(screen);
    } else if (screen_mode_ == ScreenMode::subject) {
      static_cast<void>(screen.write_text(
          0, 3, "New thread subject (Enter continues, Esc cancels)", accent,
          background));
      input_.set_geometry(termforge::Rect{0, 5, screen.cols(), 1});
      input_.draw(screen);
    } else {
      const auto prompt =
          screen_mode_ == ScreenMode::report
              ? "Report reason (Enter submits, Esc cancels)"
              : "Post body (Enter submits, Shift+Enter newline)";
      static_cast<void>(screen.write_text(0, 3, prompt, accent, background));
      composer_.set_geometry(
          termforge::Rect{0, 4, screen.cols(), body_height + 1});
      composer_.draw(screen);
    }
  }

  void render_tos(termforge::Screen &screen, termforge::Rgb foreground,
                  termforge::Rgb accent, termforge::Rgb background) {
    const auto version = sanitize_prose_for_render(tos_policy_.version);
    static_cast<void>(screen.write_text(0, 2, "Terms of service " + version,
                                        accent, background));
    const auto body_height = std::max(0, screen.rows() - 6);
    tos_box_.set_geometry(termforge::Rect{0, 3, screen.cols(), body_height});
    if (!tos_positioned_) {
      tos_box_.scroll(-std::numeric_limits<int>::max());
      tos_positioned_ = true;
    }
    tos_box_.draw(screen);
    if (screen.rows() > 3) {
      const auto prompt_row = std::max(3, screen.rows() - 3);
      const auto prompt = identity_.kind == IdentityKind::tos_required
                              ? "Type ACCEPT, or /browse for read-only access."
                              : "Type ACCEPT to complete registration.";
      static_cast<void>(
          screen.write_text(0, prompt_row, prompt, foreground, background));
      input_.set_geometry(termforge::Rect{
          0, std::min(screen.rows() - 2, prompt_row + 1), screen.cols(), 1});
      input_.draw(screen);
    }
  }

  void render_registration(termforge::Screen &screen, termforge::Rgb foreground,
                           termforge::Rgb accent, termforge::Rgb background) {
    if (registration_mode_ == RegistrationMode::closed) {
      static_cast<void>(screen.write_text(
          0, 2, "This board is not accepting new registrations.", accent,
          background));
      if (screen.rows() > 3) {
        static_cast<void>(screen.write_text(
            0, 3, "Guest browsing remains available with: ssh guest@HOST",
            foreground, background));
      }
      return;
    }

    const auto invite_prompt =
        registration_mode_ == RegistrationMode::invite &&
        registration_step_ == RegistrationStep::invite_code;
    const std::string_view prompt =
        invite_prompt ? "Enter an invite code, then press Enter."
                      : "Choose a handle, then press Enter.";
    static_cast<void>(screen.write_text(0, 2, prompt, foreground, background));
    if (screen.rows() > 3) {
      const std::string_view detail =
          invite_prompt
              ? "Invite codes are single-use. Invalid codes reveal no details."
              : "There is no email recovery. Losing every key loses the "
                "account.";
      static_cast<void>(
          screen.write_text(0, 3, detail, foreground, background));
    }
    if (screen.rows() > 4) {
      input_.set_geometry(termforge::Rect{0, 4, screen.cols(), 1});
      input_.draw(screen);
    }
  }

  void submit_registration() {
    if (registration_mode_ == RegistrationMode::closed) {
      return;
    }
    if (registration_mode_ == RegistrationMode::invite &&
        registration_step_ == RegistrationStep::invite_code) {
      if (!hash_invite_code(input_.text())) {
        status_ = "Invite code is invalid or no longer available.";
        return;
      }
      invite_code_ = input_.text();
      input_.set_text({});
      registration_step_ = RegistrationStep::handle;
      status_.clear();
      return;
    }

    const auto prepared = prepare_user_text_for_ingest(
        UserTextField::handle, RemoteBytes::from_text(input_.text()));
    if (!prepared) {
      status_ = "Handle must use 1-32 ASCII letters, digits, '_' or '-'.";
      return;
    }
    const auto now = store::UtcEpochSeconds{
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count()};
    const auto invite = registration_mode_ == RegistrationMode::invite
                            ? std::optional<std::string_view>{invite_code_}
                            : std::nullopt;
    auto provisioned = provision_pending_identity(identity_store_, identity_,
                                                  *prepared, now, invite);
    if (!provisioned) {
      if (provisioned.error() == AuthenticationError::conflict) {
        status_ = "That handle is unavailable.";
      } else if (provisioned.error() ==
                 AuthenticationError::invite_unavailable) {
        clear_invite_code();
        input_.set_text({});
        registration_step_ = RegistrationStep::invite_code;
        status_ = "Invite code is invalid or no longer available.";
      } else {
        status_ = "Registration is temporarily unavailable.";
      }
      return;
    }
    identity_ = std::move(*provisioned);
    clear_invite_code();
    input_.set_text({});
    screen_mode_ = ScreenMode::tos;
    tos_positioned_ = false;
    status_ = "Key saved. Review and accept the current TOS.";
  }

  void submit_tos_command() {
    if (input_.text() == "/browse" &&
        identity_.kind == IdentityKind::tos_required) {
      input_.set_text({});
      screen_mode_ = ScreenMode::boards;
      load_boards();
      load_oneliners();
      status_ = "Read-only access. Type /tos to review the current terms.";
      return;
    }
    if (input_.text() != "ACCEPT") {
      status_ = identity_.kind == IdentityKind::tos_required
                    ? "Type ACCEPT to agree, or /browse for read-only access."
                    : "Type ACCEPT exactly to complete registration.";
      return;
    }
    input_.set_text({});
    const auto now = store::UtcEpochSeconds{
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count()};
    auto accepted = accept_current_tos(identity_store_, identity_,
                                       tos_policy_.version, now);
    if (!accepted) {
      status_ = "TOS acceptance is temporarily unavailable.";
      return;
    }
    identity_ = std::move(*accepted);
    screen_mode_ = ScreenMode::boards;
    load_boards();
    load_oneliners();
    status_ = "Current terms accepted.";
  }

  void submit_restricted_command() {
    if (input_.text() == "/tos") {
      input_.set_text({});
      screen_mode_ = ScreenMode::tos;
      tos_positioned_ = false;
      status_.clear();
      return;
    }
    input_.set_text({});
    status_ = "Accept the current TOS before using write actions.";
  }

  void submit_active_command() {
    const auto command = input_.text();
    if (command.empty()) {
      return;
    }
    input_.set_text({});
    if (command.front() != '/') {
      submit_oneliner(command);
      return;
    }
    if (command != "/invite") {
      status_ = "Unknown command.";
      return;
    }
    const auto now = store::UtcEpochSeconds{
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count()};
    auto issued = issue_invite_code(identity_store_, identity_.handle, now,
                                    invite_policy_);
    if (!issued) {
      status_ = issued.error() == AuthenticationError::conflict
                    ? "No invite credit is currently available."
                    : "Invite issuance is temporarily unavailable.";
      return;
    }
    issued_invite_code_ = std::move(issued->code);
    issued_invite_balance_ = issued->remaining_balance;
    status_.clear();
  }

  void submit_oneliner(std::string_view input) {
    auto body = prepare_user_text_for_ingest(UserTextField::oneliner,
                                             RemoteBytes::from_text(input));
    if (!body || body->empty()) {
      status_ = "One-liner must be one line containing 1 to 280 graphemes.";
      return;
    }
    const auto now = utc_now();
    auto write = identity_store_.begin(store::TransactionMode::read_write);
    if (!write) {
      status_ = "One-liner posting is temporarily unavailable.";
      return;
    }
    auto created = identity_store_.create_oneliner(
        *write,
        {.oneliner_id = random_content_id("oneliner-"),
         .author_handle = identity_.handle,
         .body = std::move(*body),
         .posted_at = now,
         .received_at = now},
        oneliner_policy_);
    if (!created) {
      status_ = created.error().code == store::ErrorCode::conflict
                    ? "One-liner limit reached; try again later."
                    : "One-liner posting failed; no partial post was saved.";
      return;
    }
    if (!write->commit()) {
      status_ = "One-liner posting failed; no partial post was saved.";
      return;
    }
    load_oneliners();
    const auto notified =
        oneliner_published_hook_ == nullptr ||
        oneliner_published_hook_(worker_report_descriptor_, session_id_);
    status_ = notified ? "One-liner posted."
                       : "One-liner posted; live refresh is unavailable.";
  }

  void clear_invite_code() noexcept {
    std::fill(invite_code_.begin(), invite_code_.end(), '\0');
    invite_code_.clear();
  }

  void clear_issued_invite_code() noexcept {
    std::fill(issued_invite_code_.begin(), issued_invite_code_.end(), '\0');
    issued_invite_code_.clear();
  }

  SocketSink sink_;
  std::chrono::steady_clock::time_point channel_opened_;
  SharedState &shared_;
  SessionIdentity identity_;
  store::Store &identity_store_;
  RegistrationMode registration_mode_{RegistrationMode::open};
  InvitePolicy invite_policy_;
  TosPolicy tos_policy_;
  int guest_report_permit_descriptor_{-1};
  store::OnelinerPolicy oneliner_policy_;
  OnelinerPublishedHook oneliner_published_hook_{};
  int worker_report_descriptor_{-1};
  std::uint64_t session_id_{};
  ScreenMode screen_mode_{ScreenMode::boards};
  termforge::TextBox tos_box_;
  termforge::ListWidget board_list_;
  termforge::ListWidget oneliner_list_;
  termforge::ListWidget thread_list_;
  termforge::TextBox message_box_;
  termforge::TextBox oneliner_box_;
  termforge::Composer composer_;
  std::vector<store::BoardRecord> boards_;
  std::vector<store::ThreadRecord> threads_;
  std::vector<store::MessageRecord> messages_;
  std::vector<store::OnelinerRecord> oneliners_;
  std::size_t selected_board_{};
  std::size_t selected_thread_{};
  EntryFocus entry_focus_{EntryFocus::boards};
  ComposeAction compose_action_{ComposeAction::reply};
  std::optional<std::string> quote_parent_;
  std::optional<store::ContentRef> report_target_;
  ScreenMode report_return_mode_{ScreenMode::thread};
  std::string pending_subject_;
  bool tos_positioned_{};
  RegistrationStep registration_step_{RegistrationStep::invite_code};
  termforge::TextInput input_;
  std::string invite_code_;
  std::string issued_invite_code_;
  std::uint32_t issued_invite_balance_{};
  std::string accepted_input_;
  std::string status_;
  std::string notice_;
};

} // namespace

TerminalDimensions normalize_initial_dimensions(int columns, int rows,
                                                int pixel_width,
                                                int pixel_height) noexcept {
  const auto [width, height] = normalize_pixels(pixel_width, pixel_height);
  if (!valid_cells(columns, rows)) {
    return TerminalDimensions{80, 24, width, height};
  }
  return TerminalDimensions{columns, rows, width, height};
}

std::optional<TerminalDimensions>
normalize_resize_dimensions(int columns, int rows, int pixel_width,
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
  Impl(int io_descriptor, std::string terminal_type,
       TerminalDimensions dimensions,
       std::chrono::steady_clock::time_point channel_opened,
       SessionResourceLimits resource_limits,
       RegistrationMode registration_mode, InvitePolicy invite_policy,
       TosPolicy tos_policy, SessionIdentity identity,
       store::Store &identity_store, SessionInputHook input_hook_for_testing,
       int guest_report_permit_descriptor,
       store::OnelinerPolicy oneliner_policy,
       OnelinerPublishedHook oneliner_published_hook,
       int worker_report_descriptor, std::uint64_t session_id)
      : shared_(dimensions, resource_limits),
        app_(io_descriptor, std::move(terminal_type), dimensions,
             channel_opened, shared_, std::move(identity), identity_store,
             registration_mode, invite_policy, std::move(tos_policy),
             input_hook_for_testing, guest_report_permit_descriptor,
             oneliner_policy, oneliner_published_hook, worker_report_descriptor,
             session_id) {}

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
        failure_reason_.store(failure_reason_for(error.reason()),
                              std::memory_order_release);
      } catch (const std::bad_alloc &) {
        shared_.resources.mark_exceeded(ResourceLimitReason::memory);
        failure_reason_.store(SessionFailureReason::memory_limit,
                              std::memory_order_release);
      } catch (const std::exception &) {
        failure_reason_.store(SessionFailureReason::standard_exception,
                              std::memory_order_release);
      } catch (...) {
        failure_reason_.store(SessionFailureReason::unknown_exception,
                              std::memory_order_release);
      }
      if (const auto limit = shared_.resources.limit_reason();
          limit != ResourceLimitReason::none) {
        failure_reason_.store(failure_reason_for(limit),
                              std::memory_order_release);
      }
      finished_.store(true, std::memory_order_release);
    });
  }

  void post_resize(TerminalDimensions dimensions) {
    {
      std::lock_guard lock(shared_.mutex);
      shared_.dimensions = dimensions;
    }
    app_.post(termforge::Event{
        termforge::ResizeEvent{dimensions.columns, dimensions.rows}});
  }

  void post_notice(std::string notice) {
    {
      std::lock_guard lock(shared_.mutex);
      shared_.notice = std::move(notice);
    }
    app_.post(termforge::Event{termforge::ErrorEvent{
        termforge::Severity::Info, "ssh", "session notice changed"}});
  }

  void post_oneliners_changed() {
    shared_.oneliners_dirty.store(true, std::memory_order_release);
    if (shared_.oneliner_wall_visible.load(std::memory_order_acquire)) {
      app_.post(termforge::Event{termforge::ErrorEvent{
          termforge::Severity::Info, "oneliners", "one-liners changed"}});
    }
  }

  void request_stop() {
    if (shared_.stop_requested.exchange(true, std::memory_order_acq_rel)) {
      return;
    }
    app_.post(termforge::Event{termforge::ErrorEvent{
        termforge::Severity::Info, "ssh", "session stopping"}});
  }

  void join() {
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  [[nodiscard]] bool finished() const noexcept {
    return finished_.load(std::memory_order_acquire);
  }

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
    result.generation =
        shared_.progress_generation.load(std::memory_order_acquire);
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
  [[nodiscard]] static SessionFailureReason
  failure_reason_for(ResourceLimitReason reason) noexcept {
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

TerminalSession::TerminalSession(
    int io_descriptor, std::string terminal_type, TerminalDimensions dimensions,
    std::chrono::steady_clock::time_point channel_opened,
    SessionResourceLimits resource_limits, RegistrationMode registration_mode,
    const InvitePolicy &invite_policy, const TosPolicy &tos_policy,
    SessionIdentity identity, store::Store &identity_store,
    const store::OnelinerPolicy &oneliner_policy,
    SessionInputHook input_hook_for_testing, int guest_report_permit_descriptor,
    OnelinerPublishedHook oneliner_published_hook, int worker_report_descriptor,
    std::uint64_t session_id)
    : impl_(std::make_unique<Impl>(
          io_descriptor, std::move(terminal_type), dimensions, channel_opened,
          resource_limits, registration_mode, invite_policy, tos_policy,
          std::move(identity), identity_store, input_hook_for_testing,
          guest_report_permit_descriptor, oneliner_policy,
          oneliner_published_hook, worker_report_descriptor, session_id)) {}

TerminalSession::~TerminalSession() = default;

void TerminalSession::start() { impl_->start(); }

void TerminalSession::post_resize(TerminalDimensions dimensions) {
  impl_->post_resize(dimensions);
}

void TerminalSession::post_notice(std::string notice) {
  impl_->post_notice(std::move(notice));
}

void TerminalSession::post_oneliners_changed() {
  impl_->post_oneliners_changed();
}

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

SessionTelemetry TerminalSession::telemetry() const noexcept {
  return impl_->telemetry();
}

} // namespace anvil::server
