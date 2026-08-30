#include "health.hpp"

#if defined(__clang__)
// cpp-httplib owns inline parser functions with 16 KiB internal buffers.
// Anvil's 8 KiB frame policy applies again immediately after the adapter
// header; it is intentionally not imposed on this upstream implementation.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wframe-larger-than"
#endif
#include <httplib.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace anvil::server {
namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

constexpr std::uint32_t shared_magic = 0x414E5648U;
constexpr std::uint32_t shared_version = 1U;
constexpr std::size_t max_shared_sessions = 4096U;
constexpr std::size_t max_components = 64U;
constexpr std::size_t max_component_name = 128U;
constexpr std::size_t max_component_version = 64U;
constexpr std::size_t max_component_reason = 512U;
constexpr std::size_t max_startup_reason = 128U;
constexpr auto heartbeat_timeout = 3s;

struct SharedSession {
  bool occupied{};
  std::uint64_t id{};
  pid_t worker{};
  std::uint64_t resident_bytes{};
  SessionTelemetry telemetry;
};

struct SharedComponent {
  bool occupied{};
  ComponentKind kind{};
  ComponentState state{};
  std::array<char, max_component_name> name{};
  std::array<char, max_component_version> version{};
  std::array<char, max_component_reason> reason{};
};

struct SharedHealth {
  std::uint32_t magic{};
  std::uint32_t version{};
  pthread_mutex_t mutex{};
  bool accepting{};
  std::uint32_t max_sessions{};
  std::int64_t heartbeat_ns{};
  std::int64_t started_ns{};
  std::uint64_t supervisor_resident_bytes{};
  std::uint64_t registered_users{};
  std::uint64_t door_sessions{};
  std::array<SharedSession, max_shared_sessions> sessions{};
  std::array<SharedComponent, max_components> components{};
};

struct StartupStatus {
  std::uint8_t ready{};
  std::array<char, max_startup_reason> reason{};
};

static_assert(std::is_trivially_copyable_v<StartupStatus>);

[[nodiscard]] std::int64_t to_ns(Clock::time_point value) noexcept {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(value.time_since_epoch()).count();
}

[[nodiscard]] Clock::time_point from_ns(std::int64_t value) noexcept {
  return Clock::time_point(std::chrono::nanoseconds(value));
}

class SharedLock {
 public:
  explicit SharedLock(pthread_mutex_t &mutex) : mutex_(&mutex) {
    const auto result = ::pthread_mutex_lock(mutex_);
    if (result == EOWNERDEAD) {
      if (::pthread_mutex_consistent(mutex_) != 0) {
        throw std::runtime_error("cannot recover health state lock");
      }
      return;
    }
    if (result != 0) {
      throw std::system_error(result, std::generic_category(), "cannot lock health state");
    }
  }

  ~SharedLock() {
    if (mutex_ != nullptr) {
      static_cast<void>(::pthread_mutex_unlock(mutex_));
    }
  }

  SharedLock(const SharedLock &) = delete;
  auto operator=(const SharedLock &) -> SharedLock & = delete;

 private:
  pthread_mutex_t *mutex_;
};

template <std::size_t Size>
void copy_bounded(std::array<char, Size> &destination, std::string_view source) noexcept {
  destination.fill('\0');
  const auto length = std::min(source.size(), Size - 1U);
  std::memcpy(destination.data(), source.data(), length);
}

template <std::size_t Size>
[[nodiscard]] std::string read_bounded(const std::array<char, Size> &source) {
  const auto end = std::find(source.begin(), source.end(), '\0');
  return std::string(source.begin(), end);
}

[[nodiscard]] std::uint64_t resident_bytes(pid_t process) noexcept {
  std::ifstream status("/proc/" + std::to_string(process) + "/statm");
  std::uint64_t pages = 0;
  std::uint64_t resident = 0;
  if (!(status >> pages >> resident)) {
    return 0;
  }
  const auto page_size = ::sysconf(_SC_PAGESIZE);
  if (page_size <= 0 || resident > std::numeric_limits<std::uint64_t>::max() /
                                     static_cast<std::uint64_t>(page_size)) {
    return 0;
  }
  return resident * static_cast<std::uint64_t>(page_size);
}

[[nodiscard]] bool live(const HealthSnapshot &snapshot, Clock::time_point now) noexcept {
  return snapshot.accepting && snapshot.heartbeat != Clock::time_point{} &&
         now >= snapshot.heartbeat && now - snapshot.heartbeat <= heartbeat_timeout;
}

[[nodiscard]] std::string json_escape(std::string_view value) {
  std::string result;
  result.reserve(value.size() + 8U);
  constexpr char hex[] = "0123456789abcdef";
  for (const char character : value) {
    const auto byte = static_cast<unsigned char>(character);
    switch (byte) {
      case '"':
        result += "\\\"";
        break;
      case '\\':
        result += "\\\\";
        break;
      case '\b':
        result += "\\b";
        break;
      case '\f':
        result += "\\f";
        break;
      case '\n':
        result += "\\n";
        break;
      case '\r':
        result += "\\r";
        break;
      case '\t':
        result += "\\t";
        break;
      default:
        if (byte < 0x20U || byte >= 0x7FU) {
          result += "\\u00";
          result.push_back(hex[byte >> 4U]);
          result.push_back(hex[byte & 0x0FU]);
        } else {
          result.push_back(static_cast<char>(byte));
        }
    }
  }
  return result;
}

[[nodiscard]] std::string prometheus_escape(std::string_view value) {
  std::string result;
  result.reserve(value.size() + 8U);
  constexpr char hex[] = "0123456789abcdef";
  for (const char character : value) {
    const auto byte = static_cast<unsigned char>(character);
    if (character == '\\' || character == '"') {
      result.push_back('\\');
      result.push_back(character);
    } else if (character == '\n' || character == '\r') {
      result += "\\n";
    } else if (byte < 0x20U || byte >= 0x7FU) {
      result += "\\x";
      result.push_back(hex[byte >> 4U]);
      result.push_back(hex[byte & 0x0FU]);
    } else {
      result.push_back(character);
    }
  }
  return result;
}

[[nodiscard]] std::string_view kind_name(ComponentKind kind) noexcept {
  return kind == ComponentKind::storage ? "storage" : "plugin";
}

[[nodiscard]] std::string_view state_name(ComponentState state) noexcept {
  switch (state) {
    case ComponentState::not_configured:
      return "not_configured";
    case ComponentState::ready:
      return "ready";
    case ComponentState::failed:
      return "failed";
  }
  return "failed";
}

[[nodiscard]] HealthSnapshot copy_snapshot(SharedHealth &shared) {
  HealthSnapshot snapshot;
  {
    SharedLock lock(shared.mutex);
    if (shared.magic != shared_magic || shared.version != shared_version) {
      throw std::runtime_error("health shared-state version mismatch");
    }
    snapshot.accepting = shared.accepting;
    snapshot.heartbeat = from_ns(shared.heartbeat_ns);
    snapshot.started = from_ns(shared.started_ns);
    snapshot.supervisor_resident_bytes = shared.supervisor_resident_bytes;
    snapshot.registered_users = shared.registered_users;
    snapshot.door_sessions = shared.door_sessions;
    snapshot.sessions.reserve(shared.max_sessions);
    for (std::size_t index = 0; index < shared.max_sessions; ++index) {
      const auto &session = shared.sessions[index];
      if (session.occupied) {
        snapshot.sessions.push_back(HealthSession{session.id, session.worker,
                                                  session.resident_bytes, session.telemetry});
      }
    }
    for (const auto &component : shared.components) {
      if (component.occupied) {
        snapshot.components.push_back(ComponentStatus{
            component.kind, component.state, read_bounded(component.name),
            read_bounded(component.version), read_bounded(component.reason)});
      }
    }
  }
  snapshot.health_resident_bytes = resident_bytes(::getpid());
  return snapshot;
}

void set_response(httplib::Response &response, const HealthResponse &rendered) {
  response.status = rendered.status;
  response.set_content(rendered.body, rendered.content_type);
  response.set_header("Cache-Control", "no-store");
  response.set_header("X-Content-Type-Options", "nosniff");
}

[[nodiscard]] int run_health_process(SharedHealth &shared, int control_descriptor,
                                     int startup_descriptor, std::string bind_address,
                                     std::uint16_t port, pid_t supervisor) noexcept {
  static_cast<void>(::prctl(PR_SET_PDEATHSIG, SIGTERM));
  if (::getppid() != supervisor) {
    static_cast<void>(::close(startup_descriptor));
    static_cast<void>(::close(control_descriptor));
    return 1;
  }
  try {
    httplib::Server server;
    std::string startup_reason;
    server.set_error_logger([&startup_reason](const httplib::Error &error,
                                              const httplib::Request *) {
      const auto error_number = errno;
      startup_reason = httplib::to_string(error);
      if (error_number != 0) {
        startup_reason += ": ";
        startup_reason += std::strerror(error_number);
      }
    });
    server.new_task_queue = [] { return new httplib::ThreadPool(2U, 2U, 32U); };
    server.set_read_timeout(2s);
    server.set_write_timeout(2s);
    server.set_idle_interval(100ms);
    server.set_payload_max_length(1024U);
    server.set_keep_alive_max_count(2U);
    server.set_keep_alive_timeout(2s);

    const auto render = [&shared](auto renderer, httplib::Response &response) {
      try {
        set_response(response, renderer(copy_snapshot(shared), Clock::now()));
      } catch (const std::exception &error) {
        response.status = 503;
        response.set_content("{\"status\":\"unavailable\",\"reason\":\"health state unavailable\"}\n",
                             "application/json; charset=utf-8");
        static_cast<void>(error);
      }
    };
    server.Get("/livez", [&](const httplib::Request &, httplib::Response &response) {
      render(render_liveness, response);
    });
    server.Get("/readyz", [&](const httplib::Request &, httplib::Response &response) {
      render(render_readiness, response);
    });
    server.Get("/metrics", [&](const httplib::Request &, httplib::Response &response) {
      render(render_metrics, response);
    });

    StartupStatus startup{};
    startup.ready = server.bind_to_port(bind_address, static_cast<int>(port)) ? 1U : 0U;
    if (startup.ready == 0U) {
      copy_bounded(startup.reason, startup_reason.empty() ? "HTTP listener initialization failed"
                                                          : startup_reason);
    }
    static_cast<void>(::send(startup_descriptor, &startup, sizeof(startup), MSG_NOSIGNAL));
    static_cast<void>(::close(startup_descriptor));
    startup_descriptor = -1;
    if (startup.ready == 0U) {
      static_cast<void>(::close(control_descriptor));
      return 1;
    }

    std::thread control([&server, control_descriptor] {
      std::array<std::byte, 1> byte{};
      while (::recv(control_descriptor, byte.data(), byte.size(), 0) < 0 && errno == EINTR) {
      }
      server.stop();
    });
    bool listened = false;
    try {
      listened = server.listen_after_bind();
    } catch (...) {
      static_cast<void>(::shutdown(control_descriptor, SHUT_RD));
      control.join();
      throw;
    }
    static_cast<void>(::shutdown(control_descriptor, SHUT_RD));
    control.join();
    static_cast<void>(::close(control_descriptor));
    return listened ? 0 : 1;
  } catch (...) {
    StartupStatus startup{};
    copy_bounded(startup.reason, "health process initialization threw an exception");
    if (startup_descriptor >= 0) {
      static_cast<void>(::send(startup_descriptor, &startup, sizeof(startup), MSG_NOSIGNAL));
      static_cast<void>(::close(startup_descriptor));
    }
    static_cast<void>(::close(control_descriptor));
    return 1;
  }
}

}  // namespace

HealthResponse render_liveness(const HealthSnapshot &snapshot, Clock::time_point now) {
  if (live(snapshot, now)) {
    return {200, "application/json; charset=utf-8", "{\"status\":\"live\"}\n"};
  }
  const auto reason = snapshot.accepting ? "supervisor heartbeat stale" : "SSH not accepting";
  return {503, "application/json; charset=utf-8",
          "{\"status\":\"unavailable\",\"reason\":\"" + std::string(reason) + "\"}\n"};
}

HealthResponse render_readiness(const HealthSnapshot &snapshot, Clock::time_point now) {
  std::vector<const ComponentStatus *> failures;
  for (const auto &component : snapshot.components) {
    if (component.state == ComponentState::failed) {
      failures.push_back(&component);
    }
  }
  const auto is_live = live(snapshot, now);
  std::string body = "{\"status\":\"";
  body += is_live && failures.empty() ? "ready" : "not_ready";
  body += "\",\"failures\":[";
  bool first = true;
  if (!is_live) {
    body += "{\"kind\":\"ssh\",\"name\":\"listener\",\"reason\":\"";
    body += snapshot.accepting ? "supervisor heartbeat stale" : "not accepting";
    body += "\"}";
    first = false;
  }
  for (const auto *component : failures) {
    if (!first) {
      body.push_back(',');
    }
    first = false;
    body += "{\"kind\":\"" + std::string(kind_name(component->kind)) +
            "\",\"name\":\"" + json_escape(component->name) + "\",\"reason\":\"" +
            json_escape(component->reason) + "\"}";
  }
  body += "],\"components\":[";
  first = true;
  for (const auto &component : snapshot.components) {
    if (!first) {
      body.push_back(',');
    }
    first = false;
    body += "{\"kind\":\"" + std::string(kind_name(component.kind)) +
            "\",\"name\":\"" + json_escape(component.name) + "\",\"state\":\"" +
            std::string(state_name(component.state)) + "\",\"version\":\"" +
            json_escape(component.version) + "\"}";
  }
  body += "]}\n";
  return {is_live && failures.empty() ? 200 : 503, "application/json; charset=utf-8",
          std::move(body)};
}

HealthResponse render_metrics(const HealthSnapshot &snapshot, Clock::time_point now) {
  const auto is_live = live(snapshot, now);
  const auto is_ready = is_live && std::none_of(snapshot.components.begin(),
                                                snapshot.components.end(), [](const auto &item) {
                                                  return item.state == ComponentState::failed;
                                                });
  const auto uptime = now >= snapshot.started
                          ? std::chrono::duration_cast<std::chrono::seconds>(now - snapshot.started)
                                .count()
                          : 0;
  std::string body;
  body.reserve(2048U + snapshot.sessions.size() * 512U + snapshot.components.size() * 256U);
  body += "# HELP anvil_up Whether the SSH supervisor is accepting and current.\n";
  body += "# TYPE anvil_up gauge\n";
  body += "anvil_up " + std::to_string(is_live ? 1 : 0) + "\n";
  body += "# HELP anvil_ready Whether every configured dependency is ready.\n";
  body += "# TYPE anvil_ready gauge\n";
  body += "anvil_ready " + std::to_string(is_ready ? 1 : 0) + "\n";
  body += "# TYPE anvil_uptime_seconds gauge\nanvil_uptime_seconds " +
          std::to_string(uptime) + "\n";
  body += "# TYPE anvil_ssh_active_sessions gauge\nanvil_ssh_active_sessions " +
          std::to_string(snapshot.sessions.size()) + "\n";
  body += "# TYPE anvil_registered_users gauge\nanvil_registered_users " +
          std::to_string(snapshot.registered_users) + "\n";
  body += "# TYPE anvil_door_sessions_total counter\nanvil_door_sessions_total " +
          std::to_string(snapshot.door_sessions) + "\n";
  body += "# TYPE anvil_resident_memory_bytes gauge\n";
  body += "anvil_resident_memory_bytes{role=\"supervisor\"} " +
          std::to_string(snapshot.supervisor_resident_bytes) + "\n";
  body += "anvil_resident_memory_bytes{role=\"health\"} " +
          std::to_string(snapshot.health_resident_bytes) + "\n";
  body += "# TYPE anvil_session_last_frame_output_bytes gauge\n";
  for (const auto &session : snapshot.sessions) {
    const auto id = std::to_string(session.id);
    const auto label = "{session=\"" + id + "\"}";
    body += "anvil_session_resident_memory_bytes" + label + " " +
            std::to_string(session.resident_bytes) + "\n";
    body += "anvil_session_frames_total" + label + " " +
            std::to_string(session.telemetry.frames) + "\n";
    body += "anvil_session_accepted_frames_total" + label + " " +
            std::to_string(session.telemetry.accepted_frames) + "\n";
    body += "anvil_session_output_bytes_total{session=\"" + id +
            "\",kind=\"cells\"} " + std::to_string(session.telemetry.cell_bytes) + "\n";
    body += "anvil_session_output_bytes_total{session=\"" + id +
            "\",kind=\"image_transmit\"} " +
            std::to_string(session.telemetry.image_transmit_bytes) + "\n";
    body += "anvil_session_output_bytes_total{session=\"" + id +
            "\",kind=\"image_edit\"} " +
            std::to_string(session.telemetry.image_edit_bytes) + "\n";
    body += "anvil_session_last_frame_output_bytes{session=\"" + id +
            "\",kind=\"cells\"} " +
            std::to_string(session.telemetry.last_frame_cell_bytes) + "\n";
    body += "anvil_session_last_frame_output_bytes{session=\"" + id +
            "\",kind=\"image_transmit\"} " +
            std::to_string(session.telemetry.last_frame_image_transmit_bytes) + "\n";
    body += "anvil_session_last_frame_output_bytes{session=\"" + id +
            "\",kind=\"image_edit\"} " +
            std::to_string(session.telemetry.last_frame_image_edit_bytes) + "\n";
    body += "anvil_session_first_frame_seconds" + label + " " +
            std::to_string(static_cast<double>(session.telemetry.first_frame_latency.count()) /
                           1000.0) +
            "\n";
  }
  for (const auto &component : snapshot.components) {
    if (component.kind != ComponentKind::plugin ||
        component.state == ComponentState::not_configured) {
      continue;
    }
    body += "anvil_plugin_ready{plugin=\"" + prometheus_escape(component.name) +
            "\",version=\"" + prometheus_escape(component.version) + "\"} " +
            std::to_string(component.state == ComponentState::ready ? 1 : 0) + "\n";
  }
  return {200, "text/plain; version=0.0.4; charset=utf-8", std::move(body)};
}

class HealthMonitor::Impl {
 public:
  Impl(SharedHealth *shared, pid_t process, int control_descriptor)
      : shared_(shared), process_(process), control_descriptor_(control_descriptor) {}

  ~Impl() {
    shutdown();
    if (shared_ != nullptr) {
      static_cast<void>(::pthread_mutex_destroy(&shared_->mutex));
      static_cast<void>(::munmap(shared_, sizeof(SharedHealth)));
    }
  }

  void shutdown() noexcept {
    if (control_descriptor_ >= 0) {
      const std::uint8_t stop = 1U;
      static_cast<void>(::send(control_descriptor_, &stop, sizeof(stop), MSG_NOSIGNAL));
      static_cast<void>(::close(control_descriptor_));
      control_descriptor_ = -1;
    }
    if (process_ <= 0) {
      return;
    }
    const auto deadline = Clock::now() + 2s;
    while (Clock::now() < deadline) {
      const auto result = ::waitpid(process_, nullptr, WNOHANG);
      if (result == process_ || (result < 0 && errno == ECHILD)) {
        process_ = -1;
        return;
      }
      if (result < 0 && errno != EINTR) {
        break;
      }
      std::this_thread::sleep_for(10ms);
    }
    static_cast<void>(::kill(process_, SIGKILL));
    while (::waitpid(process_, nullptr, 0) < 0 && errno == EINTR) {
    }
    process_ = -1;
  }

  SharedHealth *shared_{};
  pid_t process_{-1};
  int control_descriptor_{-1};
};

HealthMonitor::HealthMonitor(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

auto HealthMonitor::start(const Config &config) -> std::unique_ptr<HealthMonitor> {
  if (config.max_sessions == 0U || config.max_sessions > max_shared_sessions) {
    throw std::runtime_error("health session capacity is invalid");
  }
  void *mapping = ::mmap(nullptr, sizeof(SharedHealth), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) {
    throw std::system_error(errno, std::generic_category(), "cannot allocate health state");
  }
  auto *shared = new (mapping) SharedHealth{};
  pthread_mutexattr_t attributes{};
  const auto attributes_initialized = ::pthread_mutexattr_init(&attributes) == 0;
  const auto lock_initialized =
      attributes_initialized &&
      ::pthread_mutexattr_setpshared(&attributes, PTHREAD_PROCESS_SHARED) == 0 &&
      ::pthread_mutexattr_setrobust(&attributes, PTHREAD_MUTEX_ROBUST) == 0 &&
      ::pthread_mutex_init(&shared->mutex, &attributes) == 0;
  if (!lock_initialized) {
    if (attributes_initialized) {
      static_cast<void>(::pthread_mutexattr_destroy(&attributes));
    }
    static_cast<void>(::munmap(mapping, sizeof(SharedHealth)));
    throw std::runtime_error("cannot initialize health state lock");
  }
  static_cast<void>(::pthread_mutexattr_destroy(&attributes));
  shared->magic = shared_magic;
  shared->version = shared_version;
  shared->max_sessions = config.max_sessions;
  shared->started_ns = to_ns(Clock::now());
  shared->heartbeat_ns = shared->started_ns;

  std::array<int, 2> control{-1, -1};
  std::array<int, 2> startup{-1, -1};
  const auto control_created =
      ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, control.data()) == 0;
  const auto startup_created =
      control_created &&
      ::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, startup.data()) == 0;
  if (!startup_created) {
    const auto saved = errno;
    for (const auto descriptor : control) {
      if (descriptor >= 0) {
        static_cast<void>(::close(descriptor));
      }
    }
    for (const auto descriptor : startup) {
      if (descriptor >= 0) {
        static_cast<void>(::close(descriptor));
      }
    }
    static_cast<void>(::pthread_mutex_destroy(&shared->mutex));
    static_cast<void>(::munmap(mapping, sizeof(SharedHealth)));
    throw std::system_error(saved, std::generic_category(), "cannot create health control channel");
  }

  const auto supervisor = ::getpid();
  const auto child = ::fork();
  if (child < 0) {
    const auto saved = errno;
    for (const auto descriptor : control) {
      static_cast<void>(::close(descriptor));
    }
    for (const auto descriptor : startup) {
      static_cast<void>(::close(descriptor));
    }
    static_cast<void>(::pthread_mutex_destroy(&shared->mutex));
    static_cast<void>(::munmap(mapping, sizeof(SharedHealth)));
    throw std::system_error(saved, std::generic_category(), "cannot fork health process");
  }
  if (child == 0) {
    static_cast<void>(::close(control[0]));
    static_cast<void>(::close(startup[0]));
    for (const auto descriptor : config.close_in_child) {
      if (descriptor >= 0 && descriptor != control[1] && descriptor != startup[1]) {
        static_cast<void>(::close(descriptor));
      }
    }
    const auto result = run_health_process(*shared, control[1], startup[1], config.bind_address,
                                           config.port, supervisor);
    std::_Exit(result);
  }
  static_cast<void>(::close(control[1]));
  static_cast<void>(::close(startup[1]));
  StartupStatus startup_status{};
  ssize_t count = -1;
  pollfd startup_poll{.fd = startup[0], .events = POLLIN, .revents = 0};
  int polled = -1;
  do {
    polled = ::poll(&startup_poll, 1, 5000);
  } while (polled < 0 && errno == EINTR);
  if (polled > 0 && (startup_poll.revents & POLLIN) != 0) {
    do {
      count = ::recv(startup[0], &startup_status, sizeof(startup_status), 0);
    } while (count < 0 && errno == EINTR);
  }
  static_cast<void>(::close(startup[0]));
  if (count != static_cast<ssize_t>(sizeof(startup_status)) || startup_status.ready != 1U) {
    static_cast<void>(::close(control[0]));
    static_cast<void>(::kill(child, SIGKILL));
    while (::waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
    }
    static_cast<void>(::pthread_mutex_destroy(&shared->mutex));
    static_cast<void>(::munmap(mapping, sizeof(SharedHealth)));
    auto message = "cannot listen on health endpoint " + config.bind_address + ':' +
                   std::to_string(config.port);
    const auto reason = read_bounded(startup_status.reason);
    if (!reason.empty()) {
      message += ": ";
      message += reason;
    }
    throw std::runtime_error(std::move(message));
  }
  return std::unique_ptr<HealthMonitor>(
      new HealthMonitor(std::make_unique<Impl>(shared, child, control[0])));
}

HealthMonitor::~HealthMonitor() = default;

void HealthMonitor::heartbeat(bool accepting) {
  SharedLock lock(impl_->shared_->mutex);
  impl_->shared_->accepting = accepting;
  impl_->shared_->heartbeat_ns = to_ns(Clock::now());
  impl_->shared_->supervisor_resident_bytes = resident_bytes(::getpid());
  for (std::size_t index = 0; index < impl_->shared_->max_sessions; ++index) {
    auto &session = impl_->shared_->sessions[index];
    if (session.occupied) {
      session.resident_bytes = resident_bytes(session.worker);
    }
  }
}

void HealthMonitor::set_component(const ComponentStatus &component) {
  SharedLock lock(impl_->shared_->mutex);
  std::array<char, max_component_name> bounded_name{};
  copy_bounded(bounded_name, component.name);
  const auto normalized_name = read_bounded(bounded_name);
  SharedComponent *available = nullptr;
  for (auto &candidate : impl_->shared_->components) {
    if (candidate.occupied && candidate.kind == component.kind &&
        read_bounded(candidate.name) == normalized_name) {
      available = &candidate;
      break;
    }
    if (!candidate.occupied && available == nullptr) {
      available = &candidate;
    }
  }
  if (available == nullptr) {
    throw std::runtime_error("health component capacity exceeded");
  }
  available->occupied = true;
  available->kind = component.kind;
  available->state = component.state;
  available->name = bounded_name;
  copy_bounded(available->version, component.version);
  copy_bounded(available->reason, component.reason);
}

void HealthMonitor::session_started(std::uint64_t id, pid_t worker) {
  SharedLock lock(impl_->shared_->mutex);
  for (std::size_t index = 0; index < impl_->shared_->max_sessions; ++index) {
    auto &session = impl_->shared_->sessions[index];
    if (!session.occupied) {
      session = SharedSession{true, id, worker, resident_bytes(worker), {}};
      return;
    }
  }
  throw std::runtime_error("health session capacity exceeded");
}

void HealthMonitor::session_updated(std::uint64_t id, pid_t worker,
                                    const SessionTelemetry &telemetry) {
  SharedLock lock(impl_->shared_->mutex);
  for (std::size_t index = 0; index < impl_->shared_->max_sessions; ++index) {
    auto &session = impl_->shared_->sessions[index];
    if (session.occupied && session.id == id && session.worker == worker) {
      session.telemetry = telemetry;
      return;
    }
  }
}

void HealthMonitor::session_finished(std::uint64_t id) {
  SharedLock lock(impl_->shared_->mutex);
  for (std::size_t index = 0; index < impl_->shared_->max_sessions; ++index) {
    auto &session = impl_->shared_->sessions[index];
    if (session.occupied && session.id == id) {
      session = {};
      return;
    }
  }
}

bool HealthMonitor::alive() {
  if (impl_->process_ <= 0) {
    return false;
  }
  int status = 0;
  const auto result = ::waitpid(impl_->process_, &status, WNOHANG);
  if (result == 0) {
    return true;
  }
  if (result == impl_->process_ || (result < 0 && errno == ECHILD)) {
    impl_->process_ = -1;
    return false;
  }
  return result < 0 && errno == EINTR;
}

pid_t HealthMonitor::pid() const noexcept { return impl_->process_; }

void HealthMonitor::detach_in_worker() noexcept {
  if (impl_->control_descriptor_ >= 0) {
    static_cast<void>(::close(impl_->control_descriptor_));
    impl_->control_descriptor_ = -1;
  }
  impl_->process_ = -1;
  if (impl_->shared_ != nullptr) {
    static_cast<void>(::munmap(impl_->shared_, sizeof(SharedHealth)));
    impl_->shared_ = nullptr;
  }
}

void HealthMonitor::shutdown() noexcept { impl_->shutdown(); }

}  // namespace anvil::server
