#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

#include "health.hpp"

using namespace std::chrono_literals;

TEST_CASE("health responses fail closed on stale or failed state") {
  const auto now = std::chrono::steady_clock::now();
  anvil::server::HealthSnapshot snapshot;
  snapshot.started = now - 10s;
  snapshot.heartbeat = now;
  snapshot.accepting = true;

  CHECK(anvil::server::render_liveness(snapshot, now).status == 200);
  CHECK(anvil::server::render_readiness(snapshot, now).status == 200);
  CHECK(anvil::server::render_liveness(snapshot, now + 4s).status == 503);

  snapshot.components.push_back({anvil::server::ComponentKind::storage,
                                 anvil::server::ComponentState::failed, "database", {},
                                 "cannot open WAL"});
  const auto failed = anvil::server::render_readiness(snapshot, now);
  CHECK(failed.status == 503);
  CHECK(failed.body.find("database") != std::string::npos);
  CHECK(failed.body.find("cannot open WAL") != std::string::npos);
}

TEST_CASE("health output escapes hostile plugin metadata") {
  const auto now = std::chrono::steady_clock::now();
  anvil::server::HealthSnapshot snapshot;
  snapshot.started = now - 1s;
  snapshot.heartbeat = now;
  snapshot.accepting = true;
  snapshot.components.push_back({anvil::server::ComponentKind::plugin,
                                 anvil::server::ComponentState::failed,
                                 std::string("door\"\\\nname\xff", 12), "1.0\"",
                                 "ABI\nrejected"});

  const auto readiness = anvil::server::render_readiness(snapshot, now);
  CHECK(readiness.status == 503);
  CHECK(readiness.body.find("door\\\"\\\\\\nname\\u00ff") != std::string::npos);
  CHECK(readiness.body.find("ABI\\nrejected") != std::string::npos);

  const auto metrics = anvil::server::render_metrics(snapshot, now);
  CHECK(metrics.status == 200);
  CHECK(metrics.content_type.find("version=0.0.4") != std::string::npos);
  CHECK(metrics.body.find("plugin=\"door\\\"\\\\\\nname\\xff\"") != std::string::npos);
  CHECK(metrics.body.find("version=\"1.0\\\"\"") != std::string::npos);
}

TEST_CASE("metrics expose opaque per-session accounting") {
  const auto now = std::chrono::steady_clock::now();
  anvil::server::HealthSnapshot snapshot;
  snapshot.started = now - 5s;
  snapshot.heartbeat = now;
  snapshot.accepting = true;
  snapshot.sessions.push_back(
      {42, 1234, 8192,
       {.frames = 3,
        .accepted_frames = 2,
        .cell_bytes = 100,
        .image_transmit_bytes = 20,
        .image_edit_bytes = 5,
        .last_frame_cell_bytes = 7,
        .last_frame_image_transmit_bytes = 3,
        .last_frame_image_edit_bytes = 1,
        .first_frame_latency = 25ms}});

  const auto metrics = anvil::server::render_metrics(snapshot, now);
  CHECK(metrics.body.find("anvil_ssh_active_sessions 1") != std::string::npos);
  CHECK(metrics.body.find("session=\"42\"") != std::string::npos);
  CHECK(metrics.body.find("anvil_session_output_bytes_total{session=\"42\",kind=\"cells\"} 100") !=
        std::string::npos);
  CHECK(metrics.body.find(
            "anvil_session_last_frame_output_bytes{session=\"42\",kind=\"cells\"} 7") !=
        std::string::npos);
  CHECK(metrics.body.find("# TYPE anvil_session_last_frame_output_bytes gauge") !=
        std::string::npos);
  CHECK(metrics.body.find("anvil_session_last_frame_output_bytes{session=\"42\",kind=\"image_"
                          "transmit\"} 3") != std::string::npos);
  CHECK(metrics.body.find(
            "anvil_session_last_frame_output_bytes{session=\"42\",kind=\"image_edit\"} 1") !=
        std::string::npos);
  CHECK(metrics.body.find("anvil_session_first_frame_seconds{session=\"42\"} 0.025000") !=
        std::string::npos);
  CHECK(metrics.body.find("1234") == std::string::npos);
}
