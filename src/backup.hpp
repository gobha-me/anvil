#pragma once

#include <chrono>
#include <expected>
#include <filesystem>
#include <string>

namespace anvil::store {
class SqliteStore;
}

namespace anvil::server::backup {

struct Snapshot {
  std::filesystem::path path;
  std::chrono::system_clock::time_point created_at;
};

[[nodiscard]] auto
create_snapshot(store::SqliteStore &database,
                const std::filesystem::path &host_key,
                const std::filesystem::path &backup_directory,
                std::chrono::system_clock::time_point now =
                    std::chrono::system_clock::now())
    -> std::expected<Snapshot, std::string>;

[[nodiscard]] auto
prune_snapshots(const std::filesystem::path &backup_directory,
                std::chrono::seconds retention,
                std::chrono::system_clock::time_point now =
                    std::chrono::system_clock::now())
    -> std::expected<void, std::string>;

[[nodiscard]] auto restore_snapshot(const std::filesystem::path &snapshot,
                                    const std::filesystem::path &database,
                                    const std::filesystem::path &host_key)
    -> std::expected<void, std::string>;

} // namespace anvil::server::backup
