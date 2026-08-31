#pragma once

#include <string_view>

namespace anvil::store::detail {

// Schema version 1 deliberately claimed an otherwise empty Anvil database.
// Version 2 is the first domain schema. Keep this as one migration so a
// partially-created schema can never become visible after startup.
inline constexpr std::string_view domain_schema_v2 = R"sql(
CREATE TABLE users(
  handle TEXT NOT NULL CHECK(typeof(handle) = 'text' AND length(handle) > 0),
  origin TEXT CHECK(origin IS NULL OR
                    (typeof(origin) = 'text' AND length(origin) > 0)),
  origin_key TEXT GENERATED ALWAYS AS (coalesce(origin, '')) STORED,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending', 'active', 'suspended', 'tombstoned')),
  created_at INTEGER NOT NULL CHECK(typeof(created_at) = 'integer'),
  last_seen_at INTEGER CHECK(last_seen_at IS NULL OR
                             typeof(last_seen_at) = 'integer'),
  UNIQUE(handle, origin_key)
);

CREATE TABLE user_keys(
  fingerprint TEXT PRIMARY KEY
    CHECK(typeof(fingerprint) = 'text' AND length(fingerprint) > 0),
  user_handle TEXT NOT NULL,
  user_origin TEXT CHECK(user_origin IS NULL OR
                         (typeof(user_origin) = 'text' AND
                          length(user_origin) > 0)),
  user_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(user_origin, '')) STORED,
  public_key TEXT NOT NULL
    CHECK(typeof(public_key) = 'text' AND length(public_key) > 0),
  added_at INTEGER NOT NULL CHECK(typeof(added_at) = 'integer'),
  revoked_at INTEGER CHECK(revoked_at IS NULL OR
                           typeof(revoked_at) = 'integer'),
  FOREIGN KEY(user_handle, user_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE invites(
  code_hash TEXT PRIMARY KEY
    CHECK(typeof(code_hash) = 'text' AND length(code_hash) > 0),
  inviter_handle TEXT NOT NULL,
  inviter_origin TEXT CHECK(inviter_origin IS NULL OR
                            (typeof(inviter_origin) = 'text' AND
                             length(inviter_origin) > 0)),
  inviter_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(inviter_origin, '')) STORED,
  claimed_by_handle TEXT,
  claimed_by_origin TEXT CHECK(claimed_by_origin IS NULL OR
                               (typeof(claimed_by_origin) = 'text' AND
                                length(claimed_by_origin) > 0)),
  claimed_by_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(claimed_by_origin, '')) STORED,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active', 'claimed', 'revoked')),
  created_at INTEGER NOT NULL CHECK(typeof(created_at) = 'integer'),
  claimed_at INTEGER CHECK(claimed_at IS NULL OR
                           typeof(claimed_at) = 'integer'),
  CHECK((claimed_by_handle IS NULL AND claimed_by_origin IS NULL AND
         claimed_at IS NULL) OR
        (claimed_by_handle IS NOT NULL AND claimed_at IS NOT NULL)),
  FOREIGN KEY(inviter_handle, inviter_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY(claimed_by_handle, claimed_by_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE tos_acceptances(
  acceptance_id INTEGER PRIMARY KEY,
  user_handle TEXT NOT NULL,
  user_origin TEXT CHECK(user_origin IS NULL OR
                         (typeof(user_origin) = 'text' AND
                          length(user_origin) > 0)),
  user_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(user_origin, '')) STORED,
  tos_version TEXT NOT NULL
    CHECK(typeof(tos_version) = 'text' AND length(tos_version) > 0),
  accepted_at INTEGER NOT NULL CHECK(typeof(accepted_at) = 'integer'),
  UNIQUE(user_handle, user_origin_key, tos_version),
  FOREIGN KEY(user_handle, user_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE boards(
  board_id TEXT PRIMARY KEY CHECK(
    typeof(board_id) = 'text' AND length(board_id) = 36 AND
    substr(board_id, 9, 1) = '-' AND substr(board_id, 14, 1) = '-' AND
    substr(board_id, 19, 1) = '-' AND substr(board_id, 24, 1) = '-' AND
    lower(board_id) = board_id AND
    length(replace(board_id, '-', '')) = 32 AND
    replace(board_id, '-', '') NOT GLOB '*[^0-9a-f]*'),
  name TEXT NOT NULL CHECK(typeof(name) = 'text' AND length(name) > 0),
  origin TEXT CHECK(origin IS NULL OR
                    (typeof(origin) = 'text' AND length(origin) > 0)),
  origin_key TEXT GENERATED ALWAYS AS (coalesce(origin, '')) STORED,
  title TEXT NOT NULL CHECK(typeof(title) = 'text'),
  description TEXT NOT NULL DEFAULT '' CHECK(typeof(description) = 'text'),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active', 'tombstoned')),
  created_at INTEGER NOT NULL CHECK(typeof(created_at) = 'integer'),
  UNIQUE(name, origin_key)
);

CREATE TABLE threads(
  thread_id TEXT PRIMARY KEY
    CHECK(typeof(thread_id) = 'text' AND length(thread_id) BETWEEN 1 AND 128),
  board_id TEXT NOT NULL,
  author_handle TEXT NOT NULL,
  author_origin TEXT CHECK(author_origin IS NULL OR
                           (typeof(author_origin) = 'text' AND
                            length(author_origin) > 0)),
  author_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(author_origin, '')) STORED,
  subject TEXT NOT NULL CHECK(typeof(subject) = 'text'),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active', 'tombstoned')),
  created_at INTEGER NOT NULL CHECK(typeof(created_at) = 'integer'),
  updated_at INTEGER NOT NULL CHECK(typeof(updated_at) = 'integer'),
  locked_at INTEGER CHECK(locked_at IS NULL OR typeof(locked_at) = 'integer'),
  UNIQUE(thread_id, board_id),
  FOREIGN KEY(board_id) REFERENCES boards(board_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY(author_handle, author_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE messages(
  message_id TEXT PRIMARY KEY
    CHECK(typeof(message_id) = 'text' AND length(message_id) BETWEEN 1 AND 128),
  board_id TEXT NOT NULL,
  thread_id TEXT NOT NULL,
  parent_message_id TEXT,
  author_handle TEXT NOT NULL,
  author_origin TEXT CHECK(author_origin IS NULL OR
                           (typeof(author_origin) = 'text' AND
                            length(author_origin) > 0)),
  author_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(author_origin, '')) STORED,
  body TEXT NOT NULL CHECK(typeof(body) = 'text'),
  posted_at INTEGER NOT NULL CHECK(typeof(posted_at) = 'integer'),
  received_at INTEGER NOT NULL CHECK(typeof(received_at) = 'integer'),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active', 'tombstoned')),
  FOREIGN KEY(thread_id, board_id) REFERENCES threads(thread_id, board_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY(parent_message_id) REFERENCES messages(message_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY(author_handle, author_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE files(
  file_id TEXT PRIMARY KEY
    CHECK(typeof(file_id) = 'text' AND length(file_id) BETWEEN 1 AND 128),
  board_id TEXT NOT NULL,
  uploader_handle TEXT NOT NULL,
  uploader_origin TEXT CHECK(uploader_origin IS NULL OR
                             (typeof(uploader_origin) = 'text' AND
                              length(uploader_origin) > 0)),
  uploader_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(uploader_origin, '')) STORED,
  name TEXT NOT NULL CHECK(typeof(name) = 'text' AND length(name) > 0),
  description TEXT NOT NULL DEFAULT '' CHECK(typeof(description) = 'text'),
  storage_path TEXT NOT NULL
    CHECK(typeof(storage_path) = 'text' AND length(storage_path) > 0),
  content_hash TEXT NOT NULL
    CHECK(typeof(content_hash) = 'text' AND length(content_hash) > 0),
  byte_count INTEGER NOT NULL
    CHECK(typeof(byte_count) = 'integer' AND byte_count >= 0),
  published_at INTEGER NOT NULL CHECK(typeof(published_at) = 'integer'),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active', 'tombstoned')),
  FOREIGN KEY(board_id) REFERENCES boards(board_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY(uploader_handle, uploader_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE plugins(
  plugin_id TEXT PRIMARY KEY
    CHECK(typeof(plugin_id) = 'text' AND length(plugin_id) > 0),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
  last_loaded_hash TEXT
    CHECK(last_loaded_hash IS NULL OR
          (typeof(last_loaded_hash) = 'text' AND length(last_loaded_hash) > 0)),
  author TEXT NOT NULL CHECK(typeof(author) = 'text'),
  version TEXT NOT NULL CHECK(typeof(version) = 'text'),
  observed_toolchain TEXT NOT NULL DEFAULT ''
    CHECK(typeof(observed_toolchain) = 'text'),
  updated_at INTEGER NOT NULL CHECK(typeof(updated_at) = 'integer')
);

CREATE TABLE plugin_state(
  state_id INTEGER PRIMARY KEY,
  plugin_id TEXT NOT NULL,
  user_handle TEXT NOT NULL,
  user_origin TEXT CHECK(user_origin IS NULL OR
                         (typeof(user_origin) = 'text' AND
                          length(user_origin) > 0)),
  user_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(user_origin, '')) STORED,
  state BLOB NOT NULL CHECK(typeof(state) = 'blob'),
  updated_at INTEGER NOT NULL CHECK(typeof(updated_at) = 'integer'),
  UNIQUE(plugin_id, user_handle, user_origin_key),
  FOREIGN KEY(plugin_id) REFERENCES plugins(plugin_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY(user_handle, user_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE leaderboards(
  entry_id TEXT PRIMARY KEY
    CHECK(typeof(entry_id) = 'text' AND length(entry_id) BETWEEN 1 AND 128),
  plugin_id TEXT NOT NULL,
  user_handle TEXT NOT NULL,
  user_origin TEXT CHECK(user_origin IS NULL OR
                         (typeof(user_origin) = 'text' AND
                          length(user_origin) > 0)),
  user_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(user_origin, '')) STORED,
  board_id TEXT NOT NULL,
  category TEXT NOT NULL CHECK(typeof(category) = 'text'),
  score INTEGER NOT NULL CHECK(typeof(score) = 'integer'),
  submitted_at INTEGER NOT NULL CHECK(typeof(submitted_at) = 'integer'),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active', 'tombstoned')),
  FOREIGN KEY(plugin_id) REFERENCES plugins(plugin_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY(board_id) REFERENCES boards(board_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY(user_handle, user_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE oneliners(
  oneliner_id TEXT PRIMARY KEY
    CHECK(typeof(oneliner_id) = 'text' AND
          length(oneliner_id) BETWEEN 1 AND 128),
  author_handle TEXT NOT NULL,
  author_origin TEXT CHECK(author_origin IS NULL OR
                           (typeof(author_origin) = 'text' AND
                            length(author_origin) > 0)),
  author_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(author_origin, '')) STORED,
  body TEXT NOT NULL CHECK(typeof(body) = 'text'),
  posted_at INTEGER NOT NULL CHECK(typeof(posted_at) = 'integer'),
  received_at INTEGER NOT NULL CHECK(typeof(received_at) = 'integer'),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active', 'tombstoned')),
  FOREIGN KEY(author_handle, author_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE blocks(
  block_id INTEGER PRIMARY KEY,
  blocker_handle TEXT NOT NULL,
  blocker_origin TEXT CHECK(blocker_origin IS NULL OR
                            (typeof(blocker_origin) = 'text' AND
                             length(blocker_origin) > 0)),
  blocker_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(blocker_origin, '')) STORED,
  blocked_handle TEXT NOT NULL,
  blocked_origin TEXT CHECK(blocked_origin IS NULL OR
                            (typeof(blocked_origin) = 'text' AND
                             length(blocked_origin) > 0)),
  blocked_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(blocked_origin, '')) STORED,
  created_at INTEGER NOT NULL CHECK(typeof(created_at) = 'integer'),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK(status IN ('active', 'tombstoned')),
  CHECK(blocker_handle != blocked_handle OR
        blocker_origin_key != blocked_origin_key),
  UNIQUE(blocker_handle, blocker_origin_key,
         blocked_handle, blocked_origin_key),
  FOREIGN KEY(blocker_handle, blocker_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY(blocked_handle, blocked_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE reports(
  report_id TEXT PRIMARY KEY
    CHECK(typeof(report_id) = 'text' AND length(report_id) BETWEEN 1 AND 128),
  reporter_handle TEXT NOT NULL,
  reporter_origin TEXT CHECK(reporter_origin IS NULL OR
                             (typeof(reporter_origin) = 'text' AND
                              length(reporter_origin) > 0)),
  reporter_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(reporter_origin, '')) STORED,
  target_kind TEXT NOT NULL CHECK(typeof(target_kind) = 'text'),
  target_id TEXT NOT NULL CHECK(typeof(target_id) = 'text'),
  target_origin TEXT CHECK(target_origin IS NULL OR
                           (target_kind = 'user' AND
                            typeof(target_origin) = 'text' AND
                            length(target_origin) > 0)),
  target_user_handle TEXT GENERATED ALWAYS AS (
    CASE WHEN target_kind = 'user' THEN target_id END) STORED,
  target_user_origin_key TEXT GENERATED ALWAYS AS (
    CASE WHEN target_kind = 'user' THEN coalesce(target_origin, '') END) STORED,
  evidence TEXT NOT NULL DEFAULT '' CHECK(typeof(evidence) = 'text'),
  status TEXT NOT NULL DEFAULT 'open'
    CHECK(status IN ('open', 'resolved', 'tombstoned')),
  created_at INTEGER NOT NULL CHECK(typeof(created_at) = 'integer'),
  resolved_at INTEGER CHECK(resolved_at IS NULL OR
                            typeof(resolved_at) = 'integer'),
  FOREIGN KEY(reporter_handle, reporter_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY(target_user_handle, target_user_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE moderation_log(
  entry_id TEXT PRIMARY KEY
    CHECK(typeof(entry_id) = 'text' AND length(entry_id) BETWEEN 1 AND 128),
  moderator_handle TEXT NOT NULL,
  moderator_origin TEXT CHECK(moderator_origin IS NULL OR
                              (typeof(moderator_origin) = 'text' AND
                               length(moderator_origin) > 0)),
  moderator_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(moderator_origin, '')) STORED,
  action TEXT NOT NULL CHECK(typeof(action) = 'text'),
  target_kind TEXT NOT NULL CHECK(typeof(target_kind) = 'text'),
  target_id TEXT NOT NULL CHECK(typeof(target_id) = 'text'),
  target_origin TEXT CHECK(target_origin IS NULL OR
                           (target_kind = 'user' AND
                            typeof(target_origin) = 'text' AND
                            length(target_origin) > 0)),
  target_user_handle TEXT GENERATED ALWAYS AS (
    CASE WHEN target_kind = 'user' THEN target_id END) STORED,
  target_user_origin_key TEXT GENERATED ALWAYS AS (
    CASE WHEN target_kind = 'user' THEN coalesce(target_origin, '') END) STORED,
  reason TEXT NOT NULL DEFAULT '' CHECK(typeof(reason) = 'text'),
  created_at INTEGER NOT NULL CHECK(typeof(created_at) = 'integer'),
  FOREIGN KEY(moderator_handle, moderator_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT,
  FOREIGN KEY(target_user_handle, target_user_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE sessions_log(
  session_id TEXT PRIMARY KEY
    CHECK(typeof(session_id) = 'text' AND length(session_id) BETWEEN 1 AND 128),
  user_handle TEXT,
  user_origin TEXT CHECK(user_origin IS NULL OR
                         (typeof(user_origin) = 'text' AND
                          length(user_origin) > 0)),
  user_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(user_origin, '')) STORED,
  remote_address TEXT NOT NULL CHECK(typeof(remote_address) = 'text'),
  connected_at INTEGER NOT NULL CHECK(typeof(connected_at) = 'integer'),
  disconnected_at INTEGER CHECK(disconnected_at IS NULL OR
                                typeof(disconnected_at) = 'integer'),
  bytes_in INTEGER NOT NULL DEFAULT 0
    CHECK(typeof(bytes_in) = 'integer' AND bytes_in >= 0),
  bytes_out INTEGER NOT NULL DEFAULT 0
    CHECK(typeof(bytes_out) = 'integer' AND bytes_out >= 0),
  FOREIGN KEY(user_handle, user_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE TABLE presence(
  session_id TEXT PRIMARY KEY,
  user_handle TEXT NOT NULL,
  user_origin TEXT CHECK(user_origin IS NULL OR
                         (typeof(user_origin) = 'text' AND
                          length(user_origin) > 0)),
  user_origin_key TEXT
    GENERATED ALWAYS AS (coalesce(user_origin, '')) STORED,
  heartbeat_at INTEGER NOT NULL CHECK(typeof(heartbeat_at) = 'integer'),
  FOREIGN KEY(session_id) REFERENCES sessions_log(session_id)
    ON UPDATE CASCADE ON DELETE CASCADE,
  FOREIGN KEY(user_handle, user_origin_key)
    REFERENCES users(handle, origin_key) ON UPDATE CASCADE ON DELETE RESTRICT
);
)sql";

// Version 3 keeps the original 17-table domain shape. Invite balance belongs
// to the account and each issued bearer code carries an explicit deadline.
// Existing active codes fail closed at expiry 0; claimed rows remain as graph
// evidence. The unique partial index makes "who invited this account" singular.
inline constexpr std::string_view invite_economics_v3 = R"sql(
ALTER TABLE users ADD COLUMN invite_balance INTEGER NOT NULL DEFAULT 0
  CHECK(typeof(invite_balance) = 'integer' AND invite_balance >= 0);
ALTER TABLE users ADD COLUMN invite_next_regeneration INTEGER
  CHECK(invite_next_regeneration IS NULL OR
        typeof(invite_next_regeneration) = 'integer');
ALTER TABLE invites ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0
  CHECK(typeof(expires_at) = 'integer');
CREATE UNIQUE INDEX invites_one_edge_per_account
  ON invites(claimed_by_handle, claimed_by_origin_key)
  WHERE claimed_by_handle IS NOT NULL;
)sql";

} // namespace anvil::store::detail
