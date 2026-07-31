# ANVIL — SSH Bulletin Board System

**Working title.** Rename freely.

**Status:** draft v1
**Target:** public showcase deployment for termforge
**Transport:** SSH, embedded server, no OpenSSH
**Deployment:** single Docker container
**Language:** C++23, termforge

---

## 0. One-line pitch

A public bulletin board you reach with one command — `ssh anvil.example.org` — serving boards, files, and door games to anyone with a terminal, built entirely on termforge.

---

## 1. Why this exists

Two reasons, both worth stating plainly because they should drive priority calls later.

**It is the best possible demo of the library.** A stranger experiences a live termforge application in five seconds with no clone, no toolchain, no dependency hunt. Screenshots do not prove a render loop; a running system someone can touch does. This is worth more to the project than any single application.

**It is a venue, not an app.** Boards and doors are content that can land incrementally into a place that already has people in it. The BBS ships first and stays useful even if nothing else ever lands.

---

## 2. Design pillars

1. **Reach beats spectacle at the shell level.** The board itself must work from PuTTY, Terminal.app, and inside tmux. Enhanced rendering is opt-in per screen, never a barrier to entry.
2. **No system users, no shell, ever.** The SSH server is embedded in the application. There is nothing to escape to.
3. **All remote input is hostile.** Every byte from a session is attacker-controlled in both directions. Parsing is the primary attack surface and is treated as such.
4. **Async and text-only.** No voice, no synchronous lobbies. The medium has no channel for the failure modes those bring.
5. **Bounded per session.** Memory, CPU, output rate, and image quota are capped per connection. One user cannot degrade the board.
6. **Restartable without user-visible breakage.** Host keys, accounts, and state survive redeploys.
7. **Mechanisms, not policy.** This ships as OSS and other people will run it. Provide the knobs — registration mode, retention, limits, moderation tooling — and let each operator set their own posture. Hardcoding one deployment's policy into the software is a defect.
8. **Store nothing you do not need.** Ephemeral data stays ephemeral. What is never written cannot leak, cannot be subpoenaed, and cannot be moderated badly.

---

## 3. Architecture

### 3.1 Embedded SSH, single process

Use **libssh's server API** inside the termforge process. One process, one port, N session coroutines.

```
  SSH clients ──▶ libssh server (accept + auth)
                        │
                        ▼
                 Session coroutine ──▶ Shared services ──▶ SQLite
                 (one per connection)   (boards, doors,     (volume)
                                         users)
```

**Rejected alternative: OpenSSH with `ForceCommand`.** It requires system users or a PAM shim, carries a login-shell code path that must be defended against, and makes the container's security posture depend on sshd configuration correctness. The embedded server removes the entire class of shell-escape concerns because no shell exists in the image.

Docker is then packaging, not a security boundary. Treat it accordingly.

### 3.2 Session lifecycle

```
connect → auth → pty-req → capability probe → menu loop → disconnect
```

- **`pty-req`** supplies `TERM` and initial dimensions. Treat `TERM` as a hint, never as truth.
- **`window-change`** messages are the resize path. There is no SIGWINCH. Wire this to termforge's resize handling explicitly — it is a common omission and produces corrupted layouts that only appear when a user resizes.
- Each session is a coroutine on a small thread pool, matching termforge's existing event model.
- Idle timeout with warning. Absolute session cap.

### 3.3 Concurrency and isolation

- Session state is per-coroutine and never shared.
- Shared services are accessed through a narrow interface with explicit locking. Nothing else crosses session boundaries.
- A session throwing must terminate that session only. Board survival is a hard requirement, verified by test.

---

## 4. Capability tiering

The central design problem. A BBS wants maximum reach; graphics want maximum capability. Resolve by tiering rather than by choosing.

| Tier | Requires | Used for |
|---|---|---|
| 0 — Teletype | 80×24, ASCII, no color | Absolute fallback. Never blocks access. |
| 1 — ANSI | 16 color, box drawing, cursor addressing | **The baseline board experience.** Boards, menus, file areas, user list. |
| 2 — Modern | Truecolor, unicode width, synchronized output, kitty keyboard | Enhanced board chrome, better input handling |
| 3 — Graphics | Kitty graphics protocol | Doors that require it, art galleries, avatars |

**The board shell targets tier 1.** Everything essential works there. Tiers 2 and 3 are enhancement, never gating.

### 4.1 Detection

Active probing, because `TERM` lies:

- Primary/secondary device attributes, `XTGETTCAP`, a kitty graphics query with a 1×1 image, kitty keyboard progressive-enhancement query.
- **Every probe has a hard timeout (~500ms total budget).** A terminal that does not answer must never hang a session. Fall back silently and proceed.
- Probe results are cached per user, and **always manually overridable from a settings screen**. Users know their terminal better than the probe does. This is not optional politeness — probes get it wrong often enough that the override is a functional requirement.

### 4.2 Multiplexers

Detect tmux and screen. Kitty graphics passthrough under tmux requires `allow-passthrough` and remains fragile.

**Do not attempt graphics under a detected multiplexer by default.** Drop to tier 2 and show a one-line explanation with the config change required. Rendering garbage into someone's tmux session is worse than declining.

---

## 5. Security posture

This section is where an unattended implementation will improvise badly. It is prescriptive.

### 5.1 Threat model

An anonymous remote attacker with full control of the byte stream in both directions, unlimited attempts, and no rate limit other than what is implemented here.

### 5.2 Terminal escape injection — read this one twice

User-submitted content is rendered into *other users'* terminals. A post containing raw escape sequences can retitle windows, alter keyboard modes, inject a paste buffer, or trigger a client bug on every reader.

**Requirements:**
- Strip or escape all C0 and C1 control characters from user input **at storage time and again at render time**. Both. Defence in depth, because a future code path will bypass one of them.
- Store message bodies as plain UTF-8. Never store ANSI. Formatting is applied at render time from structured markup, not from stored escape codes.
- Validate UTF-8 on ingest; reject overlongs and surrogates.
- Cap grapheme count and line length on ingest.

This is a classic BBS-era attack and it is fully applicable today.

### 5.3 Input parsing

- Fuzz the escape-sequence parser, capability-response parser, SSH message handling, and all user text paths. **libFuzzer or AFL++ as a CI gate, not a one-off exercise.**
- No fixed-size stack buffers for network-derived data. `std::span`, bounds-checked ranges, no raw pointer arithmetic on remote input.
- Staging builds run ASan and UBSan continuously. Production builds enable `_FORTIFY_SOURCE`, stack protector, full RELRO, PIE.

### 5.4 Authentication and registration

- **Public keys only. Never implement password authentication.**
- `guest` account with no key for read-only browsing, including a read-only view of the door menu. This matters enormously for adoption — a visitor should be able to look around without making a decision.
- Posting requires registration. First connect with any key creates a pending account; the user chooses a handle and accepts the TOS; the key becomes the credential.
- Auth attempt rate limit per IP. Connection rate limit per IP. Max concurrent sessions per IP and globally.

**Registration mode is operator-configurable** (pillar 7), set at deployment:

| Mode | Behaviour |
|---|---|
| `open` | Anyone may register. Maximum reach, maximum moderation load. |
| `invite` | Registration requires a valid unused invite code. |
| `closed` | No new registrations. Existing users only. |

**The invite graph is stored and is an accountability mechanism, not just a growth limiter.** Each account records who invited it. Abuse becomes traceable upstream to whoever vouched, which changes behaviour before moderation ever engages. Operators can configure invites per user, invite regeneration rate, and whether an inviter is notified of moderation actions against their invitees.

**TOS acceptance is versioned.** Store the accepted version per user; a TOS change re-gates access until re-accepted. The TOS text is operator-supplied, not shipped.

### 5.5 Per-session limits

| Resource | Reason |
|---|---|
| Memory cap | One session cannot exhaust the box |
| CPU time slice | Doors are arbitrary compute |
| Output byte rate | A runaway render loop must not saturate the link |
| Image quota | Client-side kitty image memory is finite; a door must not exhaust the *user's* terminal |
| Session duration | Reclaim abandoned connections |

### 5.6 Container

- Non-root user. Read-only rootfs with tmpfs for scratch.
- All capabilities dropped. Seccomp profile applied.
- **No network egress.** The container accepts connections and talks to nothing.
- Memory, PID, and CPU limits set at the container level as a backstop to §5.5.

### 5.7 Host keys

Persist host keys on the mounted volume. If they regenerate on redeploy, every returning user gets a man-in-the-middle warning and a meaningful fraction never come back.

Small detail, outsized consequence. Get it right in M0.

In a multi-instance deployment (§8.3) the **same** host keys must be present on every instance, or users who reconnect and land on a different node get a MITM warning.

### 5.8 Operator posture and unlawful content

Any system hosting user-submitted content will eventually host something unlawful. Because this ships as OSS, the operator — not this project — bears that exposure and makes the policy calls. Obligations vary substantially by jurisdiction and by how a deployment is structured, and any operator running a public instance should get actual legal input rather than relying on this document.

**What the software provides:**

- Registration modes and the invite graph (§5.4).
- Versioned TOS gating.
- A report action on **every** user-generated surface: posts, threads, file entries, handles, profile text, and recipient-submitted chat transcripts (§6).
- A moderation queue with per-board moderators, delete, lock, shadow-ban, and an append-only audit log.
- Configurable retention for logs, deleted content, and uploads (§6.1).
- A **hook interface** for hash blocklists or external scanning on upload. The hook is defined; no scanner is implemented or bundled.
- Operator-facing documentation stating plainly what running a public board entails and which knobs exist.

**What the software does not do:** decide policy, ship a TOS, bundle a scanner, or assume a jurisdiction.

---

## 6. Board features

Scoped for a first public release.

- **Message boards.** Multiple boards, threaded, plain-text bodies, quote-reply. Read/unread tracking per user.
- **User list.** Handle, last seen, post count. No email, no real names, no location — collect nothing you do not need.
- **Who's online.** Current sessions, what screen they are on.
- **One-liners.** The scrolling wall of short messages. Cheap to build, disproportionately good at making a board feel inhabited.
- **File area.** Download only in MVP (§6.1). Descriptions, categories, byte counts.
- **Private chat.** See §6.2.
- **Door menu.** See §7. Visible read-only to guests.
- **Settings.** Capability override, display preferences, key management.
- **Moderation.** Per-board moderators, delete, lock, shadow-ban, audit log, and a report action on every user-generated surface. Build this in M1, not after the first incident.

### 6.1 Uploads — post-MVP, specified now

Uploads stay out of MVP. The design is recorded here so the file area is not built in a way that forecloses it.

- **Server-configurable age limit.** Uploads expire and are purged automatically. This bounds storage growth and bounds the liability window, which is the more important of the two.
- Configurable per-file and per-user size caps, and a global quota.
- Type allowlist rather than a blocklist.
- Uploads pass through the §5.8 scanning hook before becoming visible.
- Optional moderator approval queue before an upload is listed, operator-configurable.
- Uploader identity recorded and retained for the operator-configured retention window.

ANSI art galleries depend on this and follow it, not the other way round.

### 6.2 Private chat

User-to-user chat, **unmoderated by design and never persisted server-side.**

- Messages are delivered to the recipient's live session and held in session memory only. On disconnect they are gone. Nothing is written to storage, ever.
- This is period-authentic — BBS node chat was always ephemeral — and it collapses the liability surface to nothing while honouring pillar 8.
- Cross-instance delivery goes over the pub/sub channel in §8.3, keyed by recipient user ID.
- Users may block other users. Blocks are persisted.
- **Reporting is recipient-initiated.** A recipient may submit the transcript they received as a report. Recipient-submitted evidence preserves privacy by default while still giving moderators something to act on. There is no server-side transcript to subpoena, disclose, or leak.
- Rate limited per sender. Offline users cannot be messaged; there is no store-and-forward.

---

## 7. The door interface

Doors are pluggable applications launched from the board. The interface is generic — no door is special-cased.

### 7.1 Contract

```cpp
struct DoorManifest {
  DoorId        id;
  std::string   name;
  std::string   description;
  CapabilityTier min_tier;      // refuse below this
  bool          persists_state; // needs door_state storage
  bool          has_leaderboard;
};

struct DoorContext {
  UserId        user;
  Session&      session;        // render target + input stream
  Capabilities  caps;
  StateStore&   state;          // scoped to (door, user)
  ResourceLimits limits;
};
```

A door is entered, runs its own loop against the session, and returns an exit status. The board reclaims the screen on return regardless of how the door exits.

### 7.2 Capability gating

A door declares `min_tier`. If the session is below it, the menu shows the door as unavailable with a short note naming which terminals qualify. **Decline politely; never render a broken experience.**

### 7.3 Isolation

**v1: doors run in-process**, in a coroutine with exception isolation and the resource caps from §5.5. A door throwing or exceeding limits terminates that door session and returns the user to the menu with an apology. The board does not go down — this is a tested requirement.

Design the interface as a boundary that *could* become a process boundary later. Do not build out-of-process isolation in v1, but do not foreclose it: no shared mutable state across the interface, everything passed explicitly.

Third-party doors are out of scope until out-of-process isolation exists.

### 7.4 Leaderboards

Doors with deterministic simulation and recorded input can submit a replay. The server re-simulates to verify the claimed result before it enters the leaderboard.

This makes scores unfakeable without any anti-cheat machinery, and it is only possible because the server is already right there. Doors that cannot provide a verifiable replay get an unranked scoreboard, clearly labelled.

---

## 8. Persistence

### 8.1 Storage abstraction

Define a narrow `Store` interface from the first commit, with two implementations planned:

| Backend | Use |
|---|---|
| **SQLite** (WAL mode, on the volume) | Default. Single instance. Zero configuration. |
| **Postgres** | Multi-instance deployments only. |

SQLite is the default because zero-config matters enormously for OSS adoption — someone should be able to `docker run` and have a board. Postgres is opt-in and only needed when a second instance is.

**Build the interface in MVP. Do not build the Postgres implementation in MVP.** The point is not foreclosing it.

### 8.2 Schema

Tables: `users`, `user_keys`, `invites`, `tos_acceptances`, `boards`, `threads`, `messages`, `files`, `doors`, `door_state`, `leaderboards`, `oneliners`, `blocks`, `reports`, `moderation_log`, `sessions_log`, `presence`.

- All timestamps UTC, integer epoch.
- Message bodies plain UTF-8, sanitized (§5.2). ANSI is never stored.
- Private chat has **no table** (§6.2). This is deliberate.
- Periodic backup — SQLite backup API, or standard tooling on Postgres. Retain a rolling window.
- Schema migrations versioned and applied at startup, forward-only.

### 8.3 Multi-instance scaling

Not built in MVP, but the shape is decided so nothing blocks it.

**Pattern: stateless instances, Postgres for durable state, `LISTEN`/`NOTIFY` for ephemeral fanout.** No Redis, no message broker, no service discovery.

SSH gives this an advantage most systems have to engineer around: **a TCP connection is inherently sticky.** A session lands on an instance and stays there for its lifetime. No affinity logic, no token handoff, no sticky-session balancer configuration. Any L4 balancer or plain DNS round-robin is sufficient.

Only two things cross instance boundaries:

- **Durable state** — Postgres, read and written normally.
- **Ephemeral fanout** — presence changes, one-liners, and private chat delivery via `LISTEN`/`NOTIFY`. Fire-and-forget delivery and the 8KB payload cap are acceptable precisely because this data is ephemeral by definition. Chat routes on a channel keyed by recipient user ID; whichever instance holds that session picks it up.

Three details that bite if missed:

1. **Host keys must be identical across all instances** (§5.7). Different keys mean MITM warnings on reconnect to a different node.
2. **Presence needs heartbeat plus TTL**, not connect/disconnect rows. An instance that dies ungracefully otherwise leaves its users listed online forever.
3. **Per-IP rate limits become approximate.** Either move counters into Postgres or accept per-instance enforcement. Accept the approximation initially and document it.

### 8.4 Federation-compatible data model

Federation is not built (§13). But the *data model* forecloses it if handled carelessly, and data model decisions are one-way doors while protocol decisions are two-way doors. Spend on the former only.

**Constraints to honour now. Mechanism to build: none.**

| Constraint | Why it cannot wait |
|---|---|
| User references stored as `(handle, origin)`, origin null for local | Bare per-board-unique handles are referenced from messages, moderation logs, leaderboards, and blocks. Retrofitting means a migration across every foreign key. |
| Globally unique message IDs — composite `(origin, local_id)` or opaque unique string | Local autoincrement collides the moment foreign content arrives, and you inherit a mapping table permanently. |
| Boards addressed by stable GUID or `name@origin`, not local integer ID | Same collision problem, same permanence. |
| **Tombstone deletes, never row deletes** | You cannot tombstone what you already hard-deleted. Irreversible. Independently required by the moderation audit log. |
| `posted_at` (origin's claim) split from `received_at` (local) | Identical single-instance, divergent under federation. One column. |
| Canonical message serialization defined — fixed field order, defined encoding and normalization | If signing ever matters, both sides must agree on bytes to sign over. Retrofitting canonical form onto historical content can be flatly impossible. |
| **Sanitization must be lossless** | Stored bytes must be exactly what renders and what would be signed. Do not transform at render time in ways that cannot be reproduced. |

**Tombstone tax, acknowledged:** every read path now needs a status filter, and a missed filter leaks deleted content — a serious failure. Put the filter *inside* the `Store` interface rather than at call sites, so it exists in one place. This is a further reason to define the interface before writing the first query.

**Do not build:** peering protocol, key exchange, nodelist, conflict resolution, transport abstraction, or any federation configuration. All reversible, all better designed against real operators with real opinions than speculatively today.

**Note on signing:** in an SSH BBS the server composes the message, so it can never produce a *user* signature — the key authenticates the connection, it is not a signing oracle. The realistic model is board-level attestation: "board X asserts user Y posted this." That is FidoNet's trust model and matches what allowlist federation assumes anyway, so nothing is lost by not signing per-user.

---

### 8.5 Health and metrics endpoint

A small HTTP listener via **cpp-httplib** (header-only, no build system impact):

- Liveness: is the process up and accepting.
- Readiness: is storage reachable, is the SSH listener bound.
- Metrics: active sessions, registered users, memory in use, bytes out per session, door usage counts, uptime.

**Bind localhost-only or on a separate port behind auth. Never expose it publicly alongside the SSH listener.**

This is the same dependency a web UI would eventually use (§13), which is part of why it is the right choice now.

---

## 9. Rendering over a network link

Damage tracking stops being a nicety here. Over a link with real latency it is the difference between responsive and sludgy.

- **Instrument bytes-per-frame per session from the first commit.** It is a budget, not a metric to look at later.
- **Coalesce a frame's writes into a single socket write.** Many small writes interact badly with Nagle and with SSH packet framing.
- **Use synchronized output (DECSET 2026)** where available. Partial-write tearing is far more visible over a network than locally.
- **Do not run a fixed 60fps loop.** Render on state change. Where continuous animation is needed, pace it adaptively against measured RTT.
- Target under 100ms perceived latency for input echo.

There is a publishable benchmark here: full redraw versus damage-tracked bytes per session, plotted against RTT. That graph sells the library better than a feature list.

---

## 10. termforge feature requests

**Request 1 is the headline** — it is what turns termforge from a TUI library into one that can serve remote sessions, and it is the single largest thing this project gives back.

1. **Session abstraction.** Decouple an application from a process-owned tty. Render to an arbitrary byte sink, with capabilities, dimensions, and input stream owned per session rather than per process. Everything else here depends on it.
2. **Runtime capability negotiation** with hard timeouts, cached results, and manual override.
3. **Multiplexer detection** (tmux, screen) with automatic tier downgrade.
4. **Per-session resource accounting** — bytes out, image memory, allocation.
5. **Output coalescing** — batch a frame into one write.
6. **Control-character sanitization helpers** for rendering untrusted text.
7. **Adaptive frame pacing** keyed to measured round-trip time.

File these before writing application code around workarounds.

---

## 11. Milestones

### M0 — Echo
Embedded libssh. Session coroutine. `pty-req` and `window-change` handled. Renders one termforge widget and echoes input. Host keys persisted. Deployed in Docker: non-root, read-only rootfs, caps dropped, no egress.

**Gate:** can a stranger ssh in from an untested client and see a working termforge widget that survives a window resize?

### M1 — The board
Guest browsing and key registration with all three registration modes. Invite graph. Versioned TOS gating. Boards, threads, posting, one-liners, who's online, user list. Moderation tooling with reporting on every surface. Full input sanitization. Storage interface with the SQLite implementation. **Tier 0/1 rendering only.**

**Gate:** is it pleasant to read and post from a plain 80×24 terminal? If it is not good here, no amount of tier 3 will save it.

### M2 — Capability tiering
Probe with timeouts, caching, manual override. Tier 2 and 3 rendering. Multiplexer detection and downgrade messaging. Ephemeral private chat with blocks and recipient-initiated reporting.

**Gate:** does a modern terminal feel meaningfully better without any regression for an old one?

### M3 — Doors
Door interface, registry, launch and return, capability gating, state persistence, replay-verified leaderboards. First door landed.

### M4 — Open
Fuzzing in CI. Load test at 50 concurrent sessions. Rate limits tuned under load. Operator documentation written. Public announcement.

### Post-MVP, in rough order
Uploads with age limits and the scanning hook (§6.1). ANSI art galleries. Postgres backend and multi-instance deployment (§8.3). Out-of-process door isolation, and third-party doors behind it. A web UI on the existing cpp-httplib dependency — if ever.

---

## 12. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| termforge assumes a process-owned tty | **High** | Request 1 in §10. Likely the largest single engineering cost in the project — scope it before committing to a date. |
| Escape injection via user content | **High** | §5.2, sanitize at both ends, fuzz the path |
| Untrusted input parsed in C++ | **High** | §5.3, fuzzing as a CI gate |
| Capability probe hangs or misdetects | Medium | Hard timeouts, manual override always available |
| Door takes down the board | Medium | §7.3 isolation, tested explicitly |
| Host keys regenerate on deploy | Medium | Volume-persisted, verified in M0 |
| Small audience | Low | Expected. Dozens of regulars is the realistic and acceptable outcome. |

---

## 13. Non-goals

- **No password authentication.** Keys only, no exceptions.
- **No file uploads in MVP.** Downloads only. Design recorded in §6.1 so nothing forecloses it.
- **No public web interface.** The cpp-httplib listener is health and metrics only, bound privately (§8.4). A web UI is a distant post-MVP maybe, not a plan.
- **No third-party doors** until out-of-process isolation exists.
- **No federation mechanism.** No peering protocol, key exchange, nodelist, or conflict resolution. Multi-instance (§8.3) is horizontal scaling of *one* board, which is a different thing. The data model deliberately does not foreclose federation (§8.4), but no mechanism is built and none should be until multiple independent boards exist and their operators ask for it.
- **No append-only or immutable content logs.** Content must remain deletable. This rules out p2p designs built on append-only signed logs or content-addressed permanence, however elegant — an undeletable store is incompatible with retention limits and takedown obligations.
- **No server-side storage of private chat.** Ever. This is a design commitment, not a deferral.
- **No store-and-forward messaging.** Offline users cannot be messaged.
- **No bundled scanner, TOS, or moderation policy.** Hooks and knobs only (§5.8).
- **No voice, no synchronous group chat.**
- **No mouse-required interaction.**
- **No telemetry, no analytics, no PII collection.** Handle, public key, and invite edge is the entire user record.

---

## 14. Decisions taken

Recorded so they are not relitigated in a later session.

| Question | Decision |
|---|---|
| Registration gating | Operator-configurable: `open` / `invite` / `closed`. Invite graph stored for accountability. |
| TOS | Required at registration, versioned, re-gates on change. Text is operator-supplied. |
| Private chat | Supported, unmoderated, **never persisted**. Recipient-initiated reporting. |
| Uploads | Post-MVP. Server-configurable age limit on arrival. Scanning hook, no scanner. |
| ANSI art galleries | Follow uploads; they depend on them. |
| Guest access to door menu | Yes, read-only. |
| Load test target | 50 concurrent sessions. |
| Health endpoint | Yes — liveness, readiness, and metrics over cpp-httplib, bound privately. |
| Storage | SQLite default, interface abstracted, Postgres for multi-instance only. |
| Multi-instance pattern | Stateless instances, Postgres, `LISTEN`/`NOTIFY`. Not built in MVP. |
| Federation | Not built. Data model keeps the option open (§8.4). If it ever happens: allowlist peering, board-level attestation, SSH transport, mutable state — never p2p append-only logs. |
| Web UI | cpp-httplib if it ever happens. Well past MVP. |

## 14b. Still open

1. Invite economics: how many invites per user, on what regeneration schedule, and does an inviter get notified of moderation actions against their invitees? Defaults need picking even though they are configurable.
2. Does shadow-ban belong in the moderation set, or does it create more confusion than it prevents at small scale?
3. Board-level read permissions — are all boards visible to guests, or can an operator mark some registered-only?
4. Retention defaults for `sessions_log` and `moderation_log`. Long enough to investigate, short enough not to be a liability.
5. Whether presence should show *what screen* a user is on, or only that they are online. The former is more alive, the latter is less surveillant.

---

## 15. Immediate next actions

1. File the seven termforge issues (§10), and scope request 1 first — the milestone plan depends on how large it turns out to be.
2. Stand up M0 end to end, including the Docker hardening, before writing any board features. Deployment posture is much harder to retrofit than to start with.
3. Persist host keys and verify across a redeploy on day one.
4. Define the `Store` interface before writing the first query. Retrofitting an abstraction over scattered SQLite calls is the kind of work nobody wants to do later.
5. Instrument bytes-per-frame and cold-start time from the first commit.
6. Write the sanitization layer and its fuzz harness before the first user-submitted text is stored anywhere.
7. Draft the operator documentation early, not at release. Writing down what an operator is responsible for tends to surface missing knobs while they are still cheap to add.
