# ANVIL

**A public bulletin board you reach with one command.**

```
ssh anvil.example.org
```

No account setup, no client to install, no toolchain. Boards, files, and door
games served to anyone with a terminal — built entirely on
[termforge](https://github.com/gobha-me/termforge), C++23, in a single hardened
container.

> **Status: M1 identity foundation.** The standalone plugin loader, stable plugin SDK
> boundary types, process-isolated TermForge SSH session, persistent host
> identity, live remote resize handling, bounded session lifecycles,
> supervisor-enforced per-IP admission limits, private health/readiness/metrics,
> database-backed public-key identities, read-only guest access, pending
> registration, and the hardened container are implemented. See
> [`anvil-bbs-design.md`](anvil-bbs-design.md) for the architecture and the issue
> tracker for the work breakdown.

The first M1 security boundary is also in place: user-authored prose is made
visibly inert before storage and sanitized again before rendering. Anvil uses
TermForge's single control-sequence parser for both policies, so OSC, CSI,
C0/C1 controls, and malformed UTF-8 cannot drift between two implementations.
Ingest rejects malformed UTF-8 before sanitization and applies explicit
Unicode grapheme, raw-byte, and logical-line limits for every planned user text
field. M1 handles are intentionally limited to ASCII letters, digits, `_`, and
`-`; accepted text is never normalized or silently truncated.

Network callback adapters mark peer-controlled payloads with a server-private
`RemoteBytes` span before project-owned parsing. This keeps hostile provenance
visible in function signatures, rejects invalid pointer/length pairs at the
adapter, and makes bounded span operations the only path into parsers.

---

## What it is

A BBS in the original sense: asynchronous, text-first, and inhabited. Message
boards with threads and quote-reply, a one-liner wall, who's-online, a user
list, a file area, ephemeral user-to-user chat, and pluggable door games.

Three things make it worth building:

- **It is the best possible demo of termforge.** A stranger experiences a live
  termforge application in five seconds — no clone, no build, no dependency
  hunt. Screenshots do not prove a render loop; a running system someone can
  touch does.
- **It is a venue, not an app.** Boards and doors land incrementally into a
  place that already has people in it. The board ships first and stays useful
  even if nothing else ever lands.
- **It is meant to be extended by other people.** The plugin interface is the
  point, not an internal convenience that happens to be documented. A handful
  of first-party plugins exist to prove the interface works and to seed the
  menu — not to be the catalogue.

## How it works

The SSH server is **embedded in the application** (libssh server API) — one
process, one port, one coroutine per session. There are no system users and no
shell, so there is nothing to escape to. Docker is packaging, not a security
boundary.

```
  SSH clients ──▶ libssh supervisor (accept + auth)
                        │
                        ▼
                 Session worker ──────▶ Shared services ──▶ SQLite
                 (process-isolated M0;   (boards, doors,     (volume)
                  pooled coroutines      users)
                  remain the target)
```

## M0 SSH transport

The `anvil` executable listens on one address and port and starts one isolated
worker process per connection. Registered identities use public keys only;
the exact SSH username is not an authority. The reserved `guest` username may
authenticate anonymously into a read-only board and door-menu shell. Unknown
signed keys reach pending registration. The M1 shell is a demand-rendered
TermForge screen that reports the remote dimensions and retains the M0 echo
field for bootstrap-active users. The initial size and every SSH
`window-change` are bounded before reaching the renderer; invalid changes keep
the last valid size. An interactive PTY is required. SSH sessions started with
`-T`, `exec`, and subsystem requests are rejected with exit status 126; no
system shell or subsystem is reachable.

Build and run it with a persistent host-key path. Existing deployments may
bootstrap one or more active identities from public-key files:

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/hardened.cmake
cmake --build build --parallel

install -d -m 700 state
./build/anvil \
  --bind-address 127.0.0.1 \
  --port 2222 \
  --max-sessions 64 \
  --max-sessions-per-ip 4 \
  --connection-rate-limit 10/10 \
  --auth-attempt-rate-limit 6/60 \
  --max-auth-attempts-per-session 6 \
  --max-tracked-ips 4096 \
  --idle-timeout-seconds 300 \
  --idle-warning-seconds 30 \
  --session-cap-seconds 86400 \
  --session-memory-bytes 67108864 \
  --session-cpu-burst-ms 50 \
  --session-output-bytes-per-second 1000000 \
  --session-image-bytes 33554432 \
  --database state/anvil.db \
  --registration-mode open \
  --backup-directory state/backups \
  --backup-interval-seconds 86400 \
  --backup-retention-seconds 604800 \
  --host-key state/host_key \
  --authorized-key demo="$HOME/.ssh/id_ed25519.pub"
```

When the host-key path is absent, Anvil creates one unencrypted Ed25519 key
with mode `0600`. It publishes the complete key atomically, so concurrent
instances using one volume converge on the same identity. An existing key is
used unchanged, including another key type supported by libssh; an unreadable,
malformed, symlinked, oversized, or over-permissive existing path stops startup
and is never silently replaced. The parent directory must already exist and be
writable on first start. In a deployment, mount that directory from persistent
storage: losing it gives every returning user a host-key warning.

Each optional authorized-key file must contain exactly one ordinary OpenSSH
public-key line. At startup, `--authorized-key USER=PATH` imports the key into
SQLite as an active identity; exact repeats are idempotent, while conflicting,
revoked, or non-active mappings stop startup rather than overwriting identity
state. Repeat the option to bootstrap additional users or keys. The server
refuses symlinked key files, oversized or malformed key material, and host
private keys accessible by group or others.

Connect anonymously with `ssh guest@HOST`. Guest sessions can see the board
and door-menu shell but have no writable controls. Any signed key not yet in
the database is governed by `--registration-mode`: `open` permits handle
selection, `invite` requires a valid single-use invite before handle selection,
and `closed` explains that the board is not accepting registrations while
preserving guest browsing. The default is `open`, and mode changes affect only
new registrations. The key and chosen handle are stored as pending; pending
identities remain gated until versioned TOS acceptance lands in issue #40.
There is no email or recovery address: losing every registered key loses the
account.

Invite codes are bounded opaque tokens. Anvil stores only their SHA-256 hashes
and atomically claims a code with its pending account, so concurrent reuse has
exactly one winner. Issue #39 adds user-facing invite issuance and economics;
until then, invite mode consumes already-provisioned rows in the `invites`
table.

Send `SIGINT` or `SIGTERM`
to stop accepting connections. Active shells receive a shutdown message and
are closed before their workers are reaped; a worker that does not drain within
five seconds is killed. The session limit bounds concurrent workers; excess
connections are closed before libssh allocates a session, performs key
exchange, or forks a worker. The default per-IP concurrent limit is four.

The supervisor also applies two per-IP token buckets before key exchange.
`--connection-rate-limit COUNT/PERIOD_SECONDS` counts every accepted TCP
connection and defaults to a burst of 10 replenished uniformly over 10
seconds. `--auth-attempt-rate-limit` counts denied authentication requests and
defaults to 6 over 60 seconds; workers report denials to the supervisor so the
next connection is refused before it can make key exchange expensive. A
single connection is closed after six denials by default, configurable with
`--max-auth-attempts-per-session`. Limiter state is capped at 4096 IPs by
default and idle, fully replenished entries are evicted. All counters are
per-instance. Without PROXY-protocol support, a TCP proxy's address is the
client IP seen by these limits.

An authenticated session is warned 30 seconds before the default five-minute
idle timeout. Any input resets and re-arms that warning; server output does not
count as activity. A separate 24-hour cap applies even to active sessions.
Operators can set all three positive durations in whole seconds with
`--idle-timeout-seconds`, `--idle-warning-seconds`, and
`--session-cap-seconds`; the warning must remain shorter than the idle timeout.
Each worker also receives 64 MiB of address-space headroom, a 50 ms maximum
uninterrupted application CPU burst, a 1,000,000-byte-per-second output bucket
with a one-second burst, and a 32 MiB resident terminal-image source-payload
quota. Operators can set positive values with `--session-memory-bytes`,
`--session-cpu-burst-ms`, `--session-output-bytes-per-second`, and
`--session-image-bytes`. Output is delayed to the configured rate; a single
frame larger than its one-second burst is rejected. Anvil-mediated image
uploads must reserve their source payload before transmission and the renderer
reconciles that reservation against the driver's per-session residency counter.
Exceeding any cap closes only that connection with a specific message and is
logged with the resource class.
Each completed shell logs its rendered-frame count, accepted frames, byte
breakdown, and channel-open-to-first-frame latency. These are the internal M0
measurements exposed by the private metrics endpoint.

Each SSH connection runs in a dedicated worker process during the M0 staging
architecture. An exception escaping the terminal application closes only that
session with a generic apology, while the worker logs a fixed failure class and
its process id. A fatal signal likewise terminates only its worker; the
supervisor reaps it, releases its admission slot, and continues serving other
and new sessions. The worker process is also the hard boundary for the memory
ceiling and for terminating an application that exceeds its uninterrupted CPU
slice. These controls contain accidental failures in cooperative code; they are
not a sandbox for a malicious in-process plugin. A future transition to pooled
in-process sessions must prove this isolation contract again before replacing
the worker boundary.

## Private health and metrics

Anvil serves operational HTTP endpoints on `127.0.0.1:8080` by default, in a
dedicated process that cannot add threads to the SSH supervisor before it forks
session workers:

```sh
curl --fail http://127.0.0.1:8080/livez
curl --fail http://127.0.0.1:8080/readyz
curl --fail http://127.0.0.1:8080/metrics
```

`/livez` is healthy only while the supervisor heartbeat is current and the SSH
listener is accepting. `/readyz` additionally fails when any configured storage
backend is unreachable or any enabled plugin failed to load, and names the
failed component and reason. The default SQLite component reports its schema
version; plugins remain explicitly not configured until the registry exists.
`/metrics` uses the
Prometheus text format and exposes uptime, resident memory, active sessions,
opaque per-session frame/byte/latency counters, registered-user and door counts,
and configured plugin status/version. Per-session byte metrics include
`anvil_session_output_bytes_total` counters and
`anvil_session_last_frame_output_bytes` gauges, each split into `cells`,
`image_transmit`, and `image_edit` kinds. It never labels a session with its
username, address, or other identity.

Change the listener with `--health-bind-address` and `--health-port`. The health
port must differ from the SSH port. The default Compose deployment does not
publish port 8080. If a non-loopback bind is required for a private monitoring
network, put it behind authentication and do not publish it on the public SSH
ingress: the metrics are a presence and population feed.

## Hardened container

The shipped Compose deployment runs a shell-free `scratch` image as numeric
user `65532:65532`. It publishes the unprivileged container port 2222, drops
all capabilities, enables Docker's built-in seccomp profile and
`no-new-privileges`, makes the root filesystem read-only, and provides only a
bounded `/tmp` plus the persistent `/var/lib/anvil` volume as writable paths.
The volume holds the SSH host identity now and the board database when storage
lands.

Create or choose an SSH key for the account that will be allowed into the M0
server, then start the default egress-closed deployment:

```sh
export ANVIL_AUTHORIZED_KEY="$PWD/demo_ed25519.pub"
export ANVIL_USER=demo
docker compose up --build --detach
ssh -p 2222 demo@127.0.0.1
```

`ANVIL_PORT` changes the published host port without granting
`CAP_NET_BIND_SERVICE`. The container-level backstops default to two CPUs,
512 MiB of memory, 256 PIDs, and a 16 MiB tmpfs; override them with
`ANVIL_CPU_LIMIT`, `ANVIL_MEMORY_LIMIT`, `ANVIL_PID_LIMIT`, and
`ANVIL_TMPFS_LIMIT`. `ANVIL_REGISTRATION_MODE` selects `open`, `invite`, or
`closed` and defaults to `open`.

The default Docker bridge disables IP masquerading, so sessions and future
plugins have no outbound Internet route while the published SSH port remains
reachable. Deployments that need supported egress opt in with the small
override file:

```sh
docker compose -f compose.yaml -f compose.egress.yaml up --build --detach
```

Opening egress is an operator choice, not an unsupported posture. It permits
push metrics and future network-using plugins, and correspondingly reduces the
cost imposed on data exfiltration. Metrics scraping, health checks, and local
sidecar scanning do not need the override.

The production image is compiled with `_FORTIFY_SOURCE=3`, libstdc++ bounds
assertions, stack and stack-clash protection, zero initialization of trivial
automatic variables, PIE, full RELRO, immediate binding, and a non-executable
stack. On x86 it also enables CET indirect-branch and shadow-stack metadata.
CI inspects the final ELF for those properties instead of trusting the command
line used to build it.

### Parse-path review checklist

Changes that touch remote input must satisfy all of the following before
review:

- mark hostile bytes at the external callback or descriptor adapter;
- cap lengths before allocating, copying, or advancing a view;
- pass `RemoteBytes` or `std::span`, never a pointer-and-length pair;
- keep remote-sized data off the stack and avoid raw pointer arithmetic; and
- test every parser with truncated input under ASan and require a clean error
  with no partial state change.

For continuous staging, use the dedicated ASan+UBSan image. It keeps debug
symbols, stops on the first sanitizer finding, and otherwise runs with the same
container and network posture:

```sh
docker compose -f compose.yaml -f compose.staging.yaml up --build --detach
```

The staging image is diagnostic and must not be promoted as the production
artifact. Issue #23 will drive this image through the concurrent-session load
test when that test lands.

## Design pillars

1. **Reach beats spectacle at the shell level.** The board must work from
   PuTTY, Terminal.app, and inside tmux. Enhanced rendering is opt-in per
   screen, never a barrier to entry.
2. **No system users, no shell, ever.**
3. **All remote input is hostile** — in both directions. Parsing is the primary
   attack surface and is treated as such.
4. **Async and text-only.** No voice, no synchronous lobbies.
5. **Bounded per session.** Memory, CPU, output rate, and image quota are
   capped per connection. One user cannot degrade the board.
6. **Restartable without user-visible breakage.** Host keys, accounts, and
   state survive redeploys.
7. **Mechanisms, not policy.** Other people will run this. Ship the knobs —
   registration mode, retention, limits, moderation tooling — and let each
   operator set their own posture.
8. **Store nothing you do not need.** What is never written cannot leak, cannot
   be subpoenaed, and cannot be moderated badly.
9. **The plugin interface is a public contract.** Someone else's code depends
   on it, built with a toolchain this project does not control, on a schedule
   it does not set. Breaking it is a release event with a migration note, not
   a refactor.

## Capability tiering

Reach and graphics are resolved by tiering rather than by choosing.

| Tier | Requires | Used for |
|---|---|---|
| 0 — Teletype | 80×24, ASCII, no color | Absolute fallback. Never blocks access. |
| 1 — ANSI | 16 color, box drawing, cursor addressing | **The baseline board experience.** |
| 2 — Modern | Truecolor, unicode width, synchronized output, kitty keyboard | Enhanced chrome, better input |
| 3 — Graphics | Kitty graphics protocol | Doors that require it, art galleries |

The board shell targets tier 1. Capability detection is by active probing with
hard timeouts, and is **always manually overridable** — probes get it wrong
often enough that the override is a functional requirement, not politeness.

## Mods

The core is a shell — SSH transport, sessions, storage, users, moderation, and
the UI chrome. Boards and doors and anything else that is *functionality*
arrive as plugins loaded at runtime, and **anyone can write one**. First-party
plugins load through the same manifest, pass the same ABI check, and get the
same context object as everybody else's; the moment one needs a private hook,
the public interface has a hole in it.

Two consequences worth knowing before you build against it:

**The boundary is narrow on purpose.** It is a C++ abstract base class — vtable
layout is fixed by the Itanium ABI, so that part is portable — but only
Anvil-defined types cross it: PODs, fixed-width enums, `Str`, `Span`, opaque
handles. No `std::string`, no containers, no smart pointers, because their
layouts differ between libstdc++ and libc++ and the failure is silent memory
corruption rather than a link error. A header-only SDK wrapper compiled in your
translation unit converts back to ordinary modern C++, so you write normal code
and your mod keeps working across an Anvil toolchain bump.

**A plugin runs in-process with full privilege, and there is no sandbox.** It
can read the host keys and every live session's memory, and it does not have to
go through the interface to do it. Installing one is equivalent to running a
patched server binary from that author — there is no lesser degree of trust
available, and the design says so plainly rather than shipping an isolation
story that implies otherwise.

That is the model rather than a stage on the way to something else, and it is
what every native plugin ecosystem does — Postgres extensions, nginx modules,
Vim, OBS, VST. It works because the trust question has an answer: **trust here
is transitive and already spent.** Running Anvil at all means trusting whoever
built it with your host keys and your user database. A plugin author is the
same decision about a different person. Operators pin a content hash against a
named author, every load is audit-logged, and signed releases are the next
thing on that path.

## Roadmap

| Milestone | Gate |
|---|---|
| **M0 — Echo** | Can a stranger ssh in from an untested client and see a working termforge widget that survives a window resize? |
| **M1 — The board** | Is it pleasant to read and post from a plain 80×24 terminal? |
| **M2 — Capability tiering** | Does a modern terminal feel meaningfully better without any regression for an old one? |
| **M3 — The plugin platform** | Does a plugin built outside the tree, against published headers, with a different compiler than the server's, load and run? |
| **M4 — Client and leaderboards** | Vendorable client library, replay submission, server-side re-simulation, first external title submitting. |
| **M5 — Open** | Fuzzing in CI, 50 concurrent sessions under load, operator docs, SDK published with a versioning commitment, announcement. |

A standalone, heavily tested **plugin loader library** is a prerequisite of M3
and is independent of everything else — it can be finished while the termforge
work is still being scoped.

## Plugin SDK boundary

`anvil::sdk` is an installable, header-only C++23 target containing the types
that may cross the plugin boundary. Include `<anvil/sdk/types.hpp>` to use
`anvil::Str`, `anvil::Span<T>`, `anvil::Version`, `anvil::PluginKind`, and
`anvil::CapabilityTier`. `<anvil/sdk/abi.hpp>` additionally publishes
`anvil::InterfaceVersion` and the ABI tag. `<anvil/sdk/plugin.hpp>` publishes
the raw plugin manifest, door context, and `IPlugin` / `IDoor` vtables. Plugin
authors normally include `<anvil/sdk.hpp>` instead; it is the standard-library
friendly layer compiled entirely in the plugin's own translation unit.

`Str` and `Span<T>` are borrowed views: the owner of `data` must keep it alive
for the duration specified by the interface carrying the view. `Span<T>` only
accepts trivially-copyable, standard-layout element types, and constness belongs
in `T`. These primitive view/value types have fixed layouts and no member
functions. Extensible plugin manifests, capabilities, limits, and contexts put
`uint32_t struct_size` first so appended fields can be detected safely.

`PluginManifest` carries a borrowed textual `PluginId`, display strings,
author, version, and kind. `DoorManifest` declares the minimum terminal tier
and its state, leaderboard, and optional-audio traits. `DoorContext` carries an
opaque `UserId`, session capabilities and dimensions, per-session resource
limits, and pointers to the session and state-store services. Those service
interfaces remain opaque until their callable contracts land; no unfinished
service vtable is frozen into plugin interface 1.2.

The boundary headers deliberately contain no standard-library surface types.
Their size, alignment, offset, and fixed-width assertions compile in every host
and plugin translation unit, including a dedicated 32-bit CI check.

The wrapper converts `std::string`, `std::string_view`, C strings, and
contiguous ranges to borrowed raw views. Conversions from temporary strings and
ranges are deleted, so the common dangling-borrow mistake does not compile.
`anvil::sdk::Door<Impl>` owns its manifest strings for the plugin instance's
lifetime and turns every exception escaping `Impl::run_door(DoorContext)` into
`PluginStatus::exception` before control returns to the host. A complete plugin
exports its ABI tag, factory, and plugin-owned destroy function with one macro:

```cpp
#include <anvil/sdk.hpp>

class ClockDoor final : public anvil::sdk::Door<ClockDoor> {
public:
  ClockDoor()
      : Door({"org.example.clock", "Clock", "A quiet clock", "Example",
              {1, 0, 0}, anvil::PluginKind::door},
             {anvil::CapabilityTier::ansi, false, false, false}) {}

  void run_door(anvil::sdk::DoorContext context) {
    // Ordinary C++ is safe here. Exceptions become a boundary status.
  }
};

ANVIL_PLUGIN(ClockDoor);
```

`Str` returned by the adapter remains valid for the plugin instance's lifetime,
but the host still copies manifest text before retaining it. Raw contexts and
views are borrows for the duration of the call only.

`<anvil/sdk/abi.hpp>` defines the fixed-layout `AnvilAbiTag`. A plugin exports
the complete tag as data with one global-scope declaration:

```cpp
#include <anvil/sdk/abi.hpp>

ANVIL_PLUGIN_ABI_TAG();
```

The host refuses mismatched magic, an inconsistent structure size, a plugin
interface outside its accepted ranges, or mismatched sanitizer state. Compiler,
compiler version, standard-library identity, and language-standard fields are
retained as diagnostics rather than compatibility gates. The current plugin
interface is `1.2`; the accepted range is `1.0` through `1.2`.

The tag's fixed 16-byte prefix is sufficient to decide compatibility. An older
tag may therefore be shorter than the host's `AnvilAbiTag`: the loader copies
only readable bytes into zero-initialized storage, and the host checks both
`struct_size` and the ELF symbol's actual size before reading an appended
field. A tag that claims bytes its symbol does not contain is refused.

Clang exposes ASan, UBSan, and TSan state to the header. GCC exposes ASan and
TSan but has no UBSan predefined macro, so a GCC UBSan plugin build must define
`ANVIL_ABI_SANITIZER_UNDEFINED=1`; Anvil's UBSan toolchain does this
automatically.

## Plugin loader

`anvil::loader` is an installable C++23 library around the Linux ELF/glibc
dynamic loader. It opens plugins with `RTLD_NOW | RTLD_LOCAL`, resolves an ABI
tag as a data symbol, validates it, and only then resolves the plugin-owned
factory and destroy entrypoints. The returned `Loaded<I>` keeps the shared
object mapped for as long as any instance exists, including when a caller
retains only the instance's `shared_ptr`.

```cpp
auto plugin = anvil::loader::load<IPlugin>(
    "/srv/anvil/plugins/example.so",
    anvil::loader::AbiRequirement<anvil::AnvilAbiTag>{
        anvil::current_abi_tag, anvil::loader::verify_abi_tag,
        anvil::kAbiTagPrefixSize,
        anvil::loader::abi_tag_declared_size});
if (!plugin) {
  log(plugin.error().message());
}
```

The loader remains generic: custom tags must be trivially-copyable,
standard-layout types and custom verifiers receive the expected tag, the
zero-filled observed tag, and its logical readable byte size, then return
`std::expected<void, std::string>`. Each requirement names the minimum readable
prefix and may provide a logical-size reader for appendable tags; these default
to the complete custom tag and no reader. The Anvil reader prevents sanitizer
padding in an ELF data symbol from being mistaken for fields. `verify_abi_tag`
supplies the Anvil policy and names every mismatch. Symbol names are
configurable and default to `anvil_abi_tag`,
`anvil_plugin_create`, and `anvil_plugin_destroy`.

## Storage interface

`anvil::store` is the installed, host-only C++23 persistence seam. It is
separate from the fixed-layout plugin SDK boundary and may use standard-library
types. `<anvil/store.hpp>` provides a backend-neutral `Store`, structured
errors, explicit read-only and read-write transaction modes, and a signed UTC
epoch-seconds value.

Transactions are move-only. A successful commit or an explicit rollback ends
the transaction; destroying an unfinished transaction rolls it back exactly
once. A failed commit leaves the transaction active so stack unwinding still
rolls it back. The originating `Store` must outlive its active transactions.
Store implementations keep database-specific transaction state behind
`TransactionBackend`; domain queries are added with the board, moderation, and
plugin-state features that own them rather than pre-freezing a SQLite-shaped
API.

The test suite provides a database-free in-memory implementation so domain
logic can depend on `Store` without linking SQLite. The server's private SQLite
implementation keeps that property: it stores only a path and opens an
independent connection for each transaction, so session-worker forks never
inherit a live database handle. Read transactions are SQLite `query_only`
deferred transactions; write transactions begin immediately and competing
writers wait for at most five seconds.

At startup Anvil creates `anvil.db` in the working directory unless
`--database PATH` overrides it, enables WAL mode with `synchronous=FULL`, and
applies every pending migration in one transaction before opening either
listener or forking. Migrations are compiled into the binary, strictly
forward-only, and tracked with SQLite's `user_version`. Schema version 1 claims
the otherwise empty file with application ID `ANVL`; version 2 adds the exact
17-table domain schema. An unknown application ID, a non-empty unclaimed file,
corrupt data, or a schema newer than the binary stops startup. There is no
migration metadata table, private-chat table, or plugin-owned table.

The schema stores local users with a null origin and carries `(handle, origin)`
through every user reference. Boards use canonical lowercase UUIDs, messages
use opaque globally unique IDs, and origin-claimed `posted_at` is separate from
local `received_at`. All timestamps are signed integer UTC epoch seconds. User
text is stored only as SQLite `TEXT`; the ingest and render boundaries remain
responsible for the lossless UTF-8 and control-character rules.

`Store::tombstone` is the only lifecycle transition for boards, threads,
messages, files, leaderboard entries, one-liners, blocks, and reports. It is
idempotent for an existing tombstone, reports a missing target distinctly, and
never cascades or deletes a row. Ordinary `find_message` and
`list_messages_for_board` reads exclude tombstoned messages and messages under
a tombstoned thread or board. Moderation and audit code must opt into the
deliberately verbose `*_including_tombstones` methods. The in-memory Store uses
the same filtered contract and transaction commit/rollback semantics as the
SQLite backend.

Canonical message bytes begin with `ANVILMSG`, a big-endian 32-bit version, and
then message ID, board ID, thread ID, optional parent ID, author handle,
optional author origin, body, and posted-at time in that order. Strings are the
exact stored UTF-8 bytes with big-endian 64-bit lengths; optional strings have
an explicit one-byte presence marker, and the signed epoch is represented by
its big-endian two's-complement bits. Mutable status and local receipt time are
excluded from the origin's attestation. Version 1 of this representation never
normalizes or otherwise rewrites stored text.

WAL's default 1,000-page automatic checkpoint remains enabled. `FULL` is
intentional: a low-volume BBS should not trade away the most recent committed
posts on sudden power loss merely to remove one sync per commit. The database,
its `-wal` file, and its `-shm` file are one unit of live state; use SQLite's
backup API rather than copying any of them while the server is running.

`--backup-directory PATH` enables an immediate snapshot at startup and periodic
snapshots thereafter. The interval defaults to one day and the rolling window
defaults to seven days; override them with `--backup-interval-seconds` and
`--backup-retention-seconds`. Each private snapshot directory contains a
standalone SQLite backup, the exact SSH host key, and a versioned manifest.
Only completed snapshots participate in retention, pruning runs only after a
new snapshot succeeds, and the newest successful snapshot is always retained.
The supplied Compose deployment stores these snapshots under
`/var/lib/anvil/backups` on the persistent volume.

Backups contain both user content and the board's private host key. Protect the
backup volume accordingly. A seven-day backup window also makes deleted data
recoverable for up to seven days, even if another retention setting is shorter.
Choose these values as one retention policy rather than treating backups as an
exception.

Create an operator-requested snapshot without starting listeners:

```sh
./build/anvil \
  --backup-now state/backups \
  --database state/anvil.db \
  --host-key state/host_key
```

Restore only while the server is stopped. Remove the destroyed database, its
`-wal` and `-shm` sidecars, and the lost host-key file first; restore refuses to
overwrite any of them. It validates the private snapshot, SQLite integrity and
schema, and host key before publishing new `0600` files:

```sh
./build/anvil \
  --restore-backup state/backups/anvil-backup-EPOCH-SUFFIX \
  --database state/anvil.db \
  --host-key state/host_key
```

## Version compatibility

Plugin compatibility is stated against the plugin interface, not the server or
SDK package release. A plugin README should say, for example, "requires Anvil
plugin interface 1.x, minimum 1.0." The SDK/package follows its own semantic
version: a wrapper or documentation fix may bump that package without changing
the interface. When the server exists, its release version will be a third,
independent stream.

| Anvil SDK/package | Accepted plugin interface |
|---|---|
| `0.3.0` | `1.0` |
| `0.4.0` | `1.0` |
| `0.5.0` | `1.0–1.1` |
| `0.6.0` | `1.0–1.2` |
| `0.7.0` | `1.0–1.2` |
| `0.8.0` | `1.0–1.2` |
| `0.9.0` | `1.0–1.2` |
| `0.10.0` | `1.0–1.2` |
| `0.11.0` | `1.0–1.2` |
| `0.12.0` | `1.0–1.2` |
| `0.13.0` | `1.0–1.2` |
| `0.14.0` | `1.0–1.2` |
| `0.15.0` | `1.0–1.2` |
| `0.16.0` | `1.0–1.2` |
| `0.17.0` | `1.0–1.2` |
| `0.18.0` | `1.0–1.2` |
| `0.19.0` | `1.0–1.2` |
| `0.20.0` | `1.0–1.2` |
| `0.21.0` | `1.0–1.2` |

Every release adds its accepted ranges to this table. A future interface-major
transition includes a migration note and announcement, and defaults to one
server-release overlap in which both majors load when the layouts can safely
coexist. Any release that cannot offer that window must say so explicitly.

The ordered fields, enum values, and virtual methods published by the SDK are
recorded in `cmake/sdk_abi_history.json`. CI derives the live declarations from
Clang's AST and compares them with the latest snapshot. Within one major,
existing declarations must remain exact prefixes and every trailing addition
requires a new minor snapshot; reorder, removal, or signature changes require a
new major snapshot. This is the gate behind "append, never insert."

There is one unavoidable ordering boundary: `dlopen()` runs a shared object's
ELF initializers before returning. An ABI refusal therefore guarantees that no
exported plugin entrypoint was resolved or called, not that no machine code from
the shared object ran. Admission, provenance, and content-hash checks must happen
before passing a path to this library. Plugins use hidden visibility with only
the tag, factory, and destroy symbols exported, and destruction must return to
the plugin rather than using host-side `delete`.

Build and test with both supported compilers:

```sh
CXX=g++-13 cmake -S . -B build-gcc \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/default.cmake
cmake --build build-gcc --parallel
ctest --test-dir build-gcc --output-on-failure

CXX=clang++ cmake -S . -B build-clang \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/default.cmake
cmake --build build-clang --parallel
ctest --test-dir build-clang --output-on-failure
```

Use `cmake/toolchain/hardened.cmake` with `Release` or `RelWithDebInfo` for a
production ELF. Configuration fails for an unoptimized build so fortification
cannot silently become a no-op. Use
`cmake/toolchain/address-undefined.cmake` for the combined staging sanitizer
posture; the individual ASan, UBSan, and TSan profiles remain available for
diagnosis.

The loader intentionally does not provide a plugin registry, double-load
tracking, live reload, or door/server types. Those policies remain separate
layers in the roadmap.

Post-MVP, in rough order: signed plugin releases via `ssh-keygen -Y`, plugin
reload with reference-counted drain, uploads with age limits and a scanning
hook, ANSI art galleries, the Postgres backend and multi-instance deployment.

## Explicit non-goals

- **No password authentication.** Public keys only, no exceptions.
- **No server-side storage of private chat.** Ever — this is a design
  commitment, not a deferral.
- **No STL across the plugin boundary.** Anvil-defined layouts only. Not
  negotiable; the SDK wrapper makes it invisible to authors anyway.
- **No plugin sandbox, and no plugin vetting by this project.** No registry, no
  review, no signature of approval. Operators make trust decisions about
  authors; the software makes those decisions explicit, visible, and revocable.
- **No public web interface.** The HTTP listener is health and metrics only,
  bound privately.
- **No federation mechanism.** The data model deliberately does not foreclose
  it; no mechanism is built and none should be until multiple independent
  boards exist and their operators ask for it.
- **No telemetry, no analytics, no PII.** Handle, public key, and invite edge
  is the entire user record.

The full list, with reasoning, is in §14 of the design doc.

## Running a public board

Any system hosting user-submitted content will eventually host something
unlawful. Because this ships as OSS, the **operator** bears that exposure and
makes the policy calls. The software provides registration modes, an invite
graph for accountability, versioned TOS gating, a report action on every
user-generated surface, a moderation queue with an append-only audit log,
configurable retention, and a hook interface for external scanning.

It does not decide policy, ship a TOS, bundle a scanner, vet plugins, or assume
a jurisdiction. Get actual legal input before running a public instance.

One thing is worth saying louder than the rest: **every plugin you enable is
code you are trusting completely.** Pin its hash, know whose it is, and treat
the decision the way you would treat granting commit access.

Container egress ships closed and can be opened — metrics scraping, a web UI,
and sidecar upload scanning all work without it, while push-based metrics need
it. Closed egress raises the cost of exfiltration rather than preventing it,
so it is a default worth keeping and not a reason to avoid a deployment shape
you need.

## Built on

- [termforge](https://github.com/gobha-me/termforge) — terminal UI framework, C++23
- [libssh](https://www.libssh.org/) — embedded server API
- SQLite (WAL) by default; Postgres only for multi-instance
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) — private health and metrics listener

## License

BSD 3-Clause. See [LICENSE.md](LICENSE.md). Bundled dependency notices are in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
