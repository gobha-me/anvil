# ANVIL

**A public bulletin board you reach with one command.**

```
ssh anvil.example.org
```

No account setup, no client to install, no toolchain. Boards, files, and door
games served to anyone with a terminal — built entirely on
[termforge](https://github.com/gobha-me/termforge), C++23, in a single hardened
container.

> **Status: foundations.** The standalone plugin loader and stable plugin SDK
> boundary types are implemented; the BBS server remains in design. See
> [`anvil-bbs-design.md`](anvil-bbs-design.md) for the architecture and the
> issue tracker for the work breakdown.

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
  SSH clients ──▶ libssh server (accept + auth)
                        │
                        ▼
                 Session coroutine ──▶ Shared services ──▶ SQLite
                 (one per connection)   (boards, doors,     (volume)
                                         users)
```

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
the raw plugin manifest and door-context contract.

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
vtable is frozen into plugin interface 1.1.

The boundary headers deliberately contain no standard-library surface types.
Their size, alignment, offset, and fixed-width assertions compile in every host
and plugin translation unit, including a dedicated 32-bit CI check. The later
ergonomic wrapper will convert an author's own standard-library values to these
raw types without letting those values cross the DSO boundary.

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
interface is `1.1`; the accepted range is `1.0` through `1.1`.

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

BSD 3-Clause. See [LICENSE.md](LICENSE.md).
