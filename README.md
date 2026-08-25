# ANVIL

**A public bulletin board you reach with one command.**

```
ssh anvil.example.org
```

No account setup, no client to install, no toolchain. Boards, files, and door
games served to anyone with a terminal — built entirely on
[termforge](https://github.com/gobha-me/termforge), C++23, in a single hardened
container.

> **Status: foundations.** The standalone plugin loader is implemented; the BBS
> server remains in design. See [`anvil-bbs-design.md`](anvil-bbs-design.md)
> for the architecture and the issue tracker for the work breakdown.

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

## Plugin loader

`anvil::loader` is an installable C++23 library around the Linux ELF/glibc
dynamic loader. It opens plugins with `RTLD_NOW | RTLD_LOCAL`, resolves an ABI
tag as a data symbol, validates it, and only then resolves the plugin-owned
factory and destroy entrypoints. The returned `Loaded<I>` keeps the shared
object mapped for as long as any instance exists, including when a caller
retains only the instance's `shared_ptr`.

```cpp
struct Tag {
  std::uint32_t magic;
  std::uint32_t interface_version;
};

auto plugin = anvil::loader::load<IPlugin>(
    "/srv/anvil/plugins/example.so",
    anvil::loader::AbiRequirement<Tag>{expected_tag, verify_tag});
if (!plugin) {
  log(plugin.error().message());
}
```

The tag must be a trivially-copyable, standard-layout type. The verifier returns
`std::expected<void, std::string>` so a refusal can name the mismatched field and
its expected and observed values. Symbol names are configurable and default to
`anvil_abi_tag`, `anvil_plugin_create`, and `anvil_plugin_destroy`.

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
