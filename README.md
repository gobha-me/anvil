# ANVIL

**A public bulletin board you reach with one command.**

```
ssh anvil.example.org
```

No account setup, no client to install, no toolchain. Boards, files, and door
games served to anyone with a terminal — built entirely on
[termforge](https://github.com/gobha-me/termforge), C++23, in a single hardened
container.

> **Status: design.** Nothing is implemented yet. The design is settled enough
> to build against — see [`anvil-bbs-design.md`](anvil-bbs-design.md) — and the
> issue tracker is the work breakdown.

---

## What it is

A BBS in the original sense: asynchronous, text-first, and inhabited. Message
boards with threads and quote-reply, a one-liner wall, who's-online, a user
list, a file area, ephemeral user-to-user chat, and pluggable door games.

Two things make it worth building:

- **It is the best possible demo of termforge.** A stranger experiences a live
  termforge application in five seconds — no clone, no build, no dependency
  hunt. Screenshots do not prove a render loop; a running system someone can
  touch does.
- **It is a venue, not an app.** Boards and doors land incrementally into a
  place that already has people in it. The board ships first and stays useful
  even if nothing else ever lands.

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

## Roadmap

| Milestone | Gate |
|---|---|
| **M0 — Echo** | Can a stranger ssh in from an untested client and see a working termforge widget that survives a window resize? |
| **M1 — The board** | Is it pleasant to read and post from a plain 80×24 terminal? |
| **M2 — Capability tiering** | Does a modern terminal feel meaningfully better without any regression for an old one? |
| **M3 — Doors** | Door interface, capability gating, replay-verified leaderboards, first door landed. |
| **M4 — Open** | Fuzzing in CI, 50 concurrent sessions under load, operator docs, announcement. |

Post-MVP, in rough order: uploads with age limits and a scanning hook, ANSI art
galleries, the Postgres backend and multi-instance deployment, out-of-process
door isolation and third-party doors.

## Explicit non-goals

- **No password authentication.** Public keys only, no exceptions.
- **No server-side storage of private chat.** Ever — this is a design
  commitment, not a deferral.
- **No public web interface.** The HTTP listener is health and metrics only,
  bound privately.
- **No federation mechanism.** The data model deliberately does not foreclose
  it; no mechanism is built and none should be until multiple independent
  boards exist and their operators ask for it.
- **No telemetry, no analytics, no PII.** Handle, public key, and invite edge
  is the entire user record.

The full list, with reasoning, is in §13 of the design doc.

## Running a public board

Any system hosting user-submitted content will eventually host something
unlawful. Because this ships as OSS, the **operator** bears that exposure and
makes the policy calls. The software provides registration modes, an invite
graph for accountability, versioned TOS gating, a report action on every
user-generated surface, a moderation queue with an append-only audit log,
configurable retention, and a hook interface for external scanning.

It does not decide policy, ship a TOS, bundle a scanner, or assume a
jurisdiction. Get actual legal input before running a public instance.

## Built on

- [termforge](https://github.com/gobha-me/termforge) — terminal UI framework, C++23
- [libssh](https://www.libssh.org/) — embedded server API
- SQLite (WAL) by default; Postgres only for multi-instance
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) — private health and metrics listener

## License

BSD 3-Clause. See [LICENSE.md](LICENSE.md).
