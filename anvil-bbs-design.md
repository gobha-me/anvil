# ANVIL — SSH Bulletin Board System

**Working title.** Rename freely.

**Status:** draft v2
**Target:** public showcase deployment for termforge
**Transport:** SSH, embedded server, no OpenSSH
**Deployment:** single Docker container
**Language:** C++23, termforge

---

## 0. One-line pitch

A public bulletin board you reach with one command — `ssh anvil.example.org` — serving boards, files, and door games to anyone with a terminal, built entirely on termforge, and extensible by anyone who wants to write a mod.

---

## 1. Why this exists

Three reasons, all worth stating plainly because they should drive priority calls later.

**It is the best possible demo of the library.** A stranger experiences a live termforge application in five seconds with no clone, no toolchain, no dependency hunt. Screenshots do not prove a render loop; a running system someone can touch does. This is worth more to the project than any single application.

**It is a venue, not an app.** Boards and doors are content that can land incrementally into a place that already has people in it. The BBS ships first and stays useful even if nothing else ever lands.

**It is meant to be extended by other people.** The plugin interface is not an internal convenience that happens to be documented — it is the point. The goal is a mod community: doors, board services, and tools written by people who do not have commit access here and never will. A handful of first-party plugins exist to prove the interface works and to seed the menu, not to be the catalogue.

That third reason is new to draft v2 and it changes real decisions downstream. Two in particular: the plugin boundary is now a **published contract** that cannot be casually broken (§7.3), and plugin **authorship** is now security-relevant where it previously was not (§7.9).

### 1.1 Three surfaces

The project delivers three distinct things, and conflating them is the main way the design goes wrong:

| Surface | What it is | Who consumes it |
|---|---|---|
| **Server** (§3–§6, §9) | The board itself — SSH transport, sessions, storage, users, moderation, UX/UI chrome | Operators deploy it; users connect to it |
| **Plugin SDK** (§7) | In-process, dynamically loaded functionality — doors and board services | **Anyone**, first-party or not, in this repository or outside it |
| **Client library** (§8) | A vendorable library for external applications to reach a board | Other projects, including ones this repository does not own |

The server shares an address space with loaded plugins but **not** a toolchain (§7.3). The client library shares neither. All three live in one repository so that the protocol and the interface each have exactly one implementation — with one exception, the plugin loader, which is extracted (§7.2).

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
9. **The plugin interface is a public contract.** Someone else's code depends on it, built with a toolchain this project does not control, on a schedule this project does not set. Breaking it is a release event with a migration note, not a refactor. This constrains the interface *and* what may cross it (§7.3).

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

Docker is then packaging, not a security boundary — with one qualification added in §7.9, where it becomes the *only* boundary around plugin code.

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

**Plugin authors are explicitly outside this threat model.** They are trusted parties, by construction and by operator decision (§7.9). That is a deliberate and consequential position, not an oversight.

### 5.2 Terminal escape injection — read this one twice

User-submitted content is rendered into *other users'* terminals. A post containing raw escape sequences can retitle windows, alter keyboard modes, inject a paste buffer, or trigger a client bug on every reader.

**Requirements:**
- Strip or escape all C0 and C1 control characters from user input **at storage time and again at render time**. Both. Defence in depth, because a future code path will bypass one of them.
- Store message bodies as plain UTF-8. Never store ANSI. Formatting is applied at render time from structured markup, not from stored escape codes.
- Validate UTF-8 on ingest; reject overlongs and surrogates.
- Cap grapheme count and line length on ingest.

This is a classic BBS-era attack and it is fully applicable today.

**Sanitization helpers ship in the plugin SDK.** A door rendering user-supplied text — a high score name, a chat line, anything — faces exactly this attack and must not be expected to reimplement the defence. Making the safe path the easy path is the only version of this that survives contact with a mod ecosystem.

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

These bound *accidents*, not *malice*. A plugin runs in-process and can bypass every one of them by not going through the interface (§7.9). They exist so that a buggy door degrades one session instead of the board — which is the failure that will actually happen.

### 5.6 Container

- Non-root user. Read-only rootfs with tmpfs for scratch.
- All capabilities dropped. Seccomp profile applied.
- Memory, PID, and CPU limits set at the container level as a backstop to §5.5.
- **Network egress closed by default, and openable.** See below.

**Egress is a knob, not a rule** (pillar 7). The shipped default is closed, because a board is a thing that accepts connections and the safe default is what a first-time `docker run` should get. It is not an architectural constraint, and a deployment that opens it is not doing something unsupported.

Most of what looks like it needs egress does not:

| Want | Needs egress? |
|---|---|
| Metrics scraped by Prometheus, Grafana on top | **No** — that is ingress to §9.5 |
| Web UI, health checks, readiness probes | **No** — ingress |
| Upload scanning (§5.8) | **No** — sidecar over a unix socket |
| Push metrics — statsd, OTLP push, Pushgateway | Yes |
| Federation, if it ever exists (§9.4) | Yes |
| A plugin that fetches something | Yes, and see §7.9 |

What opening it costs is stated in §7.9 rather than here, because the cost depends entirely on whose plugins are loaded. Closed egress raises the cost of exfiltration; it was never a wall, since a plugin can encode whatever it likes into a board post and let a reader collect it.

### 5.7 Host keys

Persist host keys on the mounted volume. If they regenerate on redeploy, every returning user gets a man-in-the-middle warning and a meaningful fraction never come back.

Small detail, outsized consequence. Get it right in M0.

In a multi-instance deployment (§9.3) the **same** host keys must be present on every instance, or users who reconnect and land on a different node get a MITM warning.

### 5.8 Operator posture and unlawful content

Any system hosting user-submitted content will eventually host something unlawful. Because this ships as OSS, the operator — not this project — bears that exposure and makes the policy calls. Obligations vary substantially by jurisdiction and by how a deployment is structured, and any operator running a public instance should get actual legal input rather than relying on this document.

**What the software provides:**

- Registration modes and the invite graph (§5.4).
- Versioned TOS gating.
- A report action on **every** user-generated surface: posts, threads, file entries, handles, profile text, and recipient-submitted chat transcripts (§6).
- A moderation queue with per-board moderators, delete, lock, shadow-ban, and an append-only audit log.
- Configurable retention for logs, deleted content, and uploads (§6.1).
- A **hook interface** for hash blocklists or external scanning on upload. The hook is defined; no scanner is implemented or bundled.
- Operator-facing documentation stating plainly what running a public board entails and which knobs exist — **including what installing a third-party plugin means** (§7.9).

**What the software does not do:** decide policy, ship a TOS, bundle a scanner, vet plugins, or assume a jurisdiction.

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
- **Installed plugins.** A user-visible list of loaded plugins with name, version, and author. Not an admin screen — an ordinary one. Users on a board running third-party code are entitled to know whose code it is (§7.9).

### 6.1 Uploads — post-MVP, specified now

Uploads stay out of MVP. The design is recorded here so the file area is not built in a way that forecloses it.

- **Server-configurable age limit.** Uploads expire and are purged automatically. This bounds storage growth and bounds the liability window, which is the more important of the two.
- Configurable per-file and per-user size caps, and a global quota.
- Type allowlist rather than a blocklist.
- Uploads pass through the §5.8 scanning hook before becoming visible.
- Optional moderator approval queue before an upload is listed, operator-configurable.
- Uploader identity recorded and retained for the operator-configured retention window.

ANSI art galleries depend on this and follow it, not the other way round.

**Plugin binaries are never uploads.** They arrive through §7.8 and share no code path with the file area. Nothing a user can put on the board can become something the board loads.

### 6.2 Private chat

User-to-user chat, **unmoderated by design and never persisted server-side.**

- Messages are delivered to the recipient's live session and held in session memory only. On disconnect they are gone. Nothing is written to storage, ever.
- This is period-authentic — BBS node chat was always ephemeral — and it collapses the liability surface to nothing while honouring pillar 8.
- Cross-instance delivery goes over the pub/sub channel in §9.3, keyed by recipient user ID.
- Users may block other users. Blocks are persisted.
- **Reporting is recipient-initiated.** A recipient may submit the transcript they received as a report. Recipient-submitted evidence preserves privacy by default while still giving moderators something to act on. There is no server-side transcript to subpoena, disclose, or leak.
- Rate limited per sender. Offline users cannot be messaged; there is no store-and-forward.

---

## 7. Plugin SDK

### 7.1 The functional shell model

**Anvil core is a shell, not a feature set.** The core owns the SSH transport, sessions, capability negotiation, storage, users, moderation, and the UX/UI chrome. Boards and doors and anything else that constitutes *functionality* arrive as plugins loaded at runtime.

This keeps the core small and auditable — the part handling untrusted network input is the part that changes least — and it means shipping a new door does not mean shipping a new server.

**The interface is generic and no plugin is special-cased, including this project's own.** First-party plugins load through the same manifest, pass the same ABI check, and get the same context object as anyone else's. The moment a first-party plugin needs a private hook, the interface has a hole in it and the fix is to widen the public interface, not to add a back door. This is the single most effective guard against an SDK that is technically public and practically unusable.

A useful test, applied at every interface decision: **could someone build this plugin from outside the tree, against published headers only, with a compiler this project does not choose?** If not, the interface is wrong.

### 7.2 Dynamic loading, and the loader library

There is no native C++ facility for this and there will not be one; C++ has no standard ABI. Note also that C++20 modules are a compile-time facility and are unrelated despite the name.

- **POSIX `dlopen` / `dlsym` / `dlclose`** behind a thin RAII wrapper.
- Boost.DLL is the cross-platform alternative and is rejected — it is a heavier dependency than the ~40 lines it replaces.
- Windows is not a target. If it becomes one, the wrapper is the only thing that changes.

**The loader is extracted as a standalone library and built first, before Anvil consumes it.** This reverses the usual advice about not designing for an imagined user, and the reason is specific: the loader is the component that enforces the ABI check and the ownership guarantee (§7.4), which is to say it is the component that decides whether foreign code corrupts the board. It deserves a test suite that exercises deliberately mismatched plugins, deliberately broken factories, and deliberately hostile symbol tables — and that suite is far easier to write against a library with no BBS attached to it.

Scope of the extracted library: handle lifetime, symbol resolution with correct `dlerror()` handling, ABI tag verification, and the `Loaded<I>` ownership type. **Not** in scope: anything that knows what a door is. It should be usable by any project that wants a C++ plugin interface, and Anvil should be one of its consumers rather than its owner in spirit.

### 7.3 The ABI boundary

This is the section draft v1 got right for the wrong reasons and draft v2 rewrites. The v1 position — STL types may cross freely because plugins are first-party and share a toolchain — is void the moment a mod author uses their own compiler.

**What is stable, and why the C++ interface survives.** On Linux, vtable layout is fixed by the Itanium C++ ABI, which both clang and gcc implement: virtual functions in declaration order, offset-to-top and RTTI slot ahead of them. An abstract base class used *as a handle* is therefore genuinely a C struct of function pointers, and `extern "C" IPlugin* anvil_plugin_create()` returning a derived object is safe across compilers. This is not guaranteed by the C++ standard; it is guaranteed by the platform ABI, which is the thing that actually determines whether the program works.

**What is not stable is what travels through the signatures.** `std::string` has a different layout under libstdc++ than under libc++, and libstdc++ broke against itself at the `_GLIBCXX_USE_CXX11_ABI` transition. Even `std::string_view` — as close to a POD as the standard library gets — orders its two members differently in the two implementations. And member functions are inline: plugin code calling `.size()` on a host-constructed object compiles that accessor from the *plugin's* headers and reads the wrong offsets. It compiles, links, loads, runs, and corrupts memory, which is the worst available failure mode because it presents as an intermittent crash in an unrelated destructor weeks later.

**The rule:**

> The boundary is a C++ abstract base class. Every parameter and return type crossing it must have a layout Anvil defines, not one a standard library defines.

| May cross | May not cross |
|---|---|
| POD structs of fixed-width types, defined in the SDK | `std::string`, `std::string_view`, `std::vector`, any container |
| Enums with an explicit fixed underlying type | `std::shared_ptr`, `std::unique_ptr`, `std::function` |
| `anvil::Str { const char* data; uint64_t len; }` | Anything with an inline member function called across the boundary |
| `anvil::Span<T>` over POD `T`, same shape | References or pointers to STL types |
| Opaque handles — pointer to an incomplete type | `bool` in a packed struct (use `uint8_t`) |
| Pointers to other SDK-defined interfaces | Anything whose size depends on `NDEBUG` or `_GLIBCXX_DEBUG` |

Sizes are fixed-width (`uint32_t`, `int64_t`), structs are `static_assert`ed for size and alignment in both the host build and the SDK, and every struct carries a `uint32_t struct_size` first member so a field added later is detectable rather than misread.

**Mod authors do not write against that table.** The SDK ships a header-only C++ wrapper, compiled inside the author's own translation unit, that converts `std::string` to `anvil::Str` and back, adapts ranges to spans, and lets a door be written in ordinary modern C++. The discipline is real but it lives one layer down, and the ergonomics an author experiences are those of their own standard library, whichever one that is.

**Exceptions never cross.** Every boundary method is `noexcept`. The SDK wrapper generates the try/catch that converts an escaping exception into a status code, so the guarantee is structural rather than a rule authors must remember. An exception unwinding through host frames from foreign code is not recoverable in any useful sense.

**The cost of getting this wrong is not symmetric.** Tightening the boundary later breaks every plugin ever written; loosening it later breaks nothing. Start tight.

#### 7.3.1 The ABI tag

Type discipline removes the layout problem. It does not remove every incompatibility, so the tag stays — as a hard safety check rather than as the mechanism.

Exported as a **data symbol, not a function**:

```cpp
extern "C" const AnvilAbiTag anvil_abi_tag;
```

The distinction matters. The loader `dlsym`s the symbol and reads a POD; a mismatch is rejected with **zero plugin code executed**. A function returning the tag would require calling into the plugin to discover whether calling into the plugin is safe, which is exactly backwards. This is the "fail early, before object creation" instinct taken one step further than the factory.

| Field | Source | Refuse on mismatch? |
|---|---|---|
| `magic`, `struct_size` | Constant | Yes — an unreadable tag is a refusal |
| Plugin interface version | Anvil's own, bumped on any interface change | Yes — per the policy in §7.3.2 |
| Sanitizer state | `__has_feature(address_sanitizer)`, UBSan, TSan | **Yes, always** |
| Compiler identity and version | `__clang_major__` etc., or gcc equivalents | No — recorded and logged, not gated |
| Standard library identity | `_LIBCPP_VERSION` / `__GLIBCXX__` | No — recorded and logged, not gated |
| Language standard | `__cplusplus` | No — recorded |

**Sanitizer state is not optional and is not softened by type discipline.** ASan changes allocator behaviour and inserts redzones; an ASan-built plugin in a non-ASan host fails spectacularly regardless of how clean the interface is. Staging builds run ASan and UBSan continuously (§5.3), so this mismatch *will* occur, and it must be a legible refusal rather than a mystery.

Compiler and stdlib identity move from gate to *telemetry*: recorded at load, shown in the plugin list, included in any crash report. When a plugin misbehaves, the first question is which toolchain built it, and the answer should already be written down.

A macro in the SDK header populates the whole tag. An author writes `ANVIL_PLUGIN_ABI_TAG();` once and never thinks about it.

Mismatch is a hard refusal at load with an error naming the plugin, the field, the expected value and the found value. Never a warning.

#### 7.3.2 Interface versioning

Pillar 9 means the interface version is a promise, not a build number.

- **Additive changes** — a new method appended to an interface, a new field appended to a struct after `struct_size` — bump a minor version. Older plugins keep loading; the host checks `struct_size` before reading a field an older plugin will not have set.
- **Anything else** — reordering, removing, changing a signature, changing a struct's meaning — bumps the major version and refuses every plugin built against the previous one.
- The host accepts a **range** of interface versions, and the range is documented per release. A major bump is a release event with a migration note, an announcement, and ideally a deprecation period during which both versions load.
- Vtable methods are appended, never inserted. Inserting a virtual function in the middle of an interface silently reorders every plugin's vtable, which the tag cannot catch because nothing about the plugin changed.

### 7.4 The handle wrapper

The hard part is not `dlclose`. It is **destruction order**: the handle must outlive every object created from it. Handle and instance held as separate members means declaration order decides who dies first, and getting it backwards yields a vtable pointer into unmapped memory — a crash in a destructor, at shutdown, intermittently.

The wrapper makes this unrepresentable by having the instance's deleter hold a copy of the handle:

```cpp
using Handle = std::shared_ptr<void>;   // deleter calls dlclose

template <typename I>
struct Loaded {
  Handle              handle;
  std::shared_ptr<I>  instance;   // deleter captures a copy of handle
};
```

Ownership then flows correctly by construction and no caller can invert it. Note that `Loaded<I>` lives entirely on the host side — it is the loader library's type, not a boundary type, so its use of `shared_ptr` is fine.

**Destruction dispatches back into the plugin.** The instance's deleter must call a plugin-exported `anvil_plugin_destroy(IPlugin*)`, or invoke a virtual destructor through the vtable — never host-side `delete`. The plugin allocated the object, possibly with a different allocator, certainly with a different stdlib; the plugin frees it. In practice both sides dynamically link the same libc and it would usually work, and "usually works" is the property this whole section exists to eliminate.

Three further requirements:

- **Clear `dlerror()` before `dlsym`.** A null return is not the error signal — a symbol may legitimately have a null value. Clear, call, then check `dlerror()`.
- **Resolve and verify the tag before resolving the factory.** Order is part of the guarantee.
- Every failure path returns a diagnostic naming the plugin, the symbol, and the `dlerror()` text. Silent load failures are worse than crashes.

**A key function is defined in the host for every abstract interface.** Without it, typeinfo gets vague-linkage-emitted on both sides and `dynamic_cast` across the boundary fails silently under `RTLD_LOCAL`. Type discipline does not remove this: the host still downcasts a generic `IPlugin*` to the kind-specific interface named in the manifest, and that downcast must work. Similarly, unwind tables must not be stripped — exceptions do not cross the boundary (§7.3), but they still unwind *within* the plugin, and a plugin whose internal `try`/`catch` does not work is a plugin that calls `std::terminate` on its first recoverable error.

`-fvisibility=hidden` with explicit exports, so plugin internals cannot collide. `extern "C"` on the factory, the destroy function, and the tag — C++ name mangling is not stable.

### 7.5 Plugin contract

Illustrative, in SDK types. The ergonomic wrapper an author actually writes against is a layer above this.

```cpp
struct PluginManifest {          // POD, returned by value into host storage
  uint32_t       struct_size;
  PluginId       id;
  Str            name;
  Str            description;
  Str            author;
  Version        version;        // {uint16_t major, minor, patch}
  PluginKind     kind;           // enum : uint32_t — Door | BoardService | Verifier
};

struct DoorManifest {
  uint32_t       struct_size;
  CapabilityTier min_tier;       // enum : uint32_t — refuse below this
  uint8_t        persists_state; // needs door_state storage
  uint8_t        has_leaderboard;
  uint8_t        audio_enhanced; // uses audio if available; never required
};

struct DoorContext {
  uint32_t       struct_size;
  UserId         user;
  ISession*      session;        // render target + input stream
  Capabilities   caps;
  IStateStore*   state;          // scoped to (plugin, user)
  ResourceLimits limits;
};
```

A door is entered, runs its own loop against the session, and returns an exit status. The board reclaims the screen on return regardless of how the door exits.

The context object is the plugin's **entire** view of the board. Everything a plugin can legitimately do arrives through it — no globals, no singletons, no host symbols a plugin is expected to link against. That is what §7.1's "no special cases" reduces to in practice. Note "legitimately": this is an interface-cleanliness property, not a containment one (§7.9).

`IStateStore` is scoped to `(plugin, user)` and is the only persistence a plugin gets. A plugin does not see the board database, does not compose SQL, and does not learn the schema. This is an interface-cleanliness decision rather than a security control — a plugin could reach the real database through the process it shares — but it is what keeps a mod from depending on internals that will change.

### 7.6 Capability gating, and the audio constraint

A door declares `min_tier`. Below it, the menu shows the door as unavailable with a short note naming which terminals qualify. **Decline politely; never render a broken experience.**

**Doors cannot produce audio, ever.** A door runs in the server process, so any sound it plays emerges from the server's audio device, not the user's. There is no in-band audio channel in SSH or in the terminal protocol; the bell is one bit and that is the whole budget.

This is a hard architectural constraint, not a gap to be closed later:

- A door may be `audio_enhanced` — it uses audio when running locally and is complete without it.
- **A door may never be audio-dependent.** An application whose design requires sound is an external title (§8), not a door.

State this prominently in the SDK documentation. It is the single most likely thing for a new mod author to attempt and be disappointed by, and finding out at the end of a project is much worse than finding out on the first page.

### 7.7 Lifecycle

**Load only. No runtime unload.**

`dlclose` is a minefield: any object, vtable pointer, cached function pointer, typeinfo reference, or unwind table outliving the unload dangles. A session coroutine inside a door during unload is an immediate crash. Thread-local storage in a plugin makes it substantially worse. glibc sometimes declines to unload at all, so the failure does not reproduce reliably.

Current policy:

- Plugins load at startup, or on explicit admin action (§7.8).
- **`dlclose` runs only at application stop.**
- **Loading an already-loaded plugin is an error.** Not a reload, not a no-op.
- No live unload from the UI.

**Reload and unload are planned but not built, and third-party plugins raise the priority considerably.** First-party plugins ship on the server's release cadence, so a restart-to-update is barely a constraint. Mod authors ship on their own cadence, and "the board must bounce every time any mod publishes a patch" is a genuinely bad property for a board with people on it. Reload is now the most likely post-MVP plugin feature rather than a someday item.

To keep that path open, one constraint must hold from the first commit:

> **No host object may hold a raw pointer into plugin code or data beyond a single door session.** No cached function pointers in a registry, no plugin-owned statics read directly by the host, nothing plugin-allocated stored in shared services.

If that holds, adding reference-counted drain later is mechanical: load v2 alongside v1, route new sessions to v2, let v1's refcount fall to zero. If it does not hold, reload is permanently off the table and it will not be discovered until it is attempted.

When reload does land, the default should be **never `dlclose` in production** — leak the stale handle, reclaim on restart. A few MB per stale version costs nothing and deletes an entire category of crash that only reproduces under load. Real unloading is a development affordance.

### 7.8 Loading policy and provenance

**Never scan a directory and load what is found.** Plugin loading is explicit, always.

Two layers, two owners, two homes:

| Layer | Contains | Owner | Mutability |
|---|---|---|---|
| **Manifest** | What *may* be loaded: plugin identity, path, content hash | Deployment | Immutable at runtime |
| **Database** | What *is* enabled right now | Admin | Mutable, survives restart |

Enabling a plugin absent from the manifest is an error. **Content hash is verified at every load.**

**What the hash does and does not do.** Draft v1 claimed hash verification "makes plugin provenance irrelevant to security." With third-party plugins that is precisely backwards and the correction matters. The hash guarantees the bytes loaded are the bytes the operator vetted — it defends against a compromised mirror, a tampered volume, a MITM'd download, a silently-updated image layer. It says nothing whatsoever about whether those bytes are trustworthy. **Provenance is now the primary security question and the hash is what pins an answer to it in place** (§7.9).

Practical consequence: the manifest entry should record the plugin's author and release identity alongside the hash, and the admin UI should show them. An operator pasting a hash from a release page needs to be reminded whose release page.

**Deployment topology is the operator's choice and Anvil holds no opinion.** Baked into the image, mounted from a volume, ConfigMap for the manifest with a PVC for binaries — all equivalent to the server, because the hash check does not care where the bytes came from *once the operator has decided they trust them*. Requirements this imposes:

- Plugin paths come from configuration, never baked at build time.
- **The manifest must be treated as read-only.** A ConfigMap mount is read-only, so admin toggles cannot persist to it — this is why enabled-state lives in the database.
- Manifest and binaries need not share a location.
- **Watch the manifest's directory, not the file.** ConfigMap updates propagate via a symlink swap through a `..data` directory, so `inotify` on the file path never fires. This is a common way to ship a reload feature that silently never reloads.

**Where new binaries may be introduced:**

- **Network admin UI: enable and disable only.** It never accepts a path. Toggling an already-vetted plugin is not remote code execution.
- **New binaries: console only** — a Unix domain socket reachable via container attach — or a restart with an updated manifest.

The reasoning on the console channel is worth stating explicitly: anyone who can attach to the container could already replace the server binary outright. **The channel requires a privilege that already implies total compromise**, so guarding it further is theatre. That is what makes it the right place for the capability.

All loads are audit-logged as first-class moderation events (§5.8), recording plugin identity, version, hash, author, and the toolchain fields from the tag.

### 7.9 Privilege and the trust model

**A loaded plugin runs in-process with full privilege.** It can read database credentials, SSH host private keys, and every active session's memory. It can bypass the resource limits in §5.5 by not going through the interface. It can call `exec`. Container hardening (§5.6) still holds — that is the outer wall — and there is no inner one.

**This is the model, not a stage on the way to something else.** `dlopen`, in-process, full privilege, with third-party plugins in scope. It is what every native plugin ecosystem does — Postgres extensions, nginx modules, Vim, OBS, VST — and those ecosystems work because the trust question has an answer, not because the risk was engineered away.

The answer is that **trust here is transitive and already spent.** Anyone running Anvil has decided to trust this project's author with their box: with the SSH host keys, the user database, and a listening socket. A plugin author is the same category of decision about a different person. An operator's real choice has always been *build it yourself or trust someone*, and adding a plugin does not introduce that choice, it repeats it. Pretending otherwise — shipping a sandbox that implies containment it cannot deliver against a determined author in the same address space — would be worse than saying it plainly.

**Note what the interface does not do.** A plugin does not have to call `ISession` or `IStateStore` at all. It can `dlsym(RTLD_DEFAULT, …)`, walk its own `link_map`, read `/proc/self/maps`, or use `std::filesystem` to walk the disk. Nothing in §7.5 is a fence; it is a front door in a building with no walls. Memory state cannot be protected either, and it is worth knowing why so nobody spends a week trying: `mprotect` is available to the plugin too, a dedicated arena does not stop reads outside it, and hiding a pointer does not survive a symbol lookup or a scan. The mitigations that work — a different address space, a different execution model — are the ones this design has chosen not to take.

**So the narrow interface is justified on other grounds, and they are good ones:** a buggy mod is the realistic failure and a narrow interface makes it survivable; §7.7's reload constraint and §9.2's no-plugin-tables rule both depend on plugins not reaching into internals; and an author writing against a small, documented surface writes a mod that still works three releases later. **One SDK, narrow for ergonomics and maintainability — never described as a security boundary.** A second "restricted" SDK would carry identical privilege while implying otherwise, which is the one thing worse than the honest single tier.

**The rule follows directly, and belongs in the operator documentation in these words:**

> Installing a plugin is equivalent to running a patched server binary from that author. There is no lesser degree of trust available. Install code from people you would let commit to your board.

What the software provides in place of isolation:

| Control | What it actually buys |
|---|---|
| Manifest + content hash (§7.8) | The bytes are the ones you vetted. Not that they are safe. |
| Author and release identity in the manifest and admin UI | The trust decision is made against a name, visibly |
| Audit log of every load | After the fact, you know what ran and when |
| Egress default-closed (§5.6) | Raises the cost of exfiltration. Not a wall — a plugin can encode anything into a board post. Opening it is a supported choice that this table gets smaller because of. |
| User-visible plugin list (§6) | Users can see whose code is running on the board they post to |
| Doors run in a coroutine with exception isolation | A *buggy* door — the realistic failure — takes down one session |

That last row is worth separating from the rest, because it is the one that earns its keep daily. A door throwing or exceeding limits terminates that door session and returns the user to the menu with an apology. **The board does not go down — this is a tested requirement**, and the test suite includes a deliberately misbehaving plugin.

**Author identity should be cryptographic, not just a string.** This is where the remaining effort belongs, because if the trust decision is the whole security model then the decision should at least be made against something forgery-resistant. Anvil is already an SSH-key project; `ssh-keygen -Y sign` and `-Y verify` with an allowed-signers file is a natural fit and requires no new key infrastructure or dependency. An operator then trusts a *key*, and a compromised release page cannot mint a release the author's key did not sign — which closes the one gap in §7.8 that the content hash leaves open. Strong candidate for the first post-MVP plugin feature; see §15b.

### 7.10 First, second, and third party

Three kinds of author, one interface, no privilege distinction between them.

| | Where it lives | Ships with the server | Purpose |
|---|---|---|---|
| **First-party** | This repository | Yes — a small, deliberate set | Prove the interface, seed the menu, exercise the SDK in CI |
| **Second-party** | A separate repository, same author | No | Dogfood the SDK from outside the tree |
| **Third-party** | Anywhere | No | The point of the exercise |

**First-party plugins are a demonstration set, not a catalogue.** Enough to make a new board non-empty and to keep the interface honest in CI — one door that needs tier 1 and one that needs tier 3, one board service, one verifier. Every additional first-party plugin is a plugin a community member did not write and a piece of surface this project maintains forever. When in doubt, do not ship it first-party.

**The second-party repository is the SDK's real test.** It builds against published headers only, with no access to Anvil internals, on its own CI, ideally with a different compiler than the server's. If a plugin cannot be built there, it cannot be built by a stranger either — the difference is that a stranger will not file a bug, they will just leave. This makes it a gate rather than a nicety: **a green build in the second-party repository, against a released SDK, is part of the M3 exit criteria.**

It does not need to exist before the SDK does. Create it when there is a second plugin to put in it, and no later.

---

## 8. Client library — external applications

### 8.1 Purpose

**The Anvil client ships inside the Anvil server repository.** Other projects vendor it and get integration without implementing a protocol, and the protocol has exactly one implementation on each side.

An external application — typically a game running locally on the user's machine — uses the client to reach an Anvil board for global record keeping. **Anvil is optional for those applications.** They run standalone with no board configured; a board adds leaderboards and identity, nothing more.

Unlike the plugin SDK, the client library shares no address space with the server, so §7.3's type discipline does not apply to it. It is an ordinary C++ library and can use whatever it likes at its own API.

### 8.2 Why external titles exist

Running an application as a door puts it in the server process. Running it as a client puts it on the user's machine. The second removes a set of constraints that the first cannot:

| | Door (in-board) | External title (client) |
|---|---|---|
| Audio | **Impossible** (§7.6) | Local device, full audio |
| Graphics | Negotiated tier, tmux passthrough problems | The user's real terminal |
| Resource caps | Per-session limits required | The user's machine |
| Trust required | Operator trusts the author with the box (§7.9) | None — separate machine |
| Discovery | Visitors find it by browsing | Requires install |

The trade is discovery against fidelity, and it splits cleanly by application: simple, turn-based, async, shared-venue things are doors; anything wanting audio, high graphics fidelity, or a real per-frame budget is an external title.

The trust row also gives an author a genuine choice rather than a consolation prize. Someone writing a game who does not want to ask operators to trust them with their host keys can ship an external title and reach the same leaderboards.

**A deterministic, visual-only application can be both** — same codebase, same replay format, door for discovery and local binary for fidelity.

This also inverts the dependency in a healthier direction for an OSS project: applications that *can* submit to a board, rather than applications that only exist inside one. Either piece stands alone.

### 8.3 Interface

The client is a small libssh-based library:

- **Authenticate** using the user's existing SSH key — the same key that authenticates their board session. No second identity system.
- **Submit a replay** for a completed run.
- **Fetch leaderboards** for a given application and period.
- **Fetch board metadata** — name, announcements, whether the application is registered there.
- Configuration is one host string plus a key path. Absent configuration means offline, which is not an error state.

Failure is always non-fatal. A board being unreachable must never prevent the application from running or from completing a session.

### 8.4 Score submission and verification

**One submission protocol, one implementation**, used identically by in-board doors and external clients. If this grows two code paths, something has gone wrong.

An application with deterministic simulation and recorded input submits `seed` + ordered input log. **The server re-simulates to verify the claimed result** before it enters the leaderboard.

This makes scores unfakeable with no anti-cheat machinery, and it holds regardless of how untrusted the client is — which is what makes external titles safe to accept submissions from at all. Applications that cannot provide a verifiable replay get an unranked scoreboard, clearly labelled as such.

Verification requires the server to hold a simulation implementation for that application. For doors this is the plugin itself. **For external titles the server needs a verifier** — and `PluginKind::Verifier` is what that is: a headless build of the same simulation, shipped as a plugin, loaded through §7.8 like anything else. An external title's author can therefore supply their own verifier rather than asking this project to maintain one, which is what makes the model scale past the titles written here.

The trust consequence is worth naming: **a verifier is a plugin, so installing one carries §7.9's full privilege.** An operator who wants a third-party title's leaderboard on their board is making the same trust decision as installing a door. The alternative for an operator who does not want to make it is the unranked scoreboard. Accepting an unverified score into a ranked table is not an option — it defeats the entire design.

---

## 9. Persistence

### 9.1 Storage abstraction

Define a narrow `Store` interface from the first commit, with two implementations planned:

| Backend | Use |
|---|---|
| **SQLite** (WAL mode, on the volume) | Default. Single instance. Zero configuration. |
| **Postgres** | Multi-instance deployments only. |

SQLite is the default because zero-config matters enormously for OSS adoption — someone should be able to `docker run` and have a board. Postgres is opt-in and only needed when a second instance is.

**Build the interface in MVP. Do not build the Postgres implementation in MVP.** The point is not foreclosing it.

### 9.2 Schema

Tables: `users`, `user_keys`, `invites`, `tos_acceptances`, `boards`, `threads`, `messages`, `files`, `plugins`, `plugin_state`, `leaderboards`, `oneliners`, `blocks`, `reports`, `moderation_log`, `sessions_log`, `presence`.

- All timestamps UTC, integer epoch.
- Message bodies plain UTF-8, sanitized (§5.2). ANSI is never stored.
- Private chat has **no table** (§6.2). This is deliberate.
- `plugins` holds enabled-state, last-loaded hash, author, version, and observed toolchain (§7.8). `plugin_state` is the backing store for `IStateStore`, keyed `(plugin_id, user_id)` — note the key is the *plugin*, not the door, since board services persist too.
- Periodic backup — SQLite backup API, or standard tooling on Postgres. Retain a rolling window.
- Schema migrations versioned and applied at startup, forward-only.

**Plugins do not own tables.** A plugin that needs richer storage than `IStateStore` provides is a signal to widen `IStateStore`, not to let foreign code migrate the board's schema. A mod ecosystem in which every mod adds tables produces a database no operator can back up, restore, or reason about.

### 9.3 Multi-instance scaling

Not built in MVP, but the shape is decided so nothing blocks it.

**Pattern: stateless instances, Postgres for durable state, `LISTEN`/`NOTIFY` for ephemeral fanout.** No Redis, no message broker, no service discovery.

SSH gives this an advantage most systems have to engineer around: **a TCP connection is inherently sticky.** A session lands on an instance and stays there for its lifetime. No affinity logic, no token handoff, no sticky-session balancer configuration. Any L4 balancer or plain DNS round-robin is sufficient.

Only two things cross instance boundaries:

- **Durable state** — Postgres, read and written normally.
- **Ephemeral fanout** — presence changes, one-liners, and private chat delivery via `LISTEN`/`NOTIFY`. Fire-and-forget delivery and the 8KB payload cap are acceptable precisely because this data is ephemeral by definition. Chat routes on a channel keyed by recipient user ID; whichever instance holds that session picks it up.

Four details that bite if missed:

1. **Host keys must be identical across all instances** (§5.7). Different keys mean MITM warnings on reconnect to a different node.
2. **Presence needs heartbeat plus TTL**, not connect/disconnect rows. An instance that dies ungracefully otherwise leaves its users listed online forever.
3. **Per-IP rate limits become approximate.** Either move counters into Postgres or accept per-instance enforcement. Accept the approximation initially and document it.
4. **Every instance must load an identical plugin set.** Enabled-state is shared through the database, but the binaries and the manifest are per-instance, so a partial rollout means a user's door disappears when they reconnect and land elsewhere. Verify the loaded set matches across instances at startup and refuse to serve, or at minimum surface it loudly in readiness (§9.5).

### 9.4 Federation-compatible data model

Federation is not built (§14). But the *data model* forecloses it if handled carelessly, and data model decisions are one-way doors while protocol decisions are two-way doors. Spend on the former only.

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

### 9.5 Health and metrics endpoint

A small HTTP listener via **cpp-httplib** (header-only, no build system impact):

- Liveness: is the process up and accepting.
- Readiness: is storage reachable, is the SSH listener bound, **did every enabled plugin load**.
- Metrics: active sessions, registered users, memory in use, bytes out per session, door usage counts, uptime, and per-plugin load status and version.

**Bind localhost-only or on a separate port behind auth. Never expose it publicly alongside the SSH listener.**

A plugin that fails its ABI check is a legitimate readiness failure — it is a board missing functionality its operator asked for, and it should page rather than hide in a log. This is the same dependency a web UI would eventually use (§14), which is part of why it is the right choice now.

---

## 10. Rendering over a network link

Damage tracking stops being a nicety here. Over a link with real latency it is the difference between responsive and sludgy.

- **Instrument bytes-per-frame per session from the first commit.** It is a budget, not a metric to look at later.
- **Coalesce a frame's writes into a single socket write.** Many small writes interact badly with Nagle and with SSH packet framing.
- **Use synchronized output (DECSET 2026)** where available. Partial-write tearing is far more visible over a network than locally.
- **Do not run a fixed 60fps loop.** Render on state change. Where continuous animation is needed, pace it adaptively against measured RTT.
- Target under 100ms perceived latency for input echo.

**Plugins inherit all of this through `ISession` rather than reimplementing it.** A door author writing to the session gets coalescing, damage tracking, and pacing for free, and cannot easily opt out. A mod ecosystem where each author independently discovers Nagle is a mod ecosystem of sludgy doors.

There is a publishable benchmark here: full redraw versus damage-tracked bytes per session, plotted against RTT. That graph sells the library better than a feature list.

---

## 11. termforge feature requests

**Request 1 is the headline** — it is what turns termforge from a TUI library into one that can serve remote sessions, and it is the single largest thing this project gives back.

1. **Session abstraction.** Decouple an application from a process-owned tty. Render to an arbitrary byte sink, with capabilities, dimensions, and input stream owned per session rather than per process. Everything else here depends on it.
2. **Runtime capability negotiation** with hard timeouts, cached results, and manual override.
3. **Multiplexer detection** (tmux, screen) with automatic tier downgrade.
4. **Per-session resource accounting** — bytes out, image memory, allocation.
5. **Output coalescing** — batch a frame into one write.
6. **Control-character sanitization helpers** for rendering untrusted text.
7. **Adaptive frame pacing** keyed to measured round-trip time.

File these before writing application code around workarounds.

**A note on §7.3 and termforge.** Anvil's plugin boundary cannot expose termforge types directly — they are ordinary C++ types with ordinary ABI fragility. `ISession` is an Anvil-defined interface that wraps termforge on the host side. This is not a termforge deficiency and no request above should try to fix it; it is simply where the boundary falls. It does mean a door author writes against Anvil's interface rather than termforge's API, and the SDK's ergonomic wrapper is what makes that pleasant.

---

## 12. Milestones

### M0 — Echo
Embedded libssh. Session coroutine. `pty-req` and `window-change` handled. Renders one termforge widget and echoes input. Host keys persisted. Deployed in Docker: non-root, read-only rootfs, caps dropped, egress closed by default.

**Gate:** can a stranger ssh in from an untested client and see a working termforge widget that survives a window resize?

### M1 — The board
Guest browsing and key registration with all three registration modes. Invite graph. Versioned TOS gating. Boards, threads, posting, one-liners, who's online, user list. Moderation tooling with reporting on every surface. Full input sanitization. Storage interface with the SQLite implementation. **Tier 0/1 rendering only.**

**Gate:** is it pleasant to read and post from a plain 80×24 terminal? If it is not good here, no amount of tier 3 will save it.

### M2 — Capability tiering
Probe with timeouts, caching, manual override. Tier 2 and 3 rendering. Multiplexer detection and downgrade messaging. Ephemeral private chat with blocks and recipient-initiated reporting.

**Gate:** does a modern terminal feel meaningfully better without any regression for an old one?

### M3 — The plugin platform

Prerequisite, standalone and startable at any time: **the loader library** (§7.2) — RAII handle wrapper, ABI tag verification, `Loaded<I>` ownership, with a test suite covering mismatched tags, broken factories, missing symbols, and destruction ordering.

Then, in Anvil: the SDK — stable-type boundary, header-only ergonomic wrapper, sanitization helpers, tag macro, versioning policy. Manifest allowlist with hash verification, DB-backed enable/disable, admin toggle UI, console channel for new binaries. Door interface, registry, launch and return, capability gating, state persistence. User-visible plugin list. First-party demonstration set landed as plugins. SDK documentation and a worked example door.

**Gates, all three:**
1. Does a plugin failing — throwing, exceeding limits, failing its ABI check — leave the board fully healthy?
2. **Does a plugin built outside the tree, against published headers, with a different compiler than the server's, load and run?** This is the milestone. Everything else in M3 is scaffolding for it.
3. Is the SDK documentation sufficient for someone who has never seen the codebase to write a door?

### M4 — Client and leaderboards
Client library, vendorable, with key auth, replay submission, and leaderboard fetch. Server-side re-simulation and verification. `PluginKind::Verifier`. One submission path shared by doors and external titles. First external title submitting.

### M5 — Open
Fuzzing in CI. Load test at 50 concurrent sessions. Rate limits tuned under load. Operator documentation written, including the plugin trust statement (§7.9). SDK published with a versioning commitment. Public announcement.

### Post-MVP, in rough order
Signed plugin releases via `ssh-keygen -Y` (§7.9). Plugin reload with reference-counted drain (§7.7) — promoted from someday, since mod authors ship on their own cadence. Uploads with age limits and the scanning hook (§6.1). ANSI art galleries. Postgres backend and multi-instance deployment (§9.3). A web UI on the existing cpp-httplib dependency — if ever.

---

## 13. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| termforge assumes a process-owned tty | **High** | Request 1 in §11. Likely the largest single engineering cost in the project — scope it before committing to a date. |
| Escape injection via user content | **High** | §5.2, sanitize at both ends, fuzz the path, ship the helpers in the SDK |
| Untrusted input parsed in C++ | **High** | §5.3, fuzzing as a CI gate |
| **A third-party plugin is malicious or its author is compromised** | **High** | **Accepted, not eliminated, and not mitigable in-process** (§7.9). Operator trust decision made against a named author, hash-pinned, audit-logged, egress closed by default. Signed releases (§15b.7) are the one control that materially improves this and should not slip far. |
| An STL type reaches the plugin boundary in a later change | **High** | §7.3 is a review checklist item; `static_assert` on every boundary struct; a CI plugin built with the *other* standard library, which fails immediately if discipline slips |
| Plugin ABI mismatch corrupts memory silently | **High** | Stable-type boundary (§7.3), tag as a data symbol checked before any plugin code runs, sanitizer state always gated |
| Interface breakage strands the mod ecosystem | Medium | §7.3.2 versioning policy, additive-only by default, documented range per release, deprecation period on majors |
| Host object outlives a plugin, foreclosing reload | Medium | §7.7 constraint enforced from the first commit; reload is unrecoverable if missed and now matters more |
| Nobody writes a mod | Medium | Expected for a while. The SDK is cheap to maintain once built; the second-party repo (§7.10) keeps it exercised even with zero third parties. |
| Capability probe hangs or misdetects | Medium | Hard timeouts, manual override always available |
| No verifier exists for an external title | Medium | Unranked scoreboard rather than an unverified ranked one (§8.4) |
| Door takes down the board | Medium | §7.9 coroutine isolation, tested explicitly with a deliberately misbehaving plugin |
| Host keys regenerate on deploy | Medium | Volume-persisted, verified in M0 |
| Small audience | Low | Expected. Dozens of regulars is the realistic and acceptable outcome. |

---

## 14. Non-goals

- **No password authentication.** Keys only, no exceptions.
- **No STL or other toolchain-dependent types across the plugin boundary.** Anvil-defined layouts only (§7.3). The SDK wrapper makes this invisible to authors; it is not negotiable at the boundary itself.
- **No plugin sandbox.** `dlopen`, in-process, full privilege. This is the model, not a stage (§7.9) — no out-of-process host, no IPC boundary, no restricted second SDK. Trust is transitive and already spent on whoever built the server; a plugin author is the same decision about a different person.
- **No second, "restricted" SDK.** One interface. A narrower SDK would carry identical privilege while implying containment, which is worse than the honest single tier (§7.9).
- **No plugin vetting by this project.** No registry, no review, no signature of approval. Operators make trust decisions about authors; the software makes those decisions explicit, visible, and revocable.
- **No plugin-owned database tables** (§9.2). `IStateStore` or widen `IStateStore`.
- **No file uploads in MVP.** Downloads only. Design recorded in §6.1 so nothing forecloses it.
- **No plugin binaries through any user-facing path.** Uploads are never loadable; loading is §7.8 only.
- **No public web interface.** The cpp-httplib listener is health and metrics only, bound privately (§9.5). A web UI is a distant post-MVP maybe, not a plan.
- **No runtime plugin unload.** `dlclose` at application stop only. Reload is planned, not built (§7.7).
- **No directory scanning for plugins.** Explicit manifest, always.
- **No opinion on deployment topology.** Image, volume mount, or ConfigMap are equivalent to the server; the hash check makes the location irrelevant once the operator has decided to trust the bytes (§7.8).
- **No audio in doors.** Architecturally impossible over SSH (§7.6). Audio-dependent applications are external titles, not doors.
- **No second identity system.** The client library authenticates with the user's existing board key (§8.3).
- **No unverified scores in a ranked leaderboard.** Unranked and labelled, or verified by re-simulation (§8.4).
- **No federation mechanism.** No peering protocol, key exchange, nodelist, or conflict resolution. Multi-instance (§9.3) is horizontal scaling of *one* board, which is a different thing. The data model deliberately does not foreclose federation (§9.4), but no mechanism is built and none should be until multiple independent boards exist and their operators ask for it.
- **No append-only or immutable content logs.** Content must remain deletable. This rules out p2p designs built on append-only signed logs or content-addressed permanence, however elegant — an undeletable store is incompatible with retention limits and takedown obligations.
- **No server-side storage of private chat.** Ever. This is a design commitment, not a deferral.
- **No store-and-forward messaging.** Offline users cannot be messaged.
- **No bundled scanner, TOS, or moderation policy.** Hooks and knobs only (§5.8).
- **No voice, no synchronous group chat.**
- **No mouse-required interaction.**
- **No telemetry, no analytics, no PII collection.** Handle, public key, and invite edge is the entire user record.

---

## 15. Decisions taken

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
| Health endpoint | Yes — liveness, readiness, and metrics over cpp-httplib, bound privately. Plugin load failure is a readiness failure. |
| Storage | SQLite default, interface abstracted, Postgres for multi-instance only. |
| Multi-instance pattern | Stateless instances, Postgres, `LISTEN`/`NOTIFY`. Not built in MVP. |
| Federation | Not built. Data model keeps the option open (§9.4). If it ever happens: allowlist peering, board-level attestation, SSH transport, mutable state — never p2p append-only logs. |
| Web UI | cpp-httplib if it ever happens. Well past MVP. |
| **Who writes plugins** | **Anyone. A mod community is the goal; first-party plugins are a small demonstration set, not a catalogue (§7.10).** |
| Plugin loading | `dlopen` behind an RAII wrapper. No Boost.DLL. |
| **Loader library** | **Extracted as a standalone, heavily tested project and built before Anvil consumes it (§7.2).** |
| **Plugin ABI** | **C++ abstract base class as the handle — vtable layout is fixed by the Itanium ABI. Only Anvil-defined stable types cross it: PODs, fixed-width enums, `Str`, `Span`, opaque handles. No STL, ever. A header-only SDK wrapper restores ordinary C++ ergonomics on the author's side (§7.3).** |
| **ABI tag** | **Exported as a data symbol, not a function, and verified before the factory is resolved — a mismatch is refused with zero plugin code executed. Gates on interface version and sanitizer state; records compiler and stdlib identity as diagnostics rather than gating on them (§7.3.1).** |
| **Interface versioning** | **Additive changes bump minor and keep old plugins loading; anything else bumps major and is a release event with a migration note. Vtable methods are appended, never inserted (§7.3.2).** |
| **Plugin privilege** | **`dlopen`, in-process, full privilege, no sandbox — the model, not a stage. Trust is transitive: an operator already trusts whoever built the server, and a plugin author is the same decision about a different person. Stated plainly in operator docs: installing a plugin equals running a patched server binary from that author (§7.9).** |
| **Number of SDKs** | **One. The narrow interface is justified by ergonomics, maintainability, and surviving buggy mods — never described as a security boundary, because in-process it is not one (§7.9).** |
| **Egress** | **Operator knob, default closed, openable and supported (§5.6). Metrics, web UI, and upload scanning do not need it; push metrics and any future federation do. Was wrongly written as an architectural rule in the first v2 pass — pillar 7 applies to this project's own rules.** |
| **What the hash buys** | **That the bytes are the ones the operator vetted — not that they are safe. Provenance is now the primary security question, reversing draft v1 (§7.8).** |
| Plugin unload | None at runtime. `dlclose` at application stop. Double-load is an error. Reload planned and now higher priority; constraint honoured now. |
| Plugin provenance | Manifest allowlist with content hashes and author identity (deployment-owned), enabled-state in the database (admin-owned). Never directory scanning. |
| New plugin binaries | Console/attach channel or restart. Network admin UI toggles only, never accepts a path. |
| Plugin storage | `IStateStore` keyed `(plugin, user)`. Plugins never own tables or see the schema. |
| Audio in doors | Impossible. Doors may be audio-enhanced, never audio-dependent. |
| Client library | Ships in the server repository, vendorable by other projects. Anvil is optional to them. Not subject to §7.3 — it shares no address space. |
| Submission protocol | One implementation, shared by doors and external titles. |
| External title verifiers | `PluginKind::Verifier` — the title's author ships one as a plugin, or the scoreboard is unranked. Installing one is a §7.9 trust decision. |

## 15b. Still open

1. Invite economics: how many invites per user, on what regeneration schedule, and does an inviter get notified of moderation actions against their invitees? Defaults need picking even though they are configurable.
2. Does shadow-ban belong in the moderation set, or does it create more confusion than it prevents at small scale?
3. Board-level read permissions — are all boards visible to guests, or can an operator mark some registered-only?
4. Retention defaults for `sessions_log` and `moderation_log`. Long enough to investigate, short enough not to be a liability.
5. Whether presence should show *what screen* a user is on, or only that they are online. The former is more alive, the latter is less surveillant.
6. Are board services (`PluginKind::BoardService`) actually needed in MVP, or does only `Door` ship in M3? The SDK should define the kind either way; the question is whether any host-side wiring exists for it at first release.
7. **Signed plugin releases** (§7.9) — `ssh-keygen -Y sign` with an allowed-signers file is cheap and fits the project's existing key model. Post-MVP or M3? It is the difference between an operator trusting a *download* and trusting an *author*, and retrofitting it means every existing manifest entry lacks a signature.
8. **What exactly does the SDK version-lock to?** The server release, the interface major, or its own semver? Affects whether a mod author says "works with Anvil 1.x" or "works with plugin interface 3.x". The second is more honest and more work.
9. Which plugins make up the first-party demonstration set (§7.10)? The constraint is coverage of the interface — one tier-1 door, one tier-3 door, one verifier, possibly one board service — not entertainment value.
10. Does the second-party repository build with a *different* compiler than the server's in CI, or the same one? Different is a much stronger test of §7.3 and costs one more CI job.
11. Should a plugin be able to declare a dependency on another plugin? Almost certainly not in v1 — load-ordering and version-resolution are how plugin systems become package managers — but mod ecosystems generate the request early and it is worth having the answer ready.
12. Is there a story for a plugin that wants to add a *board*, as opposed to a door? It is the most obvious `BoardService` and it collides with §9.2's no-plugin-tables rule.

---

## 16. Immediate next actions

1. File the seven termforge issues (§11), and scope request 1 first — the milestone plan depends on how large it turns out to be.
2. Stand up M0 end to end, including the Docker hardening, before writing any board features. Deployment posture is much harder to retrofit than to start with.
3. Persist host keys and verify across a redeploy on day one.
4. Define the `Store` interface before writing the first query. Retrofitting an abstraction over scattered SQLite calls is the kind of work nobody wants to do later.
5. Instrument bytes-per-frame and cold-start time from the first commit.
6. Write the sanitization layer and its fuzz harness before the first user-submitted text is stored anywhere.
7. **Start the loader library** (§7.2). It is independent of everything else here, it is small, and it is the one component that can be finished and hardened while termforge request 1 is still being scoped. Its test suite is the deliverable, not its line count.
8. **Write the plugin boundary types before the first plugin** — `Str`, `Span`, the tag, the `static_assert`s, the versioning policy. §7.3 is a one-way door and §7.7's no-raw-pointers constraint is unrecoverable if discovered late.
9. **Add a CI job that builds a plugin against the other standard library.** One job, and it is the only thing that will reliably catch an STL type creeping into the boundary during a routine change. Add it with the first plugin, not after the first corruption.
10. Draft the operator documentation early, not at release — including the §7.9 trust statement. Writing down what an operator is responsible for tends to surface missing knobs while they are still cheap to add.
11. Keep the surfaces separated in the repository layout from the first commit — server, plugin SDK headers, client library. The SDK must be buildable against with no path into server internals, and the client must not be able to reach them by accident.
