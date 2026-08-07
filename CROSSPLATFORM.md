# Plan: macOS and Windows backends for nimbox

> **Status (2026-08): SUPERSEDED for Windows.** This document is the original
> design plan. The macOS backend shipped as written (Seatbelt). The Windows
> backend did NOT ship as the restricted-token + DENY-ACE design in "Phase 3"
> below - that approach proved unworkable on Windows 11 (`CreateProcessAsUser`
> with a hand-built restricted token fails with access denied; CPAU is broken).
> The shipped Windows backend is an **AppContainer**: the child runs under a
> lowbox token that denies filesystem and network by default, with ALLOW ACEs
> plus a Low integrity label stamped for the AppContainer SID on writable
> paths and read+execute grants on read-only paths (see `src/sandwall/acl.nim`
> and `process.nim`, and the README "Windows notes"). Filesystem isolation is
> verified live. Network: with no host rules the child gets the
> `internetClient` capability (network left alone, as POSIX); with host
> rules the child gets no capability and is fully offline (the
> AppContainer blocks even loopback, so the wall proxy/allowlist cannot
> pass traffic - an airgap, not a loopback-fenced allowlist; the loopback
> exemption is MSIX-only and WFP needs admin). The Phase-3 text below is
> kept for history.

Goal: make `restrict(writable, read)` and the `nimbox restrict ... -- CMD` CLI
work on macOS and Windows, behind the same Nim API the Linux backend already
exposes. The Nim user sees one API; compile-time `when` selects the backend;
OS-specific code lives in OS-specific modules.

## Current state (the Linux baseline)

```
src/
  nimbox.nim              # library + CLI (when isMainModule)
  nimbox/
    restrict.nim          # restrict(writable, read) - the public primitive
    process.nim           # forkNimbox / exec / wait
    landlock.nim          # raw Linux Landlock syscalls
```

`restrict.nim` imports `landlock` and builds Landlock rulesets. `process.nim`
holds the fork/exec/wait helpers (posix-flavoured). The CLI in `nimbox.nim`
calls `restrict` then `exec`. Everything works because `restrict` is a single
no-state call that applies a kernel restriction to the current thread, and
`process` runs the sandboxed child via fork-restrict-exec.

The plan keeps that shape exactly: `restrict.nim` becomes the OS-dispatcher,
and per-OS backend modules each implement the same three procs the dispatcher
needs.

## Design: the dispatch contract

Every OS backend exposes the same minimal surface:

```nim
# per-OS backend: landlock.nim (linux), seatbelt.nim (macos), acl.nim (windows)
proc backendSupported*(): bool
proc backendName*(): string
proc restrictImpl*(writable, read: openArray[string])
```

`restrict.nim` (the merged module the user imports) becomes a thin dispatcher:

```nim
proc restrict*(writable: openArray[string]; read: openArray[string] = []) =
  when defined(linux):    landlock.restrictImpl(writable, read)
  elif defined(macosx):   seatbelt.restrictImpl(writable, read)
  elif defined(windows):  acl.restrictImpl(writable, read)
  else:                   raise unsupportedPlatform()
```

`process.nim` also needs a per-OS split: the fork/exec/wait model is
posix-specific. On Windows there is no fork; the equivalent is
`CreateProcessAsUser` with the restricted token. So `process.nim` dispatches
too, and Windows gets its own spawn helper.

This means **three** things change, all behind the same public API:

1. `restrict.nim` drops its Landlock logic and becomes a `when`-dispatcher.
2. The Landlock logic moves into `landlock.nim` as `restrictImpl`.
3. `process.nim` gains a `when` split: posix keeps fork/exec/wait, Windows
   gets `spawnRestricted` (CreateProcessAsUser).

The user-facing names (`restrict`, `forkNimbox`, `exec`, `wait`, the CLI) do
not change.

## Shared helpers that move out of backends

`normalize` (absolute + symlink resolution) and the path-set deduplication are
OS-independent. They move into a small `nimbox/paths.nim` that all backends
import. On Windows `normalize` also canonicalises drive letters and forward/
back-slash mix.

## Phase 1: refactor Linux behind the dispatch contract

No behaviour change, just moving code so macOS/Windows drop in cleanly.

- `src/nimbox/landlock.nim`: add `backendSupported`, `backendName`, and
  `restrictImpl(writable, read)`. The body of `restrictImpl` is today's
  `restrict` body. Keep `createRuleset`/`addRule`/`apply` private to this
  module (or move into `restrictImpl`); the merged module no longer touches
  them.
- `src/nimbox/seatbelt.nim` and `src/nimbox/acl.nim`: stubs that raise
  `OSError` with "not yet implemented", so the project compiles on all
  platforms and tests can assert the raise.
- `src/nimbox/restrict.nim`: becomes the `when`-dispatcher calling
  `restrictImpl`.
- Tests: the existing fork-based tests stay Linux-only (they rely on fork).
  Add a "restrict raises on unsupported backend" test that runs everywhere.

This phase is verifiable on Linux immediately (tests must still pass) and
unblocks cross-compilation checks.

## Phase 2: macOS Seatbelt backend

### Mechanism

Seatbelt is Apple's TrustedBSD MAC framework, same kernel layer that sandboxes
App Store apps and Chrome renderers. The primitive we want is
`sandbox_init_with_parameters` in libSystem, which applies a Scheme-dialect
policy profile to the calling process and all children. It is the documented-
but-"deprecated" API that Chrome, Firefox, and Nix all ship; Apple has no
replacement and is very unlikely to remove it.

The profile is a Scheme program. We generate one per `restrict` call:

```scheme
(version 1)
(deny default)
(import "bsd.sb")                          ; minimum to let a process run
(allow process-exec file-read*             ; read+exec system dirs
  (subpath "/bin") (subpath "/usr/bin")
  (subpath "/sbin") (subpath "/usr/lib"))
(allow file-write* file-read*              ; writable paths
  (subpath "<writable1>") (subpath "<writable2>"))
(allow file-read*                          ; read-only paths
  (subpath "<readonly1>"))
```

Parameters via `(param "X")` + `sandbox_init_with_parameters`, or simpler:
string-substitute the paths into the profile text before the call. Direct
substitution is what Codex's seatbelt policy does and avoids parameter-array
marshalling. Paths must be canonicalised (no `..`, resolved symlinks) because
Seatbelt matches on the literal subpath string.

### Module: `src/nimbox/seatbelt.nim`

```nim
proc backendSupported*(): bool = true   # Seatbelt ships on all macOS
proc backendName*(): string = "seatbelt"

proc restrictImpl*(writable, read: openArray[string]) =
  let profile = buildProfile(writable, read)   # the Scheme string
  var errbuf: cstring
  let r = sandboxInitWithParameters(profile, 0.SANDBOX_NAMED, nil, addr errbuf)
  if r != 0:
    let msg = $errbuf; sandboxFreeErrorbuf(errbuf)
    raise newException(OSError, "seatbelt: " & msg)
```

FFI: `sandbox_init_with_parameters` and `sandbox_free_errorbuf` are not in any
public header, so declare them directly:

```nim
proc sandbox_init_with_parameters(profile: cstring, flags: uint64,
        params: ptr UncheckedArray[cstring], errbuf: ptr cstring): cint
    {.importc, dynlib: "libSystem.dylib".}
proc sandbox_free_errorbuf(buf: cstring)
    {.importc, dynlib: "libSystem.dylib".}
```

### How it maps to the contract

- "monotonic": Seatbelt is also monotonic. Each `sandbox_init_*` call layers a
  stricter profile; you cannot unrestrict. So `restrict`'s "only narrows"
  semantics hold on macOS exactly as on Linux. No special handling.
- "children inherit": yes, by default. The restriction binds to the process
  and all descendants.
- The profile is rebuilt from scratch on every `restrict` call (no state),
  matching the Landlock backend's no-init model.

### Verification on macOS

- `restrict` then write to an allowed path: succeeds.
- `restrict` then write to a denied path: fails with `Operation not permitted`
  (EPERM from the MAC layer).
- Fork a child, `restrict` in child, exec `ls /` outside allow set: child sees
  the denial. Same test shape as Linux, different backend.

### Confirmed by primary sources

The in-process `sandbox_init` API is the right call, not `sandbox-exec`.
Microsoft MXC (microsoft/mxc) ships the same approach in production: it
applies a generated TinyScheme profile "via `sandbox_init()` inside
`Command::pre_exec` (after `fork()`, before `exec())`" — exactly nimbox's
fork-restrict-exec pattern. Apple marked `sandbox_init` deprecated in headers
since 10.8 but it continues to ship, Apple's own apps use it, and Chromium
relies on it. Zero-install, unprivileged, ~10ms startup.

The original research doc's note that Codex uses `sandbox-exec` on macOS is
stale for live Codex (which now uses `bwrap` on Linux with a user-namespace
fallback, per the current Codex sandboxing docs). Nimbox's Seatbelt choice
is aligned with MXC and Chromium instead, which is cleaner — no helper
binary, no external process.

### Seatbelt profile, concretely (from MXC)

Do **not** rely on importing Apple's `bsd.sb` (the open question in the first
draft of this plan). MXC instead emits an explicit baseline of read-only
system paths so the dynamic linker and stdlib keep working:

```
/usr/lib /usr/libexec /usr/share /System /Library
/private/var/db/timezone /private/var/db/dyld /private/etc
/dev/null /dev/zero /dev/random /dev/urandom
```

nimbox should emit the same baseline automatically on every macOS profile,
in addition to the caller's writable and read-only paths. SIP independently
protects `/System` and `/usr` as read-only regardless of the profile, so we
get that for free.

Two Seatbelt semantics to bake in:
- **Last-match-wins per operation.** Deny rules emitted *after* allows
  override them. So the profile order is: baseline read allows, caller write
  allows, caller read allows, then any explicit denies last.
- **Network in v1 = deny-all by omission.** Seatbelt's `(deny default)` blocks
  sockets if no `network-outbound` allow is emitted. MXC confirms Seatbelt
  does no DNS, so per-host filtering is best-effort at connect time — out of
  scope for v1, just deny everything by not emitting any network allow.

### Risks / unknowns to resolve during implementation

1. **`sandbox_init_with_parameters` vs `sandbox_init`.** The simpler
   `sandbox_init(profile, flags, errbuf)` takes the profile as a string and
   is what MXC uses; `sandbox_init_with_parameters` adds a params array for
   `(param "X")` substitution. Start with `sandbox_init` + direct string
   substitution (fewer FFI moving parts), only add the parameters variant if
   string substitution proves unsafe (e.g. quoting/escaping issues).
2. **Profile path canonicalisation.** Seatbelt matches on literal subpath
   strings, so every path in the profile must be canonical (no `..`, symlinks
   resolved) — `paths.nim`'s `normalize` handles this, but verify macOS
   resolves `/private/tmp` vs `/tmp` correctly (they're the same under macOS;
   the baseline must use the `/private` forms).
3. **Cleared environment (optional hardening).** MXC does not inherit the host
   environment, preventing secret leakage. Consider whether nimbox should do
   the same for spawned children; it's a behavioural change worth a flag, not
   the default for v1.

## Phase 3: Windows backend

### Mechanism and the unprivileged path

Windows has no single "intercept the syscall" hook. The Codex-validated
approach is a **restricted token** plus **filesystem ACLs**:

1. `OpenProcessToken(GetCurrentProcess(), ...)` to get the current token.
2. `CreateRestrictedToken(token, ...)` to produce a token with:
   - privileges stripped, and
   - a **restricting SID** added (a freshly-generated SID we own).
3. For each path the process should NOT write: stamp a DENY ACE for the
   restricting SID onto that path's DACL via `SetNamedSecurityInfo`.
4. For each writable/read-only path: ensure the restricting SID has an ALLOW
   ACE for the desired rights (write/read+execute respectively).
5. Spawn the child with the restricted token via `CreateProcessAsUser` (no
   `SE_ASSIGNPRIMARYTOKEN_NAME` privilege needed when the token is a
   restricted copy of the caller's own, per the MS docs).

The critical detail from the Codex issues: the ACL stamping is where it
breaks. Two access checks run on every `NtCreateFile`, the normal DACL check
and the restricting-SID check, and **both** must pass. Codex's bugs (issues
#13378, #18918, #22044) are all about the ACL stamping being incomplete: drives
the workspace isn't on, `.git` dirs, installed-app resource dirs. The lesson
for us: the Windows backend must stamp *every* ancestor of denied paths, and
must not over-deny (e.g. read ACEs on system dirs the process needs to load
DLLs from).

This is genuinely the weak platform. Be honest about it in the README and in
error messages.

### Module: `src/nimbox/acl.nim`

The surface is the same, but the implementation is heavier than the other two:

```nim
proc backendSupported*(): bool = true
proc backendName*(): string = "windows-acl"

proc restrictImpl*(writable, read: openArray[string]) =
  # 1. capture current token, build restricted token with a new SID
  let (rToken, sid) = buildRestrictedToken()
  # 2. stamp DENY ACE for `sid` on the filesystem root(s) the process
  #    should not touch - Windows has no single root, so deny on each
  #    drive letter / volume root, then ALLOW on the writable/read paths.
  stampDenyAces(sid, allVolumeRoots() -- writable -- read)
  stampAllowAces(sid, writable, rights = FILE_ALL_ACCESS)
  stampAllowAces(sid, read, rights = FILE_GENERIC_READ or FILE_GENERIC_EXECUTE)
  # 3. the token is applied to spawned children, not the current process,
  #    so restrictImpl *records* the token for the upcoming spawn.
  currentRestrictedToken = rToken
```

### Why Windows `restrict` works differently from posix

On Linux/macOS, `restrict` confines the *calling thread* and the child
inherits it. On Windows, a token is applied at `CreateProcess` time: you cannot
retroactively narrow the *current* process's token the way Landlock/Seatbelt
narrow the current thread. So the Windows `restrictImpl` prepares a token, and
`spawnRestricted` (the Windows equivalent of `forkNimbox`+`exec`) uses it.

This is a real semantic wrinkle: on Windows, `restrict` alone does nothing
until a child is spawned with the prepared token. The public API stays the same
(`restrict` then `forkNimbox`+`exec`), but the Windows `forkNimbox` is the
point where the token takes effect. Document this in the Windows module's doc
comment; do **not** paper over it by restricting the parent (that would break
the "parent stays free" model the whole library is built on).

### `process.nim` on Windows

```nim
when defined(windows):
  proc forkNimbox*(): Handle =
    # Windows has no fork. forkNimbox returns a sentinel; the real work
    # happens in exec(), which calls CreateProcessAsUser with the
    # prepared restricted token.
    discard
  proc exec*(cmd: openArray[string]) =
    createProcessAsUserRestricted(currentRestrictedToken, cmd)
  proc wait*(h: Handle): ExitCode = waitForSingleObject(h)
```

The Windows `runSandboxed` template still reads the same to the caller. The
fork/exec split is faked but the user code (`forkNimbox(); if child: restrict();
exec(); wait()`) is awkward because there's no real child id from fork. Better:
on Windows, expose `spawnSandboxed(writable, read, cmd)` that does it in one
call, and have `runSandboxed` map to it. The two-call posix dance is a posix
artifact; Windows gets the natural one-call form.

This is the one place the API is genuinely OS-shaped. Options:
- (a) Keep the posix two-call API and make Windows fake fork badly.
- (b) Make `runSandboxed` the portable entry point and treat forkNimbox/exec as
  posix-only internals.

Recommend (b): `runSandboxed(writable, cmd, read=[])` is the portable
high-level helper; `forkNimbox`/`exec`/`wait` are posix primitives that the
macOS/Linux `runSandboxed` uses internally. Windows `runSandboxed` calls
`spawnRestricted` directly. The README shows `runSandboxed` as the recommended
form, with the lower-level posix procs documented as posix-only.

### Verification on Windows

- `runSandboxed` write to allowed path: succeeds.
- `runSandboxed` write to denied path: fails with ERROR_ACCESS_DENIED (5).
- Child cannot modify `C:\Windows` or Program Files.
- The known-Codex failure cases: workspace on a non-system drive, `.git` inside
  workspace, reading installed-app resources. Reproduce each and confirm the
  ACL stamping covers them before claiming Windows works.

### Risks / unknowns to resolve during implementation

1. **ACL rollback.** Stamping DENY ACEs on volume roots mutates the
   filesystem's security descriptors. We must remove them after the child exits
   (`__try`/finally on the spawn), or the machine is left with deny ACEs that
   break other processes. This is the single most dangerous part of the Windows
   backend. Landlock/Seatbelt never mutate the filesystem; Windows does.
2. **Volume enumeration.** `allVolumeRoots()` must cover every mounted drive
   the process can reach, or the sandbox has holes. Use
   `FindFirstVolumeW`/`FindNextVolumeW`.
3. **Network.** Out of scope. Restricted tokens don't filter network; that
   needs WFP or a proxy, both heavy.
4. **Test environment.** We have no Windows box in the loop. The Windows
   backend can be written and cross-compiled from Linux, but the ACL-stamping
   correctness *must* be tested on a real Windows VM before merge. Flag this as
   a hard gate.

## Module layout after all phases

```
src/
  nimbox.nim                # library + CLI, unchanged surface
  nimbox/
    restrict.nim            # dispatcher: when -> restrictImpl
    process.nim             # dispatcher: posix fork/exec/wait, windows spawn
    paths.nim               # normalize, dedup (shared)
    landlock.nim            # linux backend: restrictImpl via Landlock
    seatbelt.nim            # macos backend: restrictImpl via Seatbelt
    acl.nim                 # windows backend: token + ACL stamping
```

## Order of work and gates

1. **Phase 1 (refactor)**: do this on Linux now. It is pure motion, verifiable
   by the existing tests staying green. Merges independently.
2. **Phase 2 (macOS)**: implementable and testable on a Mac. Medium risk
   (undocumented API, but proven by Chrome/Firefox/Nix). The profile
   generation is the bulk of the work; the FFI is ~10 lines.
3. **Phase 3 (Windows)**: implementable on Linux (cross-compile) but **not
   mergeable without a Windows test run**. High risk (ACL mutation, rollback,
   volume enumeration). Schedule a Windows VM before starting.

Each phase lands behind the same `restrict` / `runSandboxed` API. No phase
changes what a Nim user who already targets Linux has to do.

## What is explicitly out of scope

- Network filtering on any platform (separate effort behind a flag).
- IPC/signal scoping (Landlock ABI v6; Windows has no equivalent).
- A `sandbox-exec` (the deprecated CLI wrapper) path. Not used: nimbox calls
  the in-process `sandbox_init` C API directly, matching MXC/Chromium. The
  CLI wrapper only matters for the Terminal.app Launch-Constraints niche
  (MXC's `launchMethod: "open"`), which nimbox v1 does not target.
- Covering nimbox's own in-process write tools (the Claude Code lesson). That
  is the agent's responsibility, not the library's.

## Sources

Primary, fetched during planning:

- `sandbox(7)` / `sandbox_init` — the in-process Seatbelt API. Microsoft MXC
  ships it in production and documents the profile generation in detail.
  https://github.com/microsoft/mxc/blob/main/docs/macos-support/seatbelt-backend.md
- Zameer Manji, "Sandboxing subprocesses in Python on macOS" (Apr 2025) —
  `sandbox_init_with_parameters` FFI signature and a working preexec_fn
  pattern. https://zameermanji.com/blog/2025/4/1/sandboxing-subprocesses-in-python-on-macos/
- Microsoft Learn, "Restricted Tokens" — `CreateRestrictedToken`,
  deny-only SIDs, restricting-SID two-access-check semantics,
  `CreateProcessAsUser` not requiring `SE_ASSIGNPRIMARYTOKEN_NAME` for a
  restricted copy of the caller's token.
  https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens
- OpenAI Codex sandboxing docs (current) — policy modes, platform primitives;
  confirms live Codex now uses bubblewrap on Linux (not a Landlock helper).
  https://developers.openai.com/codex/concepts/sandboxing
- Codex Windows issues #13378, #18918, #22044 — the real failure modes of
  the ACL-stamping approach (non-system drives, `.git` dirs, missing
  read ACEs on app-resource dirs). Evidence for the Windows risk section.

From the existing `sandbox-research.md` (landlock(7), sandlock, the Codex
implementation analysis gist, the Anthropic sandbox-runtime critique, the
Claude Code Camp findings, the wincent catalog) — these remain the
foundation; the sources above extend and, in the case of live Codex's macOS
approach, correct them.
