# Changelog

All notable changes to sandwall. Dates are commit dates, not release dates.
Format loosly based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.5.1] - 2026-08-16

### Fixed

- Windows: the sandboxed child no longer flashes a console window per
  command. CreateProcessWithLogonW defaults to CREATE_NEW_CONSOLE and a
  cross-logon child cannot inherit the caller's console, so every
  sandboxed run opened its own window (delegated to Windows Terminal on
  default Win11, i.e. a visible terminal per bash command). The spawn
  now passes CREATE_NO_WINDOW plus STARTF_USESHOWWINDOW/SW_HIDE; the
  relay's CreateProcessW child inherits that invisible console.

### Changed

- No embedded C left: all three shims are gone.
  - `desktop_shim.c` -> `winuser.grantDesktopAccess` (same
    Get/SetSecurityInfo + SetEntriesInAclW calls via acl.nim, the
    do-not-free-the-old-DACL comment kept).
  - `spawn_shim.c` -> a direct 11-argument `CreateProcessWithLogonW`
    import (the shim existed because the first attempt used
    CreateProcessAsUserW's argument shape and misaligned the stack).
  - `wfp_shim.c` -> FWPM provider/sublayer/filter structs built in
    Nim with `allocWide` strings; direct `Fwpm*Add0` calls. The
    filter weight arg was dead even in the shim (it always set
    FWP_EMPTY) and is now dropped - BFE auto-assigns and the permit
    pair outranks the block on condition count.
  All three replacements are verified live on Windows 11 26100
  (setup fence read, e2e policy run, deny-narrowing with rollback,
  exit-code propagation, PATH resolution).
- Windows argv quoting exists once (`wall/quotecmd.nim`). This also
  fixes `spawnAsSandwall` (the fence behavioral probe), whose
  wrap-only quoter mangled arguments containing quotes.
- The Windows run lifecycle is owned by the library:
  `rtoken.runAsSandboxUser` spawns, waits, and unwinds (pipe close +
  DENY-ACE rollback) in a try/finally, and a failed spawn cleans up
  after itself. `closeRunRelay`/`rollbackDenies` are gone from the
  public API; callers cannot forget them anymore.
- The retired AppContainer filesystem backend (superseded by the
  dedicated-user backend in 0.4.0) is deleted from acl.nim, which
  shrinks to the shared AC primitives: types, FFI, stampAce,
  hasSidAce, removeSidAces.
- Dedupe: `wall/sockshim.nim` holds the winsock portability layer,
  the two-socket splice loop, sendAll and closeSock (proxy.nim and
  netns.nim drop their copies); `isPathUnder` lives in paths.nim;
  wfp's openEngine/deny-hint and delete-filters-by-key loops are one
  proc each; the proxy fence-port range is imported from wfp.nim
  instead of mirrored (the staticRead mirror-check test is gone).
- The debug cross-compile defines (swNoRelay, swNoJob, swNoPump,
  swNullCwd) and the never-used `internetAccess`/`inetOk` parameters
  are removed.

## [0.5.0] - 2026-08-16

### Fixed

- Windows: CreateProcessWithLogonW children no longer die at loader
  init (0xC0000142) or stall on a CSRSS ALPC reply. Two causes, both
  verified on Windows 11 26100:
  - the explicit lpDesktop="winsta0\default" string made
    console-subsystem children fail their cross-session desktop
    connect even with the setup-time winsta0 + default-desktop ACL
    grants in place. lpDesktop is now NULL: the child initializes in
    the caller's desktop. (The old "the desktop string is REQUIRED"
    finding was an artifact of the grants never being applied - see
    the next bullet.)
  - the setup-time desktop grant helper (csrc/desktop_shim.c)
    heap-corrupted (0xC0000374) before applying the default-desktop
    ACE: the old DACL returned by GetSecurityInfo was LocalFree'd
    (fatal in session-0 callers on this build) and the domain buffer
    for the second LookupAccountNameW call was one terminator short.
    The old DACL is now leaked (~200 bytes, once per setup) and the
    buffer is sized with +1.
- Windows: the child environment is passed explicitly
  (GetEnvironmentStringsW + CREATE_UNICODE_ENVIRONMENT). With a NULL
  env CreateProcessWithLogonW gives the child a fresh block: the
  stdio-relay pipe name, the wall-proxy vars, and TEMP/TMP never
  arrived, and the relay silently produced nothing.
- Windows: the stdio relay hop works. The pipe client handle is now
  inheritable (the real command inherits it as stdio), the pump
  thread's Thread object is heap-allocated (a stack-allocated Thread
  died with its scope before pumping), the relay command is
  `<self> stdio-relay --` with a matching CLI dispatch in the
  sandwall binary, and argv-to-command-line quoting follows the
  CreateProcessW escaping rules (embedded quotes in `bash -c` script
  strings were mangled by the wrap-only version).

## [0.4.0] - 2026-08-15

### Changed

- Windows backend replaced: the filesystem sandbox now runs commands
  as a dedicated local user (`sandwall`, created by the one-time
  elevated `setup`) via CreateProcessWithLogonW with
  lpDesktop="winsta0\default", inside a KILL_ON_JOB_CLOSE Job.
  Writable roots get an ALLOW ACE for that user (plus traverse-only
  ACEs on profile ancestors); deny-narrowing stamps a DENY ACE that is
  rolled back after the run. This replaces both the AppContainer
  backend (killed msys2/cygwin at DLL init) and the same-user
  write-restricted-token backend: the restricted-token model needs the
  token user SID in the restricting list for msys2's owner-ACL'd
  signal pipe, which makes every user-writable path writable and the
  sandbox a no-op (verified on Windows 11; the same wall as
  openai/codex#17459). The dedicated user also lets the existing WFP
  fence confine sandboxed network egress at the kernel (verified:
  off-loopback connect blocked) and keeps schannel https working for
  tools that use it.
- CreateProcessWithLogonW is called through a C shim
  (csrc/spawn_shim.c): the real prototype takes 11 arguments (no
  process/thread attribute params, no inherit flag); a hand-written
  Nim import with the CreateProcessAsUserW shape misaligns the stack
  and SIGSEGVs.

### Fixed

- ACCESS_MODE enum order in acl.nim: DENY_ACCESS=3 and REVOKE_ACCESS=4
  were swapped, so a policy `deny` stamp silently REVOKEd (a no-op
  strip) and deny-narrowing under a writable root never took.

## [0.2.7] - 2026-08-13

### Added

- `Rule.hidden`: rules flagged hidden are enforced by `checkPath` and
  `resolve` like any other rule but skipped by `renderPolicy`. For
  implicit guard rules a host application adds on top of the parsed
  policy (3code uses it to keep its own policy files read-only without
  showing them in the rule dump).

## [0.2.4] - 2026-08-08

### Fixed

- Windows WFP fence: the fence did not install. The failure was
  FWP_E_LAYER_NOT_FOUND (0x80320004), misdiagnosed in a prior attempt
  as FWP_E_INVALID_WEIGHT (an error code that does not exist). Root
  cause: 5 of 6 WFP layer/provider GUIDs were hallucinated
  (plausible-looking but wrong byte values). Verified against the
  Microsoft SDK header and three independent C sources (OpenVPN,
  WireGuard, strongSwan). With the correct layer GUID,
  FwpmFilterAdd0 returns S_OK. Additional bugs fixed during live
  verification on Windows 11: FWP_MATCH_RANGE was 1, should be 5
  (FWP_MATCH_GREATER); FWP_ACTION_BLOCK/PERMIT used 0x2000
  (NON_TERMINATING) not 0x1000 (TERMINATING); FWP_V6_ADDR_MASK was
  unhandled in addFilter (null pointer deref); enumOurFilters read
  only 256 of 600+ filters in a single enum call; wfp_shim.c lacked a
  _WIN32_WINNT guard (types invisible to gcc); the AC fence used
  ALE_USER_ID with a security descriptor, which matches the token
  user rather than the AppContainer SID, switched to ALE_PACKAGE_ID
  with FWP_SID; runMain passed inetOk = netAllowed (airgap) instead of
  inetOk = true (fence posture) for host rules.

### Changed

- Windows: host-rules network posture is **WFP fence + degrade**.
  With host rules and `sandwall setup` (one-time elevated) installed,
  WFP filters confine the AppContainer child to loopback, and the wall
  proxy enforces the hostname allowlist (same architecture as POSIX).
  Without `sandwall setup`, host rules produce a stderr warning and the
  child has open network access (accepted degrade).
- Policy DSL access codes replaced by words: `+` -> `write`, `-` ->
  `deny`, `*` -> `read`. Arbitrary whitespace allowed between the word
  and the target. Old-format policy files must be rewritten; the parser
  silently drops old-style lines.

### Added

- Windows: `installAcFence`, `uninstallAcFence`, and `acFenceStatus`
  expose the AppContainer fence (loopback confinement keyed on the
  package SID). `setup` installs both the user fence and the AC fence;
  `--status` reports both; `--uninstall` removes both.
- Windows: the restricted-token + CPAU backend (which could not spawn a
  confined child on Windows 11) is replaced by an **AppContainer**
  backend. The child runs under a lowbox token that denies filesystem and
  network by default; writable paths get an ALLOW ACE + Low integrity
  label for the AppContainer SID, read-only paths a read+execute grant,
  and the stamps roll back after the child exits. Filesystem isolation is
  verified on Windows 11. Network semantics now match POSIX: with no host
  rules the child gets the `internetClient` capability (network left
  alone); with host rules the child gets no capability and is fully
  offline (the AppContainer blocks even loopback, so the wall proxy
  cannot be reached - the allowlist degrades to an airgap, with a stderr
  warning). The wall proxy compiles on Windows (WSAPoll/winsock port).
  Inside a sandboxed `cmd`, run user executables by bare name or
  relative path (not a drive-letter absolute path, which cmd under an
  AppContainer refuses). Windows CLI tests now run natively (portable
  `type`/`cmd` probes, pwsh-safe CI step).

## [0.2.0] - 2026-07-28

### Added

- `rules` module: the policy file DSL (`+` allow, `-` deny, `*`
  read-only; path and host targets), parser, cascade loading, checkPath,
  resolve, render, append. Host rules (hostname/IP, optional port) are
  parsed for the future network sandbox but not enforced.
- `firewall-research.md`: cross-platform network sandboxing survey
  (Landlock ABI v4, Seatbelt, WFP, proxy architectures) for the
  upcoming network milestone.

### Fixed

- Baseline read set now covers `/etc`: ld.so config, resolv.conf,
  nsswitch, and locale files made glibc programs unreliable under a
  sandbox that denied /etc reads.

## [0.1.0] - 2026-07-25

First release. A filesystem sandbox backed by OS-native primitives, with one
Nim API across three platforms.

### Added

- **Linux backend**: Landlock ruleset. `restrict(writable, read)` confines
  the calling thread and all its children to a fixed set of writable and
  read-only paths. Unprivileged, kernel-enforced, monotonic (no un-restrict).
  Access rights are masked to the running kernel's Landlock ABI version so
  the binary loads on any 5.19+ kernel. (`cddce2c`, `69804bc`)
- **macOS backend**: Seatbelt, via `sandbox_init_with_parameters` from
  libSystem. Same monotonic, inherit-on-fork semantics as Landlock. Symbols
  are resolved through `dlsym` so the binary loads on every macOS release
  regardless of header availability. (`9c1980f`, `9fae8ca`, `557895c`)
- **Windows backend**: restricted token + per-path ACLs. A fresh SID is
  stamped as a DENY ACE on volume roots and an ALLOW ACE on the writable
  paths; the child is spawned via `CreateProcessAsUser` with that token and
  the ACLs roll back when it exits. (`ec526e1`)
- **The two primitives**: `restrict(writable, read)` and `forkNimbox` / `exec`
  / `wait`. Same names, same semantics on every platform. `restrict.nim`
  dispatches to the active backend at compile time. (`cddce2c`)
- **CLI**: `sandwall restrict RWPATH... [--ro ROPATH...] -- CMD ARGS...`.
  Confines itself then `exec`s the command. System dirs are auto read-only so
  the command's binaries and libs stay runnable. `setsid` before exec gives the
  command its own process group for clean signal delivery. (`2af0796`,
  `2f5c8d0`)
- OS-specific baseline read paths and file-type-aware Landlock rules so
  system directories, device nodes, and shared libs behave correctly across
  the backends. (`fb83fee`)
- CI: build + test matrix (Ubuntu, macOS universal binary, Windows), with a
  tag-gated release job that publishes platform artifacts. (`9c1980f`,
  `ec526e1`)
