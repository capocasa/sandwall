# Changelog

All notable changes to sandwall. Dates are commit dates, not release dates.
Format loosly based on [Keep a Changelog](https://keepachangelog.com/).

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
