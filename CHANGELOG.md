# Changelog

All notable changes to nimbox. Dates are commit dates, not release dates.
Format loosly based on [Keep a Changelog](https://keepachangelog.com/).

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
- **CLI**: `nimbox restrict RWPATH... [--ro ROPATH...] -- CMD ARGS...`.
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
