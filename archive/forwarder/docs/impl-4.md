# Chunk 4: Spawn-time permits (Windows WFP, macOS seatbelt)

## Goal

Per-IP kernel permits at spawn (current + previous generation), no live
mutation. **Two gates first**: Windows elevation, macOS in-fence DNS.

## Read first

- `src/sandwall/wall/wfp.nim` - filter table, fixed GUIDs, install/
  uninstall lifecycle, the C shim (`csrc/wfp_shim.c`), compile-only
  caveat.
- `src/sandwall/seatbelt.nim` - `buildProfile`, the egress section, the
  deny `with message` tag.
- `src/sandwall/wall/permit.nim` - `seedFromPolicy`, `refreshForSpawn`,
  snapshot.
- `windows-status.md` - verified fence behavior and the compile-verified
  convention.
- 3code `streamexec.nim` (`ensureWallProxy`, `writeWallConf`, `wallEnv`)
  and `box.nim` (`restrict` / `runSandboxed`): the spawn paths.

## Gates (before building either backend)

1. **Windows elevation.** Per-run WFP filter adds and removes need BFE
   write access. The one-time setup is elevated; the spawn is not. Probe
   on beck: can a standard-user session add and remove a filter under a
   sublayer whose SD grants it?
   If not, **cut the Windows raw path**, keep the env path, document. Do
   not ship a fence that silently stops enforcing, and do not leave
   filters behind because the un-elevated remove was denied. Note: the
   Windows child runs as the sandwall user, not the invoking user, so its
   HOME and `~/.ssh` are the sandwall user's; the invoking user's config
   and keys are not there. The raw path needs its own config/key answer
   there, or the elevation gate makes it moot.
2. **macOS in-fence DNS.** The current fence resolves at the proxy
   (`socks5h`); `getaddrinfo` inside Seatbelt is likely dead. Probe on
   stefani. If dead, allow the system resolver's mach service
   (mDNSResponder) and re-probe; that works but is a name-exfil channel.
   If that is not acceptable, **cut the macOS raw path** and keep the env
   path. Plain `ssh host` cannot work raw without in-fence DNS.

## Invariants (do not deviate)

- **Apply at spawn only.** The long-lived 3code forwarder owns the set:
  seed it from the policy at proxy start, refresh stale entries per spawn,
  write the snapshot into the run tmp. The box child reads it and passes
  it to the backend: macOS in `restrict` before Seatbelt; Windows in
  `runSandboxed` before the spawn. The standalone CLI builds and seeds the
  set in-process instead. No mid-run mutation.
- Current + previous generation; previous older than grace dropped at
  snapshot time, not at stamp time.
- **Wildcard rule -> env mode.** A wildcard allow rule cannot be
  enumerated, so the snapshot cannot cover its names. Any wildcard allow
  rule switches the run to env mode (the ProxyCommand wrapper), where the
  proxy decides by name.
- **Windows:** per-IP permit filters for the sandwall SID, one per
  (ip, port-range) pair, v4/v6; keep loopback + proxy port-range permits;
  block-all-else unchanged. Dynamic per-run GUIDs; track handles; remove
  only own handles; sweep dead PIDs (marker includes PID + timestamp).
  **Concurrent fenced runs share the permit union** (same SID): document,
  do not claim per-run isolation.
- **Windows overflow** (>512 ip-port pairs): fall back to env mode for that
  run with a log, not silent deny.
- **macOS:** one `(allow network-outbound (remote ip "<ip>:<port>"))` line
  per stamped IP; `/32` for literals; no CIDR (the policy has no CIDR
  rules). Port 0 = `*`. Emit in the egress section. `allow *` skips
  stamping.
- **The new WFP FFI goes through `csrc/wfp_shim.c`** (ORC corrupts the WFP
  RPC stack); do not call `FwpmFilterAdd0` directly from Nim.
- **IP permits are coarser than names:** a denied name sharing an IP with
  an allowed name is reachable. Document; the env path is the answer for
  policies whose denies matter.

## Instructions

1. Parent pre-spawn (3code): `seedFromPolicy` at proxy start;
   `refreshForSpawn(1500ms)` per spawn; `writeSnapshot` into the run tmp;
   `wall.conf` carries the path. Skip when the policy is effectively open
   (`allow *`) or has wildcard allow rules (env mode).
2. Windows: `stampPermits(sid, entries)` / `clearPermits(runId)` in
   `wfp.nim` plus the C shim; dynamic GUIDs; SID-keyed permits; overflow
   fallback; teardown hook; dead-PID sweep. Compile-verified until beck.
3. macOS: the profile assembler takes the parsed snapshot; emit the lines;
   unit test the exact profile text for a fixture; add the DNS mach allow
   only if the gate says so.
4. Tests: macOS profile text (grace, ports, open policy); seed/refresh
   (exact, IP literal, wildcard report, deadline, mock resolver);
   Windows pure helpers (GUID, filter shape, sweep filter); manual
   beck/stefani after the gates.

## Verification

- `nimble test` + `nimble install`.
- mingw **per module**: `nim c --os:windows -d:mingw --cpu:amd64
  --compileOnly --path:src src/sandwall/wall/wfp.nim` (and winuser). A
  full `sandwall.exe` cross-compile is not available here (wall.nim has
  POSIX-only modules); do not claim it.
- Manual gates: beck (elevation probe first, then fenced ssh allow/deny),
  stefani (DNS probe first, then profile lines + ssh). Deferred only with
  an explicit note.

## Next step

When complete and verified, call `clear` with:
- summary: "Chunk 4 done: seeded snapshot handoff, WFP per-IP dynamic
  permits (current+prev gen, teardown-safe), seatbelt per-IP allow lines,
  unit tests green, per-module mingw green; beck/stefani manual runs:
  <done/deferred + why>."
- instructions: "Read impl-5.md and execute the instructions there."
