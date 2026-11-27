# Chunk 1: Permit set core (portable, no platform code)

## Goal

The shared brain: hostname rules become lazily or proactively resolved IP
sets, plus the serialized snapshot the Windows/macOS backends consume. No
platform-specific code.

## Read first

- `src/sandwall/wall/hosts.nim` - matcher semantics, last-wins, `hasAllow`
  default flip, and the "no DNS in here on purpose" comment: this chunk is
  the deliberate counterpart.
- `src/sandwall/wall/proxy.nim` - `loadList`, `maybeReload`, `allowed`,
  `dialUp`: the current name-only decision and OS-resolver dial that chunk
  2 rewires.
- `src/sandwall/rules.nim` - `parsePolicy`, `loadPolicy`, `resolve`,
  `Rule`/`Resolved`, host rules with and without ports, IP literals.

## Invariants (do not deviate)

- Entry: `{host, ports, current, previous, expires, prevUntil, lastGood,
  stale}`. `ports` is the union of the **winning** host rule ports (0 =
  all), not the port that happened to be requested. `current`/`previous`
  are `seq[IpAddress]`; both families may appear, v4 is not mandatory.
- **Two resolution modes:**
  - **Lazy** (`getOrResolve`): the forwarder's CONNECT path resolves a name
    only when a connection asks for it. Wildcards are never enumerated;
    an exact name a wildcard covers is learned on first use.
  - **Proactive seed** (`seedFromPolicy`): the spawn-time backends need the
    policy's exact host rules resolved up front, because the child
    connects directly and there is no forwarder in the path. Resolve exact
    names and IP literals with a bounded parallel pool and an overall
    deadline; report wildcards and failures to the caller.
- **Refresh:** `expires = now + refresh`, `refresh = 300s`, min 60s.
  `getAddrInfo` has no TTL; this is a fixed refresh interval, not DNS TTL.
- **Serve-stale:** resolver failure keeps the last good IPs, marks the
  entry stale, warns once. Fail hard only when there has never been a good
  answer.
- **NXDOMAIN vs transient:** map platform resolver errors (glibc
  `EAI_NONAME`/`EAI_NODATA` vs `EAI_AGAIN`; Windows `WSAGetLastError`;
  macOS `EAI_NONAME` vs `EAI_AGAIN`). Ambiguous -> transient; never
  retract on a timeout. NXDOMAIN retracts.
- **Single-flight:** per-host in-progress table. Release the set lock
  before resolving; waiters block on a per-host event, bounded by the
  connect timeout.
- **Previous-generation grace:** keep the replaced IP set for 300s;
  `prevUntil` timestamps it. Only a long-lived set (the 3code forwarder)
  has history; a fresh in-process set has no previous, which is fine.
- **IP literals and hosts file:** seed IP-literal rules and hosts-file
  entries for the policy's exact names at load (no DNS, never expire). The
  hosts file path is per OS (`/etc/hosts`, Windows
  `System32\drivers\etc\hosts`). /etc/hosts is not a separate chunk 3 step.
- **Policy reload:** rebuild the HostList and clear the permit cache (then
  re-seed literals, hosts entries and exact rules). The next connect
  re-resolves lazily. This avoids stale permits for removed rules.
- **Cap:** 10k entries; evict the oldest expired/stale first; log once at
  the cap.

## Instructions

1. Create `src/sandwall/wall/permit.nim`:
   - `PermitEntry`, `PermitSet` (lock, table, change counter `gen`).
   - `getOrResolve(ps, name)`: injectable resolver proc (default
     `getAddrInfo` + fixed refresh); every invariant above.
   - `seedFromPolicy(ps, hosts, deadlineMs)`: proactive exact rules, bounded
     parallel, returns a report `{resolved, failed, wildcards}`.
   - `refreshForSpawn(ps, deadlineMs)`: refresh stale entries, serve-stale
     past the deadline.
   - `matchIp(ps, ip)`: current, or previous within `prevUntil`; returns
     the entry so the caller can check the port.
   - `writeSnapshot(ps, path)` / `readSnapshot(path)`: JSON v1 with
     `version`, `host`, `ports`, `current`, `previous`, `expires`,
     `prevUntil`. Unknown fields ignored on read.
2. Unit tests `tests/test_permit.nim`, added to `sandwall.nimble`'s test
   task: refresh math, serve-stale, single-flight (one resolution,
   waiters), NXDOMAIN retraction, transient-not-retract, prev-gen grace,
   seed exact + IP literal + hosts entry + wildcard report + deadline,
   snapshot round-trip, policy-reload clears, matchIp
   current/prev/expired/port.
3. Wire nothing else: proxy.nim, wfp.nim, seatbelt.nim untouched.

## Verification

- `nimble test` (builds `sandwall` and runs every test) plus
  `nimble install`.
- The new test file is in the task; the existing suites stay green.

## Next step

When complete and verified, call `clear` with:
- summary: "Chunk 1 done: wall/permit.nim with PermitSet (lazy + proactive
  seed, fixed refresh, serve-stale, single-flight, prev-gen grace,
  IP-literal and hosts-file seed, v1 snapshot JSON), unit tests green,
  nothing else touched."
- instructions: "Read impl-2.md and execute the instructions there."
