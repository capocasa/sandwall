# Impl plan: env-var-free IP-based egress (fake-IP DNS + permit set)

## Goal

Fenced tools work without proxy env vars: plain `ssh`, `telnet`, `scp`,
whenever the policy allows the host, on all three platforms. Linux gets a
fake-IP fence DNS plus an nft redirect and a raw forward path. Windows and
macOS get spawn-time per-IP kernel permits, behind the gates below.

## Architecture

- **Forwarder** (`wall/proxy.nim` for now; the rename is a separate optional
  chunk): decides policy by name and splices bytes. CONNECT/SOCKS for env
  tools on all platforms, raw redirected TCP on Linux.
- **Fence DNS + fake-IP (Linux):** the netns resolver answers A queries for
  **policy-allowed** names with a stable synthetic IP from `198.18.0.0/15`
  and records fake-IP -> name. Denied names get NXDOMAIN. Never fake-IP ->
  real-IP: the forwarder resolves name -> real IP at connect time and
  re-checks the name+port policy before dialing.
- **Permit set:** `{host, ports, current, previous, expires, prevUntil}`
  entries, with a fixed refresh, serve-stale and single-flight. Two uses,
  one type: the forwarder resolves lazily per CONNECT; the spawn-time
  backends need a **proactively seeded** set (exact host rules, resolved
  with a deadline) because the child connects directly. Wildcards cannot be
  enumerated, so the Windows/macOS raw path requires exact rules; a wildcard
  allow rule means env mode for that run.
- **Snapshot:** the long-lived 3code forwarder owns the set, seeds it from
  the policy, refreshes stale entries per spawn and writes a JSON snapshot
  into the run tmp; the box child reads it and passes it to the backend.
  The standalone CLI builds and seeds the set in-process instead.
- **Apply at spawn, everywhere.** Linux validates per connect (no kernel
  permit set); Windows stamps WFP per-IP filters; macOS emits seatbelt
  per-IP allow lines. No mid-run mutation.
- **No live repair.** Current + previous generation covers rotation;
  genuine mid-command failover on Windows/macOS fails until the next spawn
  and is documented.

## Preconditions and gates

- **Linux:** `nft` works inside a userns netns on this host: verified
  2026-11-25 with `unshare -Urn` + `nft -f` adding and deleting a nat
  table. `ensureUserns` always creates the user + mount namespace, so the
  `resolv.conf` bind mount is available.
- **Windows elevation gate:** per-run WFP filter adds need BFE write
  access. The one-time setup is elevated; the spawn is not. Probe on beck
  whether a standard-user session can add a filter under a sublayer whose
  SD grants it. If not, cut the Windows raw path and keep the env path.
  Do not ship a fence that silently stops enforcing.
- **macOS DNS gate:** the current fence resolves at the proxy (`socks5h`);
  `getaddrinfo` inside Seatbelt is likely dead. Probe on stefani. If dead,
  allow the system resolver's mach service and accept the name-leak
  channel, or cut the macOS raw path. Plain `ssh host` cannot work raw
  without in-fence DNS.
- **DNS exfil asymmetry:** Linux's fence DNS answers only allowed names,
  so there is no DNS exfil. Windows/macOS need the system resolver, which
  is a name-exfil channel (the child can query any name). Document it or
  cut the platform's raw path.

## Known limitations (document, do not paper over)

- **IP-based permits are coarser than names.** A denied name that shares
  an IP with an allowed name is reachable through the raw path on all
  three platforms (the backend sees only the IP). Linux's fake-IP DNS
  hides the denied name from normal resolution, but a hard-coded IP still
  works. Policies whose denies matter should use the env path (the proxy
  decides by name).
- **127/8 trade-off on Linux:** the child's own loopback services work in
  redirect mode; host loopback via `+localhost` no longer does. Document;
  env mode is the fallback for that.
- **Wildcards on Windows/macOS:** not enumerable, so the raw path cannot
  pre-permit them. Any wildcard allow rule switches the run to env mode.
- **No ssh shim at all.** The raw path removes the ProxyCommand, the SOCKS
  hop, `wall connect` and the `-F` wrapper. The sandbox runs as the user,
  so `~`, `User`, config and key paths are already correct; the degraded
  uid case is a bug to fix, not a shim use case. The only fence artifact is
  `~/.ssh` being readonly, so the default policy gains two narrow writable
  grants: `allow ~/.ssh/known_hosts` (touched if absent, so a first connect
  can persist the host key) and `allow ~/.ssh/control` (created if absent),
  so ControlMaster works with `ControlPath ~/.ssh/control/...` and no
  shim. The private keys stay denied. Windows runs as the sandwall user,
  not the invoking user, so its config/key story is separate and likely
  moot if the elevation gate cuts the raw path.

## Design notes to carry into docs

- **Fixed refresh, not DNS TTL.** `getAddrInfo` has no TTL, so the permit
  set uses a fixed refresh interval (300s, min 60s) and serve-stale.
  Per-connect freshness is an age check, not DNS TTL fidelity.
- **Rotation:** current + previous generation, 300s grace. Mid-command
  failover on Windows/macOS fails until the next spawn; Linux heals at
  the next connect.
- **Linux DNS has no exfil; Windows/macOS do.** State it plainly in the
  manual instead of pretending the resolver is fenced.

## Chunks

1. **impl-1.md** - Permit set core (portable, no platform code).
2. **impl-2.md** - Resolver-backed CONNECT/SOCKS path.
3. **impl-3.md** - Linux fence DNS + fake-IP + nft + raw path.
4. **impl-4.md** - Windows/macOS spawn-time permits, behind the gates.
5. **impl-5.md** - 3code integration, fallback wiring, docs, changelogs.
6. **impl-6.md** - Optional rename pass (`proxy` -> `forwarder`), after
   the feature lands. The feature does not depend on it.

## Rules

- Each chunk ends verified: `nimble test` and `nimble install`; new test
  files go into the nimble test task.
- Consumer check: grep `~/p/3code/src/threecode` for every changed exported
  sandwall symbol before finishing the chunk.
- Handoffs state files changed, test status, open questions.
- Keep this plan updated when discoveries change the shape.

## Progress

- Chunk 1 done (`166a739`): `src/sandwall/wall/permit.nim`,
  `tests/test_permit.nim`, `hosts.winningPorts`.
- Chunk 2 done: the proxy decides names against the HostList and then
  through the permit set, bare IPs through `matchIp`; `dialUp` takes the
  resolved addresses; `tests/test_proxy.nim` grew the resolver-backed
  cases (7 tests, 11 in the suite).
- Chunk 3 done (`7014b66`): Linux raw path, fence DNS with fake-IPs,
  nft redirect, env fallback (details in its carried-forward section).
- Chunk 4 done (`3f29d41`, `253dd5b`, `cef7e48`): `permit.snapshot()` in
  memory, `permit.liveAddresses`, `permit.canStamp`,
  `hosts.hasWildcardAllow`; WFP per-run permit filters (dynamic
  session), the setup grant, `wfp-stamp-probe`, `dnsServers`;
  `runSandboxed(..., permits)`; CLI seeding, `setup --stamp-as`,
  `wfp-stamp-probe`. **The macOS raw path is cut** (Seatbelt cannot
  permit single addresses); the Windows elevation gate is built but
  still unprobed. Both manual gates deferred: beck refused every
  documented credential, stefani was down.
- Chunk 5 done (3code): wall.conf carries `raw`, `permits`, `dns`; the
  parent decides raw per launch (Linux: nft present; Windows: exact
  allow rules and a non-empty snapshot), the box child exits 75 with
  the marker when the Linux fence does not hold and the parent re-runs
  env mode once; Windows stamps the snapshot and falls back to env
  mode on `PermitStampError`; the `-F` ssh shim and `wallSshConfig` are
  gone (env mode keeps a ProxyCommand-only wrapper); default policy
  gains `allow ~/.ssh/known_hosts` and `allow ~/.ssh/control` on POSIX;
  `3code setup --stamp-as`, `3code wall wfp-stamp-probe`; manual,
  README and both changelogs. Details in the chunk 5 section below.
- Gate run on beck (2026-11-25, after its rebuild): the Windows gate is
  open. `3code setup --stamp-as carlo` (elevated), then the unelevated
  probe as `carlo`: exit 0; a throwaway ungranted standard account:
  exit 1. A raw run as `sandwall` reached its permitted address, was
  refused on any other, and resolved names. The run found defects,
  all fixed and committed: sandwall `21b61c9` (permit filters owned by
  Administrators, so BFE failed the add with 1307; `dnsServers` read
  FIXED_INFO 8 bytes off, a SIGSEGV on every raw run), `ed1d20c` (the
  CLI called the fence not installed when an unelevated process could
  not read the engine); 3code `09badfed` (wall.conf paths are
  parseCfg string literals; a bare drive path read back as `C`),
  `385bec95` (an unreadable snapshot takes the env fallback). Details
  in the gate section at the end.

### Carried forward from chunk 1

- **ORC here is single-threaded per object.** Nim 2.4.0 keeps plain
  (not atomic) reference counts, and its cycle collector keeps its books
  per thread. Two threads touching one GC'd allocation corrupt it, and
  the crash shows up later, elsewhere (it took a stress run to find;
  TSan confirms the fix). The permit set is built for that: everything
  it hands out is a private copy made under the lock, and pool workers
  hold raw pointers only. Code that uses the set from proxy threads
  must do the same: read `sh.ps` in place (no `let ps = sh.ps`), and
  never keep a GC'd object alive across a handoff to another thread.
- `getOrResolve(ps, name, ports)` takes `winningPorts(hosts, name)`,
  not the requested port: the entry is also matched by address, where
  the name behind the request is unknown.
- `matchIp(ip, port)` is the overload to decide with; the two-argument
  form returns the first entry holding the address. `SeedReport` has
  `pending` (not done by the deadline) next to `failed`.
- **This harness's bash runs inside a sandwall fence.** `nimble test`
  cannot pass from here: two `test_sandbox` cases fail on the outer
  fence (a home-dir marker, `/proc/self/setgroups`), and `unshare -Urn`
  is refused, so the netns e2e of chunk 3 needs a host-side run. Verify
  per suite: every other suite must report 0 failed.
- `nimble install` was not run: the cybernetic standing orders say no
  auto-install, which overrides the rule above.

### Carried forward from chunk 2

- **The proxy owns a `PermitSet`, and one can be handed in.**
  `startWallProxy` (both overloads) takes `permit: PermitSet = nil`:
  nil means the proxy makes its own set and closes it in
  `stopWallProxy`; a passed set is used but not owned (the caller seeds
  it, snapshots it, closes it), which is the hook chunk 5's long-lived
  3code forwarder needs. `loadList` clears the set and reseeds the
  policy's IP-literal allow rules on every load and reload.
- **The decision is `admit` in proxy.nim.** A name: HostList as before,
  then `getOrResolve`, dial `current` in order, then `previous` while
  `ps.clock() < prevUntil`, then 502 (CONNECT) or reply 0x04 (SOCKS5).
  A literal: `matchIp(ip, port)` first, and when no entry holds it the
  policy's own decision about the literal, so an open default and `+*`
  keep admitting bare IPs as they always did. Without that fallback an
  allow-all policy would deny `ssh 1.2.3.4` and every tool that resolves
  locally; with it nothing that was allowed before is denied now.
- `sh.ps` is read in place in `admit` (never `let ps = sh.ps`), and
  `sh.ps.clock()` is a direct field call: the C shows no refcount op
  around it, so it is safe from a client thread. A TSan stress run (6
  threads, policy reload every 40 ms, ~8k tunnels) reports nothing in
  the decision path; the only report is the pre-existing `sh.running`
  bool written by `stopWallProxy` and polled by `acceptThread`, which
  predates this chunk and is still there.
- `tests/test_proxy.nim` injects a scripted resolver and a virtual clock
  through the permit set (`Script`, `permitSetFor`). Reuse that shape for
  any later test that needs a resolver: copy values out under a lock,
  never hand a shared seq to another thread.

### Carried forward from chunk 3

- **The raw fence needs a route.** A fresh netns has none, so a
  connect to a fake-IP died ENETUNREACH before nft saw the SYN. The
  plan did not say so. `prepareRawFence` now adds
  `198.18.0.0/15 dev lo scope link` through rtnetlink (one
  RTM_NEWROUTE, `netns.netlinkRoute`) before loading the ruleset;
  nothing but the pool becomes routable, so a hard-coded real IP is
  "network unreachable" rather than a redirect.
- **An AF_UNIX datagram sender without an address is anonymous.**
  `recvfrom` returns addrlen 0 for a socket that only `connect()`ed,
  so the forwarder's reply had nowhere to go. Every per-query socket
  (the netns relay's, the tests') is bound to an abstract name first
  (`sockshim.bindUnixAbstract`).
- **`hosts.allowsAnyPort` is the DNS decision.** `allows(name, 0)`
  skips port-matched rules, so `allow host:22` denied the name at
  resolution time. A bare rule decides the whole name, an allow for
  one port makes it resolvable, a deny for one port leaves the others
  to speak. The port is checked at connect, as before.
- **The forwarder resolves at DNS time, in a thread per datagram**
  (`spawnWorker`, the accept loop hands off like a connection): an
  allowed name with no address is SERVFAIL, and the connect that
  follows finds the permit set warm. The pool lives in `ProxyShared`
  under its own `fakeLock`; every read is a private copy
  (`fakeName`), and `FakePool` must be constructed with
  `initFakePool()` (a zeroed one has size 0 and reports the pool
  exhausted).
- **The raw path is fail-closed for bare addresses.** `matchIp(ip,
  port)` only; the policy default does not vouch. So an open policy
  (`+*`, deny-only) denies `ssh 1.2.3.4` in raw mode where env mode
  admitted it. Chunk 5 should say so in the manual's IP-permit
  paragraph.
- **The API split, for chunk 5's wiring.** The low-level
  `restrict(writable, ..., raw = false, dnsSockPath = "")` raises
  `RawUnavailableError` (exported from restrict on Linux) with
  nothing half-applied, after the netns, which cannot be undone.
  `restrict(rules, ..., raw = false, fallbackFd = -1)` catches it,
  prints the cause and `RawMarker`, writes the marker to the fd, and
  exits 75. The standalone CLI (`runRaw`) forks for the attempt,
  hands the child a CLOEXEC pipe as the fd, and re-spawns env mode
  only on exit 75 AND the marker over that pipe (a command's own 75
  is not enough). 3code's box child calls the low-level form: it
  must catch `RawUnavailableError`, print `RawMarker` and exit 75,
  and streamexec re-spawns when it sees the marker in the child's
  stderr.
- **What chunk 5 must arrange.** The forwarder needs a DNS listener:
  `startWallProxy(unixSockPath, ..., dnsSockPath = "")` (new optional
  parameter) or, for the per-run proxy, `proxyChild` creates
  `dns.sock` next to `proxy.sock` and `restrict(rules)` passes that
  path. `prepareRawFence` writes `nft.conf` and `resolv.conf` into
  `parentDir(proxySockPath)`, so that directory must exist and be
  writable inside the fence before Landlock (3code: the wall dir is
  not in the writable list today). `findNft()` is the parent's probe
  (`findExe("nft")`, then `/usr/sbin/nft`).
- **Unproven in this fence:** everything after `enterNetns` (the
  route, nft, the resolv.conf bind mount, the SO_ORIGINAL_DST bridge,
  the UDP relay). `tests/test_wall.nim` has an environment-gated e2e
  (userns and nft present: fence DNS answers, plain connect by name
  echoes through the redirect, a denied port is closed, the child's
  own loopback listener stays reachable); it is SKIPPED here and
  needs a host-side run. The user-facing flow is proven to the extent
  the fence allows: `sandwall rules.txt -- cmd` with nft present tries
  raw, prints the cause and the marker, and retries env mode.
- **Resolver caveats for the manual.** nsswitch lines that consult
  `resolve` or `mdns` before `dns` bypass the fence DNS (real IPs
  that are unreachable, `.local` names never reach `dns`); the
  resolv.conf bind mount follows a symlink target, and a dangling one
  is a raw failure (exit 75, env mode).
- The env-mode bridge stays up in raw mode on its own port: tools
  with their own proxy configuration still go through the forwarder.
- CHANGELOG untouched (chunk 5 lists it). `wall.nim` now exports
  `dns`.

### Carried forward from chunk 4

- **The macOS raw path is cut, by a fact and not by a choice.** A
  Seatbelt network filter takes `*` or `localhost` only as the host
  part of `(remote ip "host:port")`: a literal address makes
  sandbox-exec refuse the whole profile ("host must be * or localhost
  in network address"), so there is no per-address permit to stamp.
  Sources: caliban-sandbox's seatbelt.rs (profiles run through the real
  sandbox-exec in tests), security.stackexchange #133624 (same error),
  microsoft/mxc's seatbelt-backend.md ("an on/off switch for outbound
  network plus a loopback exception"). The plan's invariant "one
  `(allow network-outbound (remote ip "<ip>:<port>"))` line per
  stamped IP" cannot be written. `seatbelt.nim` is untouched (no DNS
  mach allow either: with nothing to permit, in-fence DNS is moot),
  and `restrict(rules, raw = true)` now raises on macOS instead of
  silently running env mode. macOS stays on the env path (`socks5h`,
  ProxyCommand). The stefani DNS probe is not needed any more.
- **The Windows elevation gate is built and still unprobed.** From
  the WFP documentation ("Access control"), the check is per object:
  `FwpmFilterAdd0` needs FWPM_ACTRL_ADD (0x1) on the filters
  container and FWPM_ACTRL_ADD_LINK (0x2) on the layer and the
  sublayer; `FwpmFilterDeleteById0` needs DELETE on the filter. The
  default descriptors give a standard user none of it: taviso's probe
  in henrypp/simplewall#680 shows the unelevated add failing with 5
  until a descriptor admits it, and succeeding once one does. The
  elevated half is `grantPermitStamping(accountSid)` (CLI: `sandwall
  setup --stamp-as ACCOUNT`): it appends an allow ACE to the DACL of
  the filters container, both connect layers and our sublayer (read
  DACL, SDDL string, append, set; idempotent). The stamping process
  grants DELETE on its own filters through the SD passed at add.
  The gate itself is now a self-command: `sandwall wfp-stamp-probe`,
  run unelevated as the spawning account, stamps and removes one
  permit through `stampPermits` itself (0 ok, 1 denied, 2 other). If
  it says denied on beck, cut: drop `permits` from the spawn path in
  chunk 5 (the env path is untouched) and document. Unknowns that
  only beck can settle: whether BFE honors the grant for a standard
  user, whether the SDDL hex rights (`(A;;0x00000001;;;S-1-5-...)`)
  parse as expected, the GetNetworkParams layout, and whether port
  53 permits revive getaddrinfo inside the fence (windows-status says
  DNS is dead there; if the block is on the Dnscache RPC path rather
  than the socket, the permits do not help: probe `nslookup` in a raw
  run).
- **Deviation from the plan: a dynamic session, no dead-PID sweep.**
  The per-run filters go in through `FwpmEngineOpen0` with
  FWPM_SESSION_FLAG_DYNAMIC, so BFE deletes them itself when the
  session ends, a crash included (documented on FwpmEngineOpen0). No
  handle file and no sweep are needed, and none is possible: an
  unelevated session is denied the enum it would need (fenceStatus's
  hint). `clearPermits` deletes by id (prompt) and closes the session;
  a refused delete is no error. Keys are `permitKey(runId, index)`
  (splitmix64 of clock+pid and index), so no two runs collide and
  BFE never sees a duplicate key.
- **The API, for chunk 5.** `wfp.permitFilters(entries, now)` turns a
  snapshot into (address, port) pairs, both generations within grace
  (`permit.liveAddresses`), deduplicated and sorted; over
  `MaxPermitFilters` (512, resolvers on 53 included)
  `stampPermits` raises `PermitStampError` (an OSError) before touching
  the engine, and so does any BFE refusal, after ending the session:
  nothing is ever half stamped. `runSandboxed(writable, cmd, read,
  denied, permits = snapshot)` stamps first, then restricts and
  spawns, and clears in a defer; it raises PermitStampError before
  anything is stamped, restricted or spawned. The box child does:
  `try: runSandboxed(..., permits = readSnapshot(path))` `except
  PermitStampError: <proxy env, runSandboxed(...) again>`. Other
  OSErrors are spawn failures as before. The standalone CLI does
  exactly that in-process and is the reference. `permit.snapshot(ps)`
  is `writeSnapshot` without the file (the CLI seeds in-process with
  `seedFromPolicy(hosts, 1500)`); `readSnapshot(path)` is the forwarder
  to box handoff. `hosts.canStamp` (= `hasAllow and not
  hasWildcardAllow`) is the policy gate: `*`, `*.suffix` and deny-only
  policies go to env mode, and on Windows an empty snapshot (nothing
  resolved) does too. 3code's setup must call
  `grantPermitStamping(sidString(account))` for the unelevated account
  that spawns (never the sandwall user: the CLI refuses that).
- **Compile-verified only, all of the Windows runtime.** mingw
  compileOnly passes for sandwall.nim, process, restrict, wall, wfp,
  winuser, winffi, rtoken; osxcross compileOnly passes for restrict
  and sandwall.nim. Consumer check: 3code's sandbox.nim, box.nim,
  wall.nim and streamexec.nim compile against this tree. Suites:
  test_permit 28, test_hosts 15, test_winwall 7, the rest at baseline.
- **beck and stefani were unreachable from this session**
  (2026-11-25): beck's sshd refused both agent keys and the documented
  `admin`/`user` passwords (password = username, per the archived
  plan-beck-bash-sandwall.md), and stefani (127.0.0.1:22222) refused
  the connection (VM down). No credentials were guessed beyond the
  documented ones.
- A drive-by: the CLI's "fence not installed" warning now checks
  `fenceStatus()` (the dedicated-user fence) instead of the legacy
  `acFenceStatus()`, which warned even with the user fence in place.
- Still true from the plan: the Windows child runs as the sandwall
  user, so the invoking user's ssh config and keys are not there; the
  raw path on Windows does not change that.

### Carried forward from chunk 5

- **The 3code wiring, as built.** `sandbox.writeWallConf(dir, port,
  sock, raw, permits, dns)` is the parent's decision in a file;
  `runtime.loadWallConf` reads it back and RESETS every `[wall]` key
  first (a file that omits a key means its default, never the previous
  file's value). POSIX: `streamexec.runStreamingBashPath` computes
  `raw = allowRaw and findNft().len > 0` (Linux only; macOS has no raw
  path), writes the conf, and gives the child no proxy env and no ssh
  shim when raw (`wallEnv(..., raw = true)` is empty). The box child
  (box.nim, Linux) calls `restrict(..., raw = true, dnsSockPath =
  wallDns)`, prints the cause and `RawMarker` and returns
  `RawFallbackExit` on `RawUnavailableError`, before exec. The parent
  sees exit 75 with a rawOut ending in the marker, writes one stderr
  line (`3code: raw egress unavailable (<cause>), retrying with the
  proxy env`) and recurses once with `allowRaw = false` (`runStreamingBash`
  is a wrapper around `runStreamingBashPath`). Windows (in-process in
  streamexec): `ensureWallProxy(..., withPermits = true)` owns a
  `PermitSet` in sandbox.nim, `permitsForSpawn(tmp)` refreshes it and
  writes `tmp/permits.json`, `runSandboxed(..., permits = readSnapshot)`
  with `putProxyEnv` + a plain re-run on `PermitStampError`.
  box.nim's Windows branch does the same from `wall_raw`/`wall_permits`
  for the standalone `3code sandbox --config` path. `sandbox.stopWall`
  closes the set. `3code setup --stamp-as ACCOUNT` carries the account
  up to the elevated re-run (`--elevated LOG --stamp-as ACCOUNT`),
  refuses the sandwall user and a missing account, and fails the
  command when the grant is refused (the fence is up by then).
- **The ssh shim is env-mode only and minimal**: `installSshShim`
  returns "" unless proxied, writes `wallbin/ssh` = `exec <ssh> -o
  "ProxyCommand=<self> wall --config '<conf>' connect %h %p" "$@"`.
  `wallSshConfig` (the -F config, the pw_dir repair, ControlMaster off)
  is deleted. `arm()` creates `~/.ssh/control` when `~/.ssh` exists
  (never `~/.ssh` itself: ssh creates that with 700). The default
  policy (both POSIX blocks) gained `allow ~/.ssh/known_hosts` and
  `allow ~/.ssh/control` after the key denies (last-match-wins).
- **Building 3code against unreleased sandwall needs a path override.**
  `nimble.paths` (gitignored, generated by `nimble lock`) pins
  sandwall 0.5.18 and is included LAST in config.nims, so it wins over
  `--path:` on the command line; the chunk temporarily pointed that one
  line at `/home/carlo/p/sandwall/src` and restored it after. The
  manifest now says `requires "sandwall >= 0.5.19"`; nimble.lock still
  pins 0.5.18 and needs `nimble lock` (and a published 0.5.19) at
  release time. `testament r` is per file; several files go through
  `sh tests/tools/test_dispatch.sh files ...`.
- **Test status in this fence (2026-11-25).** test_wall_bash: all green
  or skipped. The two netns e2e tests are now SKIPPED honestly: the
  old probe read sandwall's "continuing WITHOUT network fencing"
  degrade as "netns works" (exit 0), the new `netnsHolds` probe
  requires the token AND no degrade line. The new fallback e2e (raw
  asked, netns refused here, one re-run in env mode, the command runs
  once) runs here and passes. New and env-gated (host-side run needed):
  "netns: raw ssh by name rides the redirect; the fake-IP stays, the
  real one moves" (scripted resolver, readers on 127.0.0.2 and
  127.0.0.3, `ps.clear()` to force the re-resolve). Not provable here:
  the raw ssh e2e, the loopback regression in raw mode. Pre-existing
  environment failures, same at baseline: test_streamexec "a deny
  already covered by a denied root stays silent and unreachable"
  (the outer fence denies /proc/self/setgroups), test_sandbox_dotnet
  (~/.nuget denied by the outer fence). mingw compileOnly passes for
  sandwall.nim's consumers sandbox/box/streamexec/runtime/wall/
  defaults and the whole src/threecode.nim; osxcross compileOnly
  passes for sandbox/box/streamexec/wall.
- **beck and stefani, still deferred.** beck's sshd answers (port
  22220) and refuses both agent keys and the documented `user`/`admin`
  passwords (tried once each through sshpass, password = username);
  stefani (port 22222) refuses the connection (VM down). Nothing else
  was tried. The Windows gate is therefore still unprobed: the probe
  is `3code setup --stamp-as <spawning account>` (elevated) then
  `3code wall wfp-stamp-probe` unelevated as that account (0 ok, 1
  denied, 2 other). If it says denied on beck, the plan says cut: drop
  `permits` from the spawn path (streamexec Windows branch and box.nim
  Windows branch: pass no permits, never set `wall_raw = on`) and
  document; the env path is untouched.
- **Documented residues** (manual, Network rules): mid-command failover
  (permits fixed at spawn on Windows; Linux sees a new set on the next
  connect), DNS name leak on Windows, IP permits coarser than names,
  raw bare-IP fail-closed on Linux (an open policy denies `ssh
  192.0.2.10` in raw mode where env mode admitted it; name it or allow
  the address), host loopback unreachable in raw mode on Linux,
  concurrent Windows runs share the permit union, 512-pair cap to env
  mode, nsswitch `resolve`/`mdns` before `dns` bypass the fence DNS,
  macOS always env mode.
- **For chunk 6 (the rename)**: 3code references `startWallProxy`,
  `WallProxy`, `stopWallProxy` (sandbox.nim, tests), and its own
  `wallProxy*`, `proxySockPath`, `moveWallSock`, `ensureWallProxy`,
  `wallProxyNeeded`, `wallProxyPort`, `syncWallProxyPolicy` names
  (sandbox.nim, streamexec.nim, test_wall_bash.nim). A sandwall-side
  rename of `proxy` to `forwarder` breaks 3code's build until those
  follow; keep the sandwall names or rename both in one release.
- **A design point the user may want to revisit**: chunk 3 made the raw
  path fail-closed for bare IPs (`matchIp` only) while the env path
  (`admit`) consults the policy's own decision about a literal. With
  raw now the default on Linux for every policy including 3code's
  open `allow *`, `ssh <ip>` and `curl https://<ip>` fail where they
  used to work. Making `serveRaw` decide literals like `admit` does
  would remove the regression; it is a small change plus a test, but
  it is a policy decision, so it was documented, not changed.

### Carried forward from the beck gate run (2026-11-25)

- **beck is reachable, but it was rebuilt on 2026-11-24 and its
  documented access is stale.** Accounts are `admin` and `carlo`
  (standard user, the spawning account), password = username; `user`
  no longer exists and neither agent key is authorized. sshpass
  cannot test a password from this harness: ssh gets no tty here,
  falls back to the missing ssh-askpass and sends empty passwords, so
  a sshpass "Permission denied" says nothing (the chunk 4 and 5
  notes were wrong on that point). Use the askpass dance: a 700
  script that echoes the password as `SSH_ASKPASS`, with
  `SSH_ASKPASS_REQUIRE=force`, `-o RequestTTY=no`, stdin from
  /dev/null. `admin` lands elevated in session 0 (no UAC prompt is
  possible there), `carlo` unelevated.
- **The fence on beck is the one this run installed**:
  `3code setup --stamp-as carlo` from `C:\ProgramData\3code-gate\3code.exe`
  (fix-ci HEAD built on lucien), 8 filters, the sandwall user, the
  grant for carlo. That directory holds the gate binaries
  (`3code.exe`, `sandwall.exe`, the two OpenSSL DLLs the exe dlopens
  at startup, so they must sit next to it), and
  `C:\Users\carlo\sw-gate-work` the probe scripts (`t.ps1`, `raw.txt`,
  `env.txt`, `wall.conf`, `wall-old.conf`, `permits.json`). Nothing is
  deployed at the standard location; the other session's stub is in
  `C:\Users\admin\p\3code\build` and was not touched. One leftover:
  `C:\Users\swprobe2`, 16 locked hive files of the deleted probe
  account (no owner process, `reg unload` refused even elevated); it
  clears on reboot.
- **Three defects, found by running what was compile-verified only.**
  (1) sandwall `21b61c9`: `FwpmFilterAdd0` failed with 1307
  (ERROR_INVALID_OWNER). The permit filter's descriptor said
  `O:BAG:BAD:` and a standard user cannot assign Administrators as the
  owner. `permitFilterSddl(callerSid)` makes the caller the owner and
  names no group; the probe passes unelevated and elevated. (2) Same
  commit: `dnsServers` read `GetNetworkParams`' FIXED_INFO with
  136-byte name fields. The header (and Win11 26100, measured: the
  first resolver's text at 280, NodeType at 320) has `MAX_HOSTNAME_LEN
  + 4` = 132, so the list starts at 272. The walk took the first
  server's text as its `next` pointer: SIGSEGV on every raw run, even
  for `cmd /c ver`. The walk is now `dnsServersIn` (portable, its
  offsets pinned by a test) and the buffer is checked against
  `sizeof(FixedInfo)`. (3) 3code `09badfed`: `writeWallConf` wrote the
  path keys with `quoteShell`. Nim 2.4 leaves a plain path bare, and
  `parseCfg` tokenizes a bare value as a symbol whose set has neither
  colon nor space, so a Windows path came back as `C`; a POSIX path
  with a space or a quote came back mangled too. The paths are
  parseCfg string literals now (`cfgString`).
- **Also fixed, same run.** sandwall `ed1d20c`: the CLI warned "fence
  is not installed" on every unelevated Windows run, because
  `fenceStatus()` reports a denied enum as not installed; it prints a
  one-line note when the status is unknown and keeps the warning for
  a known-absent fence. 3code `385bec95`: an unreadable snapshot ran
  the command with neither permits nor proxy env, no network at all;
  it now takes the refused stamp's fallback.
- **What ran on hardware, and what did not.** Ran: the elevated half
  of the grant; the probe as granted, ungranted and elevated
  accounts; the sandwall CLI in raw and env mode; `3code sandbox
  --config` raw, and both fallbacks (unreadable snapshot, refused
  stamp as the ungranted account). Did not run: the bash tool's own
  launch, streamexec's Windows branch (`ensureWallProxy(withPermits)`,
  `permitsForSpawn`, the in-process `runSandboxed`); it needs msys64
  and the TUI on beck, neither deployed. The manual, the README and
  the sandwall changelog say exactly that.
- **A fact that corrects an open question**: name resolution works
  inside the fence in env mode too, with no port 53 permit at all
  (the DNS client service does the query). The resolver permits stay
  as designed, harmless; the Windows name leak is what it is.
- **Left as found**: 3code's `nimble.paths` points at
  `/home/carlo/p/sandwall/src` since 23:41:49, set by the other
  session working in the same checkout (the btw work, committed as
  `7b9c6125`). This run restored its own override before that and did
  not touch the file afterwards. Put the 0.5.18 pin back, or run
  `nimble lock` once 0.5.19 is published, when nobody is building
  against the tree. Commits in 3code used pathspecs (`git commit --
  <files>`) for that reason; keep doing that while two sessions
  share the checkout.
- **Still open**: stefani is down (connection refused), so macOS
  stays compile-verified; the Linux host-side netns runs and the
  nft-hidden parent run; the rename (impl-6); the bare-IP fail-closed
  decision.
