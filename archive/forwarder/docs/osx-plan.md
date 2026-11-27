# Plan: macOS raw egress with no env mode

## The rule this plan follows

There is no env mode. No CONNECT, no SOCKS, no ProxyCommand, no `socks5h`,
no `wall connect`, no forwarder hop for the child. The child connects
straight to the address it resolved. The fence is kernel-side, on every
platform.

Two hard requirements from the design review:

1. **Only what runs in the box is restricted.** Nothing outside the box
   changes behavior while a run is live.
2. **Strictly per process.** The fence attaches to the child's process
   tree and nothing else.

The policy vocabulary that matters here: exact hosts, and `*` meaning all
open. `*` is trivially stampable (stamp nothing), so the old "wildcards
cannot be enumerated, fall back to env mode" gate is dead everywhere.

## Why Seatbelt alone cannot do it

Seatbelt network filters accept only `*` or `localhost` as the host part
of `(remote ip "host:port")`. A literal address makes `sandbox-exec` refuse
the whole profile. Verified, three sources in impl-plan.md. On macOS the
per-address decision cannot live in Seatbelt.

## The mechanism space, checked

| mechanism | per process? | verdict |
|---|---|---|
| Seatbelt per-IP | no | profile language takes `*` or `localhost` only |
| pf match by pid | no | pf matches sockets by uid/gid; pid is not a pf notion |
| pf match by uid | no | whole user fenced, fails requirement 1 |
| Endpoint Security framework | yes | needs `com.apple.developer.endpoint-security.client`: Apple account, provisioning profile embedded in the binary. A self-built CLI cannot ship it |
| DYLD interposition of `connect()` | weak | ignored for Apple platform binaries (`ssh` is one); any static binary bypasses it |
| utun + per-socket `IP_BOUND_IF` | per socket | nothing can force a child onto the interface from outside |
| dedicated sandbox uid (the Windows route) | yes | breaks `~` and key ownership: `~/.ssh` is 0600 user-owned, git writes to a home it no longer owns |
| **primary gid marker + pf** | **yes** | **the only kernel-level per-process network scoping macOS has** (probe osx-1 passed) |

## Prior art: how the real macOS firewalls do it

- **LuLu** (Objective-See, open source) and **Little Snitch** (obdev) both
  moved from socket-filter kexts (`sflt_register`, deprecated, blocked
  since macOS 12) to Apple's **Network Extension content filter**
  (`NEFilterDataProvider`): the kernel holds each new flow, the extension
  returns allow/drop, keyed by the flow's audit token (pid). Truly
  per-process, but it requires the
  `content-filter-provider-systemextension` entitlement plus a one-time
  user approval in System Settings. An Apple developer account and a
  signed, entitled binary: not shippable from a self-built CLI.
- **AI coding sandboxes** (Codex CLI, Claude Code) use `sandbox-exec` /
  Seatbelt exactly as sandwall does, and sidestep per-address by turning the
  network off entirely, or by proxying. Codex's proxy is the env-mode
  family we deleted: an HTTP proxy on 3128 and SOCKS5 on 8081, the policy
  enforced by name, `HTTP_PROXY`/`HTTPS_PROXY` in the command env, and an
  ssh `ProxyCommand` shim, with a stream of follow-up fixes for stale env
  restoration (#17271) and per-command proxy settings (#62386). Its
  structural flaw is our reason for leaving: any client that ignores proxy
  env vars (an open issue, #37329) bypasses the policy entirely, so it is
  not a fence. Everyone crawls back to proxying because it is the only
  option that works without an entitlement; the gid marker plus pf is the
  first exit from that trap.
- **pf-based tools** (hand-rolled `pfctl` scripts, the older
  sandboxed-app literature) scope by uid, which fails requirement 1.

So the landscape is: entitled system extension (per process, needs
Apple), or uid-wide pf (not per process), or no network. Nobody ships
per-process, per-address, entitlement-free egress on macOS. The gid
marker plus pf is the gap: per process like LuLu, no entitlement like
pf.

## The design: pf owns the network, Seatbelt owns the files

macOS ships pf, an in-kernel L3/L4 filter. Per-address, per-port,
in-kernel, no entitlement, no Apple approval, no Network Extension.

Division of labor:

- **Seatbelt** keeps doing what it does now: files, mach, unix sockets,
  process ops. Its profile emits `(allow network-outbound)` and
  `(allow network-inbound)` unconditionally (the existing egress = true
  branch). On macOS, Seatbelt stops pretending to gate the network.
- **pf** gates the network by address for exactly one process tree.

## The marker: one primary gid, per run, child only

pf reads the socket's credential at socket creation and takes
`kauth_cred_getgid(so_cred)`, the **primary gid** (XNU
`bsd/netinet/in_pcb.c`, `in_pcblookup_hash_exists`). Not the supplementary
list: a supplementary group does not match, verified by probe. So the
marker is the child's primary gid, set with `setgid(marker)` followed by
`setuid(user)`, before exec. The rules, in this order:

```
pass out quick on lo0 group <gid>
block return-rst out quick inet  proto tcp to ! <table> group <gid>
block return-rst out quick inet6 proto tcp to ! <table6> group <gid>
```

The rules live in one child anchor per run, `com.sandwall.runs/<id>`, and
end with an explicit pass so permitted traffic is decided inside the child
anchor (the block is `to ! <table>`, so a permitted packet falls through
to the next rule):

```
pass out quick on lo0 group <gid> [port <loopback ports>]
block return-rst out quick inet  proto tcp to ! <table>  group <gid>
block return-rst out quick inet6 proto tcp to ! <table6> group <gid>
block return     out quick inet  proto udp to ! <table>  group <gid>
block return     out quick inet6 proto udp to ! <table6> group <gid>
pass out quick group <gid>
```

The main ruleset calls `anchor "com.sandwall.runs/*"`, which evaluates the
child anchors. (The probe's own rules sat in the anchor itself, which
`anchor "x/*"` does not evaluate; that is why the first runs missed.)

Facts from probe osx-1 (stefani, macOS 14.8.7, all passed):

- Marked process: connect fails fast (`000`), the rule counter shows the
  packet. Unmarked control at the same moment: `301`. Loopback from the
  marked process: `200`. Requirements 1 and 2 hold.
- The child's uid, HOME, home readability and file ownership are
  unchanged: a file it creates is still `501:20` (group `staff`). The
  marker shows only as the egid in `id`. Nothing outside the box carries
  it.
- The ruleset must be reached from the main ruleset by the **exact**
  anchor name: `anchor "com.sandwall.runs/*"` skips the anchor's own
  rules; `anchor "com.sandwall.runs"` works. The first two probe runs
  were silent misses for this reason.
- `user`/`group` are filter options at the end of the rule, not part of
  the `from` clause: `... to ! <table> group <gid>`, not
  `from group <gid>`. pfctl rejects the latter.
- Rule order matters: the `quick` lo0 pass comes before the `quick` block,
  or loopback is blocked too.
- Do not call `setgroups` in the drop: macOS `setuid` re-derives the
  supplementary groups from the account, and an earlier `setgroups` resets
  the real gid. The sequence is exactly `setgid(marker)`, `setuid(user)`.
- Probe osx-1b, the ssh-with-keys run: stefani had no private key, so one
  was generated (`~/.ssh/id_ed25519` on stefani) and its public half
  authorized on jules (`root@78.47.197.142`). Inside the fence, with
  jules's address in the table and everything else denied:
  `ssh root@78.47.197.142` answered `FENCED_OK as root`; the same process
  got `000` on curl and `Connection refused` on ssh to a denied address;
  the block rule counted exactly the two denied SYNs. No shim, no env
  vars, no proxy hop. Script: `osx1b-ssh-probe.sh`.
- Probe osx-1c/1d, escape attempts from the marked process:
  - `setgid(20)` and `setgroups([20])` are refused (`EPERM`) even though
    the account is a member of `staff`, and `setuid` re-derived the
    supplementary groups: the marker is the real, effective and saved gid
    and the child cannot shed it. A forked grandchild inherits it and is
    fenced (`grandchild 000`).
  - **UDP was a hole** in the tcp-only ruleset: a datagram to a live echo
    listener on jules came back (`ECHO:hello`). The udp rules above close
    it (same probe, no reply after the rule). UDP matters for more than
    DNS: QUIC, any UDP exfil.
  - `/usr/bin/ping` reached 1.1.1.1 from the marked process. Not a fence
    failure: `ping` is setuid root, so it left the marker by privilege.
    Seatbelt still applies across that exec; non-TCP/UDP traffic cannot
    be credential-matched by pf at all (the gid lookup is tcp/udp only),
    and opening raw sockets needs privileges the child lacks. Documented
    in Known limitations.
- Seatbelt precedence, probed with `sandbox-exec`: a `deny` wins over a
  later `allow`, so `(deny network-outbound (remote ip "localhost:*"))`
  followed by `(allow ... "localhost:18099")` denies 18099 too. Seatbelt
  can decide whether the child gets loopback, but cannot scope it by port.
  pf can (`port != <list>`). See Loopback below.

Only root can `setgid` to an arbitrary gid, so the gid is planted by a
privileged exec broker. That is the one-time and per-run cost of the only
workable mechanism; the alternatives above cost more or fence nothing.

## Pieces

### 1. `sandwall setup` on macOS (one-time, elevated)

Installs a LaunchDaemon (`com.capocasa.sandwall.plist`, `RunAtLoad`,
root) and records the installing account's uid. It touches no pf state
itself and never edits `/etc/pf.conf`; the daemon arranges pf at start,
because none of it survives a reboot: Apple does not enable pf at startup
(the file says components enable it themselves with `-E`), and a
`pfctl -f` load is runtime-only. Reported, exits nonzero on failure, same
posture as the Windows gate.

The block rules are not scoped to an interface (a `on en0` clause would
let VPN/utun traffic escape); tcp uses `return-rst` so a denied connect
fails fast instead of hanging.

### 2. The daemon: `sandwallpf`

- **At start, before serving:** enable pf with `pfctl -E` (reference
  counted, so coexisting services keep their enable) and make sure the main
  ruleset calls `anchor "com.sandwall.runs/*"` and
  `anchor "com.sandwall.orphans"`. If the lines are missing, read the
  live ruleset (`pfctl -sr`, `-sn`, `-sm`), append the two lines, reload
  once. Never `pfctl -F all` on the main ruleset (Apple's own comment:
  system services insert anchors dynamically; a flush drops them) and
  never write `/etc/pf.conf`. A user `pass out quick all` above our lines
  would override the fence; the daemon checks for that and reports it.
- **Fail-closed for orphans:** at start it loads `com.sandwall.orphans`
  with `block drop out quick group <lo-hi>` for the whole marker range,
  placed after the runs anchor. A child whose run state was lost (daemon
  killed, restarted) hits no child anchor and falls to this: blocked,
  not unfenced. The range is owned by the daemon and checked against the
  group database, so nobody else matches it.
- Owns the anchor `com.sandwall.runs/*`, one child anchor and one gid per
  live run. Gid range owned by the daemon (e.g. 42400-42499, reused after
  `end`; the range caps concurrent fenced runs, documented). Before
  allocating a gid the daemon checks `getgrgid` returns nothing and skips
  any gid that exists on the system, so the marker never collides with a
  real group (it would widen the fence to everyone in that group).
- IPC: unix socket `/var/run/com.sandwall.sandwallpf.sock`, 0600
  root:wheel. Caller authenticated by `LOCAL_PEERCRED`; uid must equal the
  uid recorded at setup. One account, same as the Windows grant.
- Operations:
  - `begin(gid, snapshot) -> runId`: create the child anchor, load the
    block/pass rules above, fill the v4 and v6 tables from the snapshot.
  - `refresh(runId, snapshot)`: replace table contents (address
    rotation, same policy).
  - `end(runId)`: flush the child anchor and tables.
  - `exec(runId, cmd...)`: `fork`, `setgroups` to the marker gid plus the
    `setgid(marker)` then `setuid(user)`, no `setgroups`, `execvp`.
    What it execs is the box child (3code's own spawn with its args),
    which applies Seatbelt in-process exactly as today and then execs the
    tool; the daemon never needs to understand rules, and the file fence
    stays unchanged and monotonic.
  - Sweep runs whose `expires` passed, so a crashed parent cannot leave a
    run fenced forever (the child is then caught by the orphan block).
    On daemon start, flush the `com.sandwall.runs` anchor: stale child
    anchors are gone, orphans fall to the catch-all.

The IPC surface never grants privilege: a same-uid caller can get commands
exec'd, but only as itself with a marker gid and a fence, never as root.

Order inside `exec`: stamp pf, `setgid(marker)`, `setuid(user)`, exec the
box child, which applies Seatbelt and execs the tool. A failure before
exec means the child never runs. With a `*` policy the parent never
called `begin`, so `exec` runs without a marker: plain gid, no fence,
which is exactly what `*` means.

### 3. The snapshot is unchanged

`wall/permit.nim` already produces `{host, ports, current, previous,
expires, prevUntil}` with a seeded set. The daemon takes the same JSON the
Windows backend takes. No new type, no new format.

### 4. Seatbelt profile: network off except loopback-by-policy

In raw mode `buildProfile` emits `(allow network-outbound)` for the
internet (gated by pf, so the profile must not be read as the network
fence) and the loopback rule from the policy: `(deny network-outbound
(remote ip "localhost:*"))` when no localhost rule exists, nothing extra
when one does (pf scopes the ports). The `egress = false` branch
(loopback only, the forwarder hop) goes away with the env path. No
per-address lines are attempted, per the fact above.

### 5. 3code wiring

- `writeWallConf` gains `raw = on` on macOS whenever the daemon socket
  exists and answers `ping`. No policy-shape gate: `*` stamps nothing,
  exact hosts stamp addresses.
- The spawn routes through `sandwallpf exec`; the parent calls `begin`
  before and `end` on child exit (refresh on the existing schedule). The
  `ensureWallProxy`/`wallEnv`/`installSshShim` machinery is deleted from
  the macOS path, along with the env path everywhere else.
- Fallback: none to env. Daemon absent, stamp refused, or exec failed:
  the run fails closed with the marker line and the reason. The
  `raw = off` respawn is gone.

## Loopback: a local proxy is an exit, so it is policy-driven

pf passing `lo0` for the marker would let the child reach any listener on
the host, including a local HTTP or SOCKS proxy, which is an exit around
the address table. There is no network namespace on macOS to separate the
child's loopback from the host's. Resolution, in two layers:

- **Seatbelt decides whether loopback exists for the child.** The policy
  has no `localhost`/`127.0.0.1` host rule: the profile emits
  `(deny network-outbound (remote ip "localhost:*"))` and the child has
  no loopback at all. A policy that allows a localhost host switches
  loopback on.
- **pf scopes it by port when it is on.** The lo0 pass carries the ports
  from the localhost rules (`port { 5432, 8080 }`), and a
  `block return-rst out quick on lo0 group <gid>` follows. A localhost
  rule without a port (all ports) opens every listener on the host,
  proxies included; the manual says so next to the rule.

Inbound to the child's own listener is unaffected (the listening socket
carries the marker, the peers do not).

## DNS on macOS: say it plainly

No fake-IP fence on macOS. The child uses the system resolver through
`mDNSResponder` over a unix socket; pf cannot see it and Seatbelt cannot
gate it without breaking resolution for the run. Consequences, documented:

- Name queries leak, same as the documented Windows leak. Linux is the
  only platform with no DNS channel at all.
- Denies that matter should not rely on the raw path on macOS: an allowed
  name sharing an address with a denied one is reachable. The manual
  already has the IP-permit caveat section.

Given there is no env mode, this is the price of the design on macOS.

## `*` means all open, everywhere

- macOS: `*` means `begin` is not called; Seatbelt already allows
  network. Nothing to enumerate, nothing to stamp.
- Windows: the same. The old "at least one exact rule, no wildcard" gate
  for `raw = on` collapses to "the WFP grant is in place".
- Linux: unchanged; raw is the default and `*` is the trivially open case.

## Cleanup and failure

- Child exit: parent calls `end`; the child anchor, tables and gid go.
- Parent crash: `expires` bounds the damage; the sweep reaps the run.
  The still-running child keeps its gid and is then caught by the orphan
  block (fail-closed mid-run, acceptable, documented).
- Daemon killed and restarted: the child anchor is gone on restart; the
  orphan block fences the orphan from the first packet after the flush.
  There is no window in which an orphan is unfenced.
- Daemon down at spawn: the run fails closed with the reason. Never env,
  never unfenced.
- User's own pf ruleset: the daemon adds its two anchor lines to the live
  ruleset once, without flushing, and leaves the rest alone.

## Verification, on stefani, in order

1. Done, probes osx-1 and osx-1b, both green on stefani; findings in
   The marker above.
2. Unit: snapshot to anchor text; gid allocation and reuse; the expiry
   sweep with a faked clock.
3. End-to-end: `ssh host` permitted and denied; `*` policy with no stamp;
   a denied name on a shared IP, documented as reachable; two concurrent
   runs with different policies, both correctly and independently fenced;
   UDP to a permitted and a denied address; loopback with no localhost
   rule (refused), with a port rule (that port open, another refused).
4. Crash runs: kill the parent, check the sweep; kill and restart the
   daemon while a child is live, check the child hits the orphan block;
   daemon down, check the next spawn fails closed.

State after osx-4: step 2 is done (unit, Linux). From step 1 onward on
macOS, what ran without root: both Seatbelt profiles under
`sandbox-exec` (no loopback: `127.0.0.1` gives 000 and 1.1.1.1 gives
301; loopback: 200), every rule set through `pfctl -n`, and the CLI
without the daemon (`setup --status` says not installed; a host-rule
policy exits 125 with the marker; a filesystem-only policy runs as
before). **Not run: the daemon as root.** sudo on stefani needs a
password this session does not have, so step 3, step 4, and the first
`pfctl -E` have never executed. The list for the first root run:
`sudo sandwall setup`, `sandwall setup --status`, then the e2e cases
in order. Unproven and worth a first look: the `xucred` layout
(Nim object, the SDK keeps the struct private), the main-ruleset
append against the live `/etc/pf.conf`, the `com.sandwall.runs/*`
flush semantics, and whether `pass in` on lo0 creates state for the
child's listener.

## Known limitations (document, do not paper over)

- **Non-TCP/UDP cannot be credential-matched by pf** (the gid lookup is
  tcp/udp only). Raw sockets need privileges the child lacks; setuid
  binaries like `ping` leave the marker by privilege, as they leave any
  unprivileged fence. Seatbelt still applies to them across exec.
- **A localhost rule without a port opens every listener on the host**,
  local proxies included. That is the macOS stand-in for Linux's netns
  separation and it is coarser.
- The name leak and the shared-IP caveat from the DNS section.

## Chunks

- **osx-1**: done. Both probes passed on stefani (macOS 14.8.7); findings
  folded into The marker above. Script: `osx1-probe.sh` at the repo root.
- **osx-2**: done, unexercised as root. `pfSetup` (plist, uid record,
  `launchctl bootstrap`), `pfUninstall`, `pfFenceStatus`; `sandwall
  setup [--status|--uninstall]` on macOS.
- **osx-3**: done, unit-tested with a fake pfctl on Linux. `wall/pf.nim`
  is the decision half (rule text, gid allocation, lease sweep,
  `handle`), `wall/pfdaemon.nim` the socket half (`serve`,
  LOCAL_PEERCRED auth on macOS, SO_PEERCRED on Linux). Findings:
  - pf takes `port` only after a `proto`, and `inet` is one family, so
    the lo0 port list is four rules (tcp/udp, inet/inet6).
  - `block return-rst` on lo0 without a proto is a syntax error
    (`return-rst can only be applied to TCP rules`); the lo0 block is
    `block return out quick on lo0`, which covers udp too.
  - `pass in quick on lo0 group <gid>` keeps the child's own listener
    answerable when lo0 is scoped: its replies ride the state of the
    inbound rule instead of hitting the lo0 block.
  - `pfctl -n -f -` runs unprivileged, so every rule set was syntax
    checked on stefani without root.
- **osx-4**: done, run unprivileged on Linux only. `sandwallpf exec`
  passes the caller's stdio by SCM_RIGHTS (the CMSG macros are not
  linkable from Nim, the header arithmetic is written out), the child
  `dup2`s, `setsid`s, `chdir`s, `setgid(marker)`, `setuid(caller)`,
  execs. An unknown run id is refused, never exec'd unfenced. The
  daemon thread holds the run until the child exits and answers the
  exit code; a live child also keeps its run out of the sweep. The
  child (`sandwall --pf-child PROJECT POLICY -- CMD`) applies Seatbelt
  with `loopback = loopbackPolicy(hosts).enabled` and execs.
  Unprivileged, `setgid` fails and the child exits 126 with the reason,
  before running anything.
- **osx-5**: 3code: `raw = on` on macOS, spawn through the broker, and the
  deletion of the env path on all three platforms (the "no env mode" sweep
  Linux and Windows still owe).
- **osx-6**: docs, manual, both changelogs, the DNS paragraph above.

## Open questions

- Ports in the pf rule for the internet: the permit entries carry ports
  and loopback already honors them. First cut for non-loopback is
  address-only (`to <table> port <p>` per entry is the follow-up when a
  policy needs it).
- Inbound: the fence is egress-only on all platforms. Keep it egress-only.
- Gid range size vs concurrent runs: 42400-42499 is 100 concurrent fenced
  runs, far above anything 3code does; shrink or grow at will.
