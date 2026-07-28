# Chunk 3: POSIX fences (Linux netns + macOS Seatbelt)

## Goal

The kernel half of the wall on POSIX: confine the current thread's
egress to loopback-only (Linux) or loopback-to-proxy (macOS), so the
only way off the machine is the chunk-2 proxy. Plus the tiny SOCKS5
client used as git's ProxyCommand helper.

## Read first

- `src/sandwall/mask.nim` (existing usernamespace: unshare
  CLONE_NEWUSER|CLONE_NEWNS, uid_map setup - chunk 3 EXTENDS this
  pattern with CLONE_NEWNET)
- `src/sandwall/restrict.nim` (public entry, dispatch shape)
- `src/sandwall/seatbelt.nim` (profile generation)
- `src/sandwall/wall/proxy.nim`, `src/sandwall/wall/hosts.nim`
- `impl-plan.md` decisions 5/6/8; `firewall-research.md` (why proxy
  architecture, Landlock limits)
- cplt design issue (in research): netns + unix-socket bridge shape.

## Background you must respect

- Landlock CANNOT do this: its net rules are port-only, and even those
  are bypassable via TCP Fast Open (sendto MSG_FASTOPEN skips the
  connect LSM hook). Do not build a Landlock port-fence mode.
- The Linux fence is: same unshare as mask.nim PLUS CLONE_NEWNET. A
  fresh netns has only `lo`, and it starts DOWN; bring it up with an
  SIOCSIFFLAGS ioctl (works: we are root-mapped inside the userns and
  the netns is owned by it). No external interface exists, so all
  non-loopback egress fails at the kernel. This also kills UDP and DNS
  (decision 8) with zero extra code.
- The proxy then cannot be reached over TCP loopback from the parent
  netns... except the fence and proxy run in the SAME netns in our
  architecture: 3code forks the box, the box enters the netns, and the
  box ALSO starts the proxy thread inside the netns (the proxy's
  upstream connects must work!). WRONG - the proxy would be fenced
  too. The correct shape (from the plan and srt/cplt):
  - Parent (unfenced) runs the proxy on HOST loopback AND on a unix
    socket at a path inside the sandbox's writable tree (e.g.
    `<tmpdir>/sandwall-proxy.sock`). A filesystem unix socket crosses
    netns boundaries because it is a file, not a network object.
  - Inside the fenced child, a forwarder listens on 127.0.0.1:PORT and
    splices each accepted connection to the unix socket path.
  - Proxy env vars point at 127.0.0.1:PORT inside the fence.
  Implementation detail: the proxy (chunk 2) gains an optional extra
  listener on a unix socket path - same accept loop, family AF_UNIX,
  peer address checks skipped (filesystem perms are the ACL).

## Instructions

### 1. `src/sandwall/wall/connect.nim` - SOCKS5 client helper

`proc socksConnect*(proxyPort: uint16; host: string; port: uint16):
int` - connect to 127.0.0.1:proxyPort, do the SOCKS5 no-auth handshake
for (host, port), then act as a byte pump between stdin/stdout and the
socket (this is exactly what git's `ProxyCommand` needs:
`GIT_SSH_COMMAND='ssh -o ProxyCommand="3code wall connect %h %p"'`).
Exit codes: 0 clean EOF, 1 connect/handshake failure (message to
stderr). Pure stdlib (`std/net` + `std/posix` poll loop). Keep it
under 120 lines. Unit-test the handshake against the chunk-2 proxy
test fixture (extend tests/test_proxy.nim or new test_connect.nim).

### 2. `src/sandwall/wall/netns.nim` (linux only)

```nim
proc enterNetns*() =
  ## Unshare user+mount+net namespaces (uid-mapped, as mask.nim) and
  ## bring `lo` up via SIOCSIFFLAGS. Idempotent-safe to call after
  ## maskDenied (which already unshared user+mount): detect "already
  ## in a userns we created" by attempting the unshare and tolerating
  ## EPERM only when /proc/self/uid_map already maps us. Simplest
  ## correct approach: refactor mask.nim so BOTH maskDenied and
  ## enterNetns funnel through one `ensureUserns(extraFlags: cint)`
  ## that unshares exactly once per process (module-level var).
  ## Raises OSError when unprivileged userns is unavailable; callers
  ## follow the established warn-and-continue posture.

proc bridgeToUnix*(listenPort: uint16; sockPath: string)
  ## Listen on 127.0.0.1:listenPort inside the netns; every accepted
  ## connection is spliced to the AF_UNIX socket at sockPath (the
  ## host-side proxy listener). Runs on its own thread; call BEFORE
  ## exec. One thread per accepted connection, same splice loop shape
  ## as the proxy.
```

Ordering contract (document in module header): in the fenced child
the sequence is maskDenied(denied) -> enterNetns() -> spawn
bridgeToUnix thread -> exec. Landlock fs rules must still allow
connect()ing to the unix socket path: the socket lives in a writable
tmp dir so it is covered; document this requirement.

### 3. macOS: extend `seatbelt.nim`

Add an `egress: bool` parameter to `restrictImpl` (default true =
current behavior, network untouched). When `egress == false`, append
to the generated profile:

```
(allow network-outbound (remote ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))
```

placed BEFORE the profile's catch-all deny, and do NOT emit any other
network rules (the default-deny covers the rest). No mDNSResponder
exception: DNS stays fenced, the proxy resolves (decision 8). On
macOS the proxy runs on the HOST loopback and the sandbox reaches it
directly (no bridge needed) - env vars point at the host 127.0.0.1
port, which Seatbelt permits via the rule above.

### 4. Public API: extend `restrict.nim`

```nim
proc restrict*(writable: openArray[string]; read: openArray[string] = [];
               denied: openArray[string] = [];
               fenceNet: bool = false; proxyPort: uint16 = 0;
               proxySockPath: string = "")
```

- `fenceNet = false` (default): exactly today's behavior. Existing
  callers (3code fs-only box) are unaffected.
- Linux with `fenceNet = true`: enterNetns() after maskDenied; if
  `proxySockPath.len > 0` spawn bridgeToUnix(proxyPort, proxySockPath)
  thread. On OSError from enterNetns: print the warn-and-continue
  message to stderr (`sandwall: network fence unavailable ...;
  continuing WITHOUT network fencing`) and continue unfenced
  (matches mask.nim posture and locked Q3).
- macOS with `fenceNet = true`: pass egress=false down to
  seatbelt.restrictImpl. proxySockPath unused.
- Old kernels / no userns: same warn-and-continue.
- Windows: parameter accepted, ignored for now (chunk 4); document.

Update the module header of restrict.nim to describe the fence.

### 5. Tests

- `tests/test_wall.nim` (linux-only sections guarded with
  `when defined(linux)`):
  - enterNetns: after entering, `socket connect` to 127.0.0.1 on a
    port where a listener was started BEFORE entering still works
    (same-netns loopback alive), and connecting to any external
    address fails fast (use a documentation IP like 192.0.2.1 with a
    short timeout - expect ECONNREFUSED/ENETUNREACH/EACCES, any
    failure passes; the point is it does NOT connect).
  - bridge: parent starts the chunk-2 proxy listening on BOTH
    127.0.0.1:0 and a unix socket in tempdir with policy `+127.0.0.1`;
    child (fork) enters netns, starts bridge to the unix socket,
    performs a SOCKS5 handshake via 127.0.0.1:bridgePort to a
    parent-side echo server -> echo returns. This is the end-to-end
    proof of the whole Linux architecture.
  - Do these in forked children (the test process must stay
    un-fenced). Follow the fork/wait pattern in tests/test_sandbox.nim.
- macOS section (compile-guarded, verified later on the stefani VM per
  3code's osx-testing notes): generated profile contains the loopback
  allow lines when egress=false. Pure string test of the profile
  builder - factor profile generation into a proc that returns the
  string if it is not already.
- Wire test_wall.nim and test_connect.nim into sandwall.nimble test
  task.

## Verification

- `nimble test` green on Linux.
- Manual: `nim c -r` a scratch main that restricts with fenceNet and
  execs `curl -m 3 https://example.com` -> fails (no route); and
  `curl -m 3 -x socks5://127.0.0.1:BRIDGE https://example.com` with
  the bridge+proxy up and `+example.com` in policy -> succeeds.
  Delete the scratch main.
- Commit: `posix network fence: linux netns bridge, macos seatbelt egress`.

## Next step

When complete and verified, call clear with:
- summary: "Chunk 3 done: netns fence + unix bridge + connect helper
  on Linux (tested end-to-end via forked child + proxy + echo),
  Seatbelt egress=false profile on macOS (string-tested only),
  restrict() gained fenceNet/proxyPort/proxySockPath, tests green,
  committed."
- instructions: "Read /home/carlo/p/sandwall/impl-4.md and execute it."
