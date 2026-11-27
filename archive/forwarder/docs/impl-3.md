# Chunk 3: Linux fence DNS + fake-IP + nft + raw path

## Goal

Plain `ssh`, `telnet`, `scp` inside the netns with no env vars and no
shim: fence DNS with stable fake-IPs, nft redirect into the forwarder, and
the forwarder's raw path fake-IP -> name -> real IP per connect.

## Read first

- `src/sandwall/wall/netns.nim` - bridge process, `serveBridgeConn`,
  `bridgeToUnix`, PDEATHSIG lifetime.
- `src/sandwall/wall/proxy.nim` - where the raw path lands.
- `src/sandwall/wall/permit.nim` - `getOrResolve`, `matchIp`.
- `src/sandwall/mask.nim` - `ensureUserns` always creates the user+mount
  namespace; `restrict.nim` ordering.
- `~/p/3code/src/threecode/sandbox.nim` - `wallEnv`, `wallSshConfig`,
  `installSshShim`, `writeWallConf`.

## Invariants (do not deviate)

- **fake-IP -> name only.** The allocator lives in the forwarder, which
  outlives the fence; a binding is stable for the forwarder's lifetime,
  not the netns's. Pool `198.18.0.0/15`, lowest-free, never released.
- **Fence DNS answers by policy decision, not rule coverage.** Allowed
  (exact, wildcard, open `*`, deny-only default-allow) -> fake-IP;
  denied -> NXDOMAIN; resolver failure -> SERVFAIL. A -> fake-IP;
  AAAA -> NOERROR with no answers (NODATA); other types -> NOTIMP.
  Echo the qname case; ignore EDNS0 OPT. Check the name with port 0 (any
  port); the port is checked at connect.
- **Redirect is TCP only** (`meta l4proto tcp`). TCP to non-loopback
  (which includes the fake pool) -> raw port; 127/8 passes. The child's own
  loopback services keep working; host loopback via `+localhost` no longer
  does in redirect mode (documented).
- **The bridge reads `SO_ORIGINAL_DST`.** The host-side forwarder cannot:
  it is beyond the unix splice. The bridge's raw listener prepends
  `SWRAW <ip> <port>\n` on the existing `proxy.sock` stream; the
  forwarder detects the prefix. Proxy and raw listeners use **separate
  netns ports**, so there is no self-destination ambiguity.
- **DNS rides a separate AF_UNIX SOCK_DGRAM** (`dns.sock`), not a
  multiplexed stream. The bridge forks a DNS relay process (UDP 53 inside
  the netns <-> `dns.sock`); PDEATHSIG.
- **resolv.conf:** the mount namespace exists; bind-mount a generated file
  over `/etc/resolv.conf` (`nameserver 127.0.0.1`). On failure: exit 75.
- **Mode decision is the parent's.** The parent probes `nft`
  (`findExe` plus `/usr/sbin/nft`) and writes `raw = on|off` into
  wall.conf. The child applies; on any redirect failure it logs one line
  and **exits 75 before Landlock/exec**, printing a marker line
  (`sandwall: raw unavailable, retrying env`); the parent treats 75 as the
  signal only when the marker is present and re-spawns with `raw = off`.
  No half-applied fence.
- **The raw path re-checks the policy.** Fake-IP -> name -> check
  `name:port` against the HostList before dialing; bare IP -> `matchIp`
  plus a port check. Unknown -> DENY log. A bare IP that no allowed
  name has resolved yet is denied (lazy set; fail closed).

## Instructions

1. DNS codec in `src/sandwall/wall/dns.nim`: parse header/question/qname
   (no compression needed for queries), build A/AAAA/NXDOMAIN/NOTIMP/
   SERVFAIL, echo qname bytes, ignore OPT. Testable without the fence.
2. Fence DNS responder in the forwarder: accept on `dns.sock` (unix
   datagram), consult the current policy, allocate/return the fake-IP,
   record the binding. Add the socket to the Linux poll loop; use the same
   policy reload as TCP.
3. Fake-IP allocator: stable map name -> `198.18.x.y`, lowest-free,
   parameterized pool size for the exhaustion test.
4. Bridge: second listener `rawPort` in the netns; `serveRawConn` reads
   `SO_ORIGINAL_DST`, writes `SWRAW <ip> <port>\n` to `proxy.sock`, then
   splices. DNS relay process: UDP `127.0.0.1:53` <-> `dns.sock`.
5. resolv.conf bind mount plus the nft ruleset (substitute RAWPORT with the
   bridge's raw listener port):
   ```nft
   table ip sandwall_fwd {
     chain out {
       type nat hook output priority -100;
       meta l4proto tcp ip daddr != 127.0.0.0/8 redirect to :RAWPORT
     }
   }
   ```
   Netns-local, no cleanup. Load before Landlock (nft needs exec/read).
6. Raw path in `proxy.nim`: detect `SWRAW `, parse the original dst. Fake
   pool -> name -> policy check -> `getOrResolve` -> dial current (then
   previous within grace) on the original port. Bare IP -> `matchIp` +
   port check. Unknown -> DENY log. No ssh config repair, no wrapper:
   the sandbox runs as the user, and the writable known_hosts rule lives
   in the 3code default policy (chunk 5).
7. Fallback: parent probe; child exit 75 with the marker line; parent
   re-spawn in env mode.
8. Tests: dns codec (A/AAAA/NXDOMAIN/NOTIMP/SERVFAIL, qname case, EDNS);
   allocator (stability, exhaustion with a small pool); raw framing;
   environment-gated e2e on userns+nft (allow host:22 -> ssh banner or
   auth-denied; `nc host 23` -> DENY in the forwarder log, which is
   host-side stderr; child loopback listener reachable). Gate and mark
   expected-fail-when-absent.

## Verification

- `nimble test` + `nimble install`.
- This host: userns and nft are available; `unshare -Urn` + `nft -f` was
  verified 2026-11-25.
- Manual: `allow <host>:22`, fenced `ssh -o BatchMode=yes <host>`;
  `nc <host> 23` denied; the child's own loopback listener reachable.

## Next step

When complete and verified, call `clear` with:
- summary: "Chunk 3 done: fence DNS over a unix datagram relay, stable
  fake-IP bindings (fake-IP->name only), bridge-side SO_ORIGINAL_DST with
  SWRAW framing, nft redirect with 127/8 scoping, raw forward path with a
  policy re-check, parent-decided fallback via exit 75 + marker. Tests
  green (e2e where env allows)."
- instructions: "Read impl-4.md and execute the instructions there."
