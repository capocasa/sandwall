# Chunk 2: The wall proxy

## Goal

`src/sandwall/wall/proxy.nim`: a threaded HTTP CONNECT + SOCKS5 proxy
that listens on 127.0.0.1, enforces a HostList (chunk 1) per target,
resolves DNS itself, and hot-reloads its policy file on mtime change.
This is the only network-allowed egress point for fenced processes.

## Read first

- `src/sandwall/wall/hosts.nim` (HostList, toHostList, allows)
- `src/sandwall/rules.nim` (loadPolicy/parsePolicy, resolve, hosts)
- `impl-plan.md` (locked decisions; proxy shape)
- Nim stdlib docs knowledge: `std/net` (Socket, newSocket, bindAddr,
  listen, accept, connect, recvLine, recv, send, setSockOpt,
  SO_REUSEADDR), `std/threadpool` or `std/threads`, `std/times`
  (getLastModificationTime), `std/posix` for `getAddrInfo` via
  `std/net`'s `dial`/`connect` with hostname.

## Design constraints

- Single Nim process, one thread per accepted connection (simple,
  matches srt's shape; connection counts are tiny). Use `std/threads`
  with a channel-free design: each accepted client socket moves to its
  thread. Guard the shared allowlist with a lock (see reload below).
- Two protocols on ONE listener: peek the first byte. SOCKS5 starts
  with 0x05; HTTP CONNECT starts with 'C' (0x43). Peeking one byte is
  enough: any 0x05 -> SOCKS5, otherwise read an HTTP request line and
  only accept the CONNECT method (respond 405 to anything else).
- No TLS interception. After a successful CONNECT, reply
  `HTTP/1.1 200 Connection Established\r\n\r\n` and splice bytes both
  ways until EOF. After a SOCKS5 success reply, same splice.
- DNS resolution happens in the proxy AFTER the allow decision, via
  the OS resolver (`std/net` connect with hostname does this). The
  allow decision is purely string-based on the requested name (see
  hosts.nim docs).
- Deny behavior: CONNECT gets `HTTP/1.1 403 Forbidden\r\n\r\n` and a
  stderr log line `sandwall proxy: DENY host:port`; SOCKS5 gets reply
  code 0x02 (connection not allowed by ruleset) and the same log.
  Allow decisions are not logged (noise); a `-v` verbose flag logs
  allows too.
- Timeouts: 30s read timeout on the initial request parse, then none
  during splice (long-lived TLS tunnels must survive idle). Use
  blocking sockets with SO_RCVTIMEO only during the handshake phase;
  simplest is two blocking sockets in the splice with a select loop -
  use `std/selectors` or a simple `posix.poll` loop on both fds.

## Instructions

1. `src/sandwall/wall/proxy.nim`:

   ```nim
   type
     WallProxy* = object
       sock: Socket              ## listener on 127.0.0.1
       port*: uint16             ## actual bound port
       policyPath*: string       ## file to reload on mtime change
       projectDir*: string       ## for relative policy targets
       verbose*: bool

   proc startWallProxy*(policyPath: string; projectDir: string;
                        port: uint16 = 0; verbose = false): WallProxy
     ## Bind 127.0.0.1:port (0 = ephemeral), load the policy, spawn the
     ## accept loop on a background thread. Port 0 lets the caller read
     ## back `proxy.port` (the fixed-range Windows story picks explicit
     ## ports instead).

   proc stopWallProxy*(p: var WallProxy)
     ## Close the listener, join the accept thread. Client threads are
     ## detached; closing their sockets on process exit is the OS's job.
   ```

   Internals:
   - `loadList(p): HostList` - `rules.loadPolicy(p.policyPath,
     p.projectDir).resolve().hosts.toHostList()`. Store with the file's
     mtime; before EACH accept (cheap: one stat per connection) compare
     mtime and reload on change. Protect the current list with a
     `std/locks` Lock since client threads read it.
   - CONNECT parse: read request line `CONNECT host:port HTTP/1.1`,
     consume headers until empty line (ignore content). Parse host:port
     (IPv6 bracket form possible). Check `list.allows(host, port)`.
     Connect upstream with a 15s timeout. On upstream failure: `502`.
   - SOCKS5: greeting `05 nmethods methods...` -> reply `05 00` (no
     auth; loopback only). Request `05 01 00 atyp addr port`: support
     atyp 0x01 (IPv4), 0x03 (domain), 0x04 (IPv6). Convert IPv4/IPv6 to
     string form for the allow check. Reply success with bound addr
     0.0.0.0:0, then splice.
   - Splice: poll both sockets (POLLIN|POLLHUP|POLLERR), forward
     whatever is readable, half-close on EOF (shutdown write side), end
     when both directions closed. 64 KiB buffers.
   - No authentication, binds 127.0.0.1 only, never 0.0.0.0. Document
     that loopback binding IS the access control (any local process can
     use the proxy, by design; the fence is on the sandboxed side).

2. `src/sandwall/wall.nim` (public wall API, will grow in chunk 3):

   ```nim
   import ./wall/hosts
   export hosts
   import ./wall/proxy
   export proxy
   ```

   Export it from `src/sandwall.nim` alongside the existing modules
   (`import ./sandwall/wall` / `export wall`).

3. Tests: `tests/test_proxy.nim`. Real loopback tests (they are
   hermetic; bind 127.0.0.1:0):
   - Start a throwaway upstream TCP echo server on 127.0.0.1:0 in the
     test.
   - Policy file in a temp dir: `+127.0.0.1` (IP literal allow).
     Start proxy on that policy. CONNECT to `127.0.0.1:echoport` ->
     200, bytes echo through the tunnel.
   - CONNECT to `127.0.0.1:otherport` where policy is
     `+127.0.0.1:echoport` only -> 403.
   - SOCKS5 path: handshake + connect to the echo server via domain
     atyp with `localhost` in the allowlist -> success; disallowed
     name -> reply code 0x02.
   - Reload: rewrite the policy file (ensure mtime advances; sleep
     1100ms or write with explicit future mtime via
     `std/os.setLastModificationTime`), then a previously-denied target
     succeeds.
   - Plain HTTP GET to the proxy -> 405.
   Wire into sandwall.nimble `task test` after test_hosts.nim.

   Keep tests fast (< 5s total): small timeouts, no real DNS (use
   127.0.0.1 / localhost only).

## Verification

- `nimble test` green.
- Manual smoke: write a temp policy `+example.com`, run a tiny main
  that starts the proxy on a fixed port, then
  `curl -x http://127.0.0.1:PORT https://example.com -I` works and
  `curl -x http://127.0.0.1:PORT https://nim-lang.org -I` gets 403.
  Delete the temp main after.
- Commit: `wall proxy: CONNECT+SOCKS5 with hostname allowlist, mtime reload`.

## Next step

When complete and verified, call clear with:
- summary: "Chunk 2 done: wall/proxy.nim (CONNECT+SOCKS5 one-listener
  proxy, HostList enforced, mtime reload, deny logs), wall.nim public
  module, tests/test_proxy.nim green incl. curl smoke, committed."
- instructions: "Read /home/carlo/p/sandwall/impl-3.md and execute it."
