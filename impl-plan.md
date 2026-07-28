# Sandwall network firewall ("wall") - master plan

Repo already renamed to sandwall (f8145ec). This plan adds the network
half: `wall` modules in this repo, then 3code integration (chunks in the
3code repo).

## Locked decisions (user)

- Full monty: kernel fence to loopback + CONNECT/SOCKS5 proxy enforcing
  per-request hostname allowlists. No TLS termination.
- Default policy has no host rules and no network fencing. First host
  rule (or explicit fence) switches fencing on.
- `+host` bare = all ports. `+host:port` allowed. `+localhost` meaningful.
- Linux < kernel 6.7 (Landlock ABI < 4) with host rules: run unfenced,
  skip net rules, warn. Never hard-fail.
- Linux primary fence: netns + unix-socket bridge to the proxy (Landlock
  port-only fencing is advisory at best: port-only, TCP Fast Open bypass,
  no UDP before ABI v10).
- Windows: dedicated local user `sandwall`, DPAPI-stored credentials,
  persistent WFP filters keyed on the user SID, loopback permit to a
  FIXED proxy port range, block all other egress. Filesystem isolation
  stays as-is (restricted token + ACLs), so no-admin users keep the fs
  sandbox without network fencing. One-time elevated idempotent setup;
  consumers print a config-disableable warning when setup never ran.
- Proxy is library code in sandwall; consumers expose it as a subcommand
  of their own binary (3code gets `3code wall proxy|connect`). The
  sandwall repo ships no standalone binaries; the box/proxy/connect
  binaries are trivial mains inside the consumer.
- UDP fully denied inside the fence, TCP-only proxy, DNS only via the
  proxy. Revisit flag noted for later.
- 3code itself never sandboxed; its web tools ignore host rules.

## Chunks (this repo)

1. **impl-1.md - Host allowlist model.** Pure module: resolve host rules
   into an ordered match list with last-wins semantics, wildcard
   (`*.example.com` suffix only), IP literals, port matching. Unit tests.
2. **impl-2.md - Proxy.** `wall/proxy.nim`: threaded HTTP CONNECT +
   SOCKS5 server on 127.0.0.1, allowlist check per target, policy mtime
   reload, upstream DNS resolution, deny-logging to stderr. Tests:
   live loopback CONNECT allow/deny, SOCKS5 handshake, reload.
3. **impl-3.md - POSIX fences.** `wall.nim` public API; Linux netns
   (CLONE_NEWNET in the mask.nim userns) + unix-socket bridge forwarder
   + `wall/connect.nim` minimal SOCKS5 client for git ProxyCommand;
   macOS Seatbelt `(allow network-outbound (remote ip "localhost:*"))`
   extension. `restrictWall` extended with an `egress` parameter
   (backwards-compatible default = untouched).
4. **impl-4.md - Windows fence.** `wall/wfp.nim` (BFE FFI: provider,
   sublayer, ALE_USER_ID block + loopback permit filters, idempotent
   install/uninstall/status), `wall/winuser.nim` (create `sandwall`
   user, random password, DPAPI store, LogonUser), setup entry points.
   Unverified without a Windows machine; mirrors srt's wfp.rs shape.

## Chunks (3code repo, written when chunk 4 starts)

5. Rename dependency procbox -> sandwall in box.nim/nimble; add
   `3code wall` subcommands (proxy, connect, setup-windows).
6. Bash tool wiring: start proxy per box when host rules present, fence
   the box process, inject proxy env vars + GIT_SSH_COMMAND, warning on
   Windows-without-setup (config disableable).
7. Integrate, full test suites both repos, docs.
