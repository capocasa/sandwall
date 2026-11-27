# Chunk 2: Resolver-backed CONNECT/SOCKS path

## Goal

Every name decision validates the IP set at connect time (per-connect
freshness for env tools on all platforms). The rename is chunk 6, not
here.

## Read first

- `src/sandwall/wall/proxy.nim` - `ProxyShared`, `loadList`,
  `maybeReload`, `allowed`, `dialUp`, `serveConnect`, `serveSocks5`,
  `startWallProxy`.
- `src/sandwall/wall/permit.nim` - the chunk-1 API.
- `src/sandwall/wall/hosts.nim` - name matching to preserve.

## Instructions

1. Keep the module and public API names (`startWallProxy`,
   `spawnWallProxy`, `stopWallProxy`, `setProxyEnv`). The rename is
   chunk 6; do not break 3code mid-feature.
2. Decision path:
   - CONNECT/SOCKS5 with a hostname: check the name against the HostList
     exactly as today, then `getOrResolve(name)`, then dial the **current**
     IPs in order with the existing overall timeout; on connect failure,
     try previous IPs within grace; then 502.
   - SOCKS5 ATYP IPv4/IPv6: `matchIp`; unknown -> the standard deny log.
   - Bare-IP CONNECT: `matchIp` (current, previous within grace, or an
     IP-literal entry); log the entry's host when known.
   - Keep `maybeReload`'s mtime check. On reload: rebuild the HostList and
     clear the permit cache, so removed rules stop resolving.
3. `dialUp` takes `seq[IpAddress]`: one resolution, in the permit set, not
   a second `getAddrInfo` at dial.
4. No SOCKS4: the proxy speaks SOCKS5 only. ATYP 0x01/0x04 are the
   "IP-only clients".
5. Tests: extend `tests/test_proxy.nim` with the injectable resolver:
   resolve once, second connect inside the refresh does not re-resolve;
   expired re-resolves; NXDOMAIN denies; transient keeps the stale IP;
   previous IP tried on connect failure; bare-IP allow/deny.

## Verification

- `nimble test` + `nimble install`.
- Manual smoke through the existing test harness or a fenced 3code curl:
  allow -> 200, deny -> the deny log. There is no `sandwall forward`
  subcommand; do not invent one.

## Next step

When complete and verified, call `clear` with:
- summary: "Chunk 2 done: CONNECT/SOCKS decisions resolve via PermitSet
  with per-connect age checks, bare IP via matchIp, previous IPs tried on
  connect failure, tests green."
- instructions: "Read impl-3.md and execute the instructions there."
