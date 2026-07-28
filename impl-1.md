# Chunk 1: Host allowlist model

## Goal

Add a pure, file-free module that turns the policy's ordered host rules
into a matchable allowlist with last-wins semantics. This is the brain
the proxy (chunk 2) consults per CONNECT request. No OS code, no proxy
yet.

## Read first

- `src/sandwall/rules.nim` (Rule, RuleKind, rkHost, Resolved.hosts,
  parseHost, isValidHost; note `port = 0` means all ports and `host =
  "*"` means all networks)
- `tests/test_rules.nim` (unittest style used in this repo)
- `src/sandwall/paths.nim`

## Instructions

Create `src/sandwall/wall/hosts.nim` (new directory `src/sandwall/wall/`;
network internals live under `wall/` per the rename decision):

1. Types:

   ```nim
   type
     HostMatcher* = object
       ## One compiled host rule, in policy order.
       allow*: bool          ## true for +, false for -
       isWildcard*: bool     ## host began with "*."
       isAll*: bool          ## host == "*" (all networks)
       host*: string         ## lowercase; literal hostname or IP, or the
                           ## suffix after "*." for wildcards
       port*: uint16         ## 0 = all ports

     HostList* = object
       matchers*: seq[HostMatcher]
   ```

2. `proc toHostList*(hosts: seq[Rule]): HostList` - convert the resolved
   `rkHost` rules from `rules.resolve()`. Lowercase hostnames. Detect
   and strip a leading `*.` (sets `isWildcard`, keeps the suffix in
   `host`). Map `akWritable` to allow=true, `akDeny` to allow=false;
   skip `akReadOnly` host rules (read-only is meaningless for hosts;
   the parser only produces it if a user writes `*host`, treat as
   invalid and skip).

   Note: `rules.isValidHost` currently rejects `*.example.com`. Extend
   `isValidHost` in rules.nim so a leading `*.` label is accepted for
   hostnames (strip it, validate the rest as a hostname). Keep `*`
   alone meaning all-networks. Add parser tests for this.

3. `proc allows*(l: HostList; host: string; port: uint16): bool` -
   last-wins matching:
   - Normalize `host`: lowercase; strip one trailing dot (FQDN root).
   - Default (no matcher hits): **deny**. The fence only exists when
     the policy has host rules, so the empty list denies everything;
     callers that want unrestricted simply do not fence (see impl-plan
     Q6).
   - A matcher hits when port matches (matcher.port == 0 or == port)
     AND one of:
     - `isAll` (host `*`) matches any host.
     - `isWildcard`: host == matcher.host (apex included:
       `*.example.com` allows `example.com` itself, matching browser
       and srt convention) or host ends with `"." & matcher.host`.
     - Exact: host == matcher.host. IP literals compare as strings;
       IPv6 may arrive bracketed from CONNECT requests, so strip
       surrounding `[]` from the incoming host before comparing.
   - `localhost` is an ordinary hostname here (it matches only the
     literal `localhost`, not 127.0.0.1; users write both if they want
     both). Document this in the module header.

4. Module header comment in the same doc style as rules.nim: the DSL
   meaning of host rules, last-wins order, wildcard form (`*.` suffix
   only, leading position only), apex inclusion, port semantics, the
   deny default, and that matching is string-based (the proxy resolves
   AFTER the allow decision; no DNS here, so DNS-rebinding tricks by
   the sandboxed process are impossible by construction - it cannot
   resolve at all when fenced).

5. Export from `src/sandwall.nim`: `import ./sandwall/wall/hosts`,
   `export hosts`.

6. Tests: new `tests/test_hosts.nim`, same unittest style as
   test_rules.nim. Cover:
   - empty list denies everything
   - exact host allow and deny, last-wins override both directions
   - `+*.example.com` allows `api.example.com`, `example.com`, denies
     `notexample.com`, `example.com.evil.com`
   - port rules: `+host:443` allows 443, denies 80; bare `+host`
     (port 0) allows any port; `-host:22` blocks only 22
   - `+*` allows everything; `-` then `+*` ordering, `+*` then `-host`
     (host still denied, everything else allowed)
   - IP literals: `+1.2.3.4`, `[::1]:8080` matching `::1` port 8080
   - case-insensitivity: `+EXAMPLE.com` matches `example.COM`
   - trailing-dot FQDN form
   - `akReadOnly` host rules skipped
   - parser: `+*.example.com` and `+*.bad_underscore.com` (latter
     skipped silently)

   Wire into `sandwall.nimble` `task test` after test_rules.nim:
   `exec "nim c --path:../src -r test_hosts.nim"`.

## Verification

- `nimble test` green, including the new suite.
- `git diff` shows only: new `src/sandwall/wall/hosts.nim`, new
  `tests/test_hosts.nim`, small edits to rules.nim (isValidHost),
  sandwall.nim, sandwall.nimble, tests/test_rules.nim (parser cases).
- Commit: `host allowlist model with last-wins matching`.

## Next step

When complete and verified, call clear with:
- summary: "Chunk 1 done: src/sandwall/wall/hosts.nim (HostMatcher/
  HostList/toHostList/allows, last-wins, wildcard+apex, port rules),
  isValidHost accepts leading *., tests green, committed."
- instructions: "Read /home/carlo/p/sandwall/impl-2.md and execute it."
