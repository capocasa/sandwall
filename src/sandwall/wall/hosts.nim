## hosts: the matchable form of a policy's host rules.
##
## `rules.resolve()` carries the ordered `rkHost` rules out of a policy;
## this module compiles them into a `HostList` the wall proxy consults
## once per CONNECT/SOCKS5 request. Matching is last-wins, exactly like
## path rules: the final rule that mentions a host decides, anything
## unmentioned is denied.
##
## Match semantics:
##
##   +api.stripe.com      exact hostname (case-insensitive), all ports
##   +api.stripe.com:443  exact hostname, one port
##   +*.example.com       suffix wildcard; the apex counts too, so this
##                        allows example.com itself and a.example.com,
##                        but not notexample.com or example.com.evil.com
##   +1.2.3.4 / +::1      IP literal, string-compared (brackets around
##                        incoming IPv6 literals are stripped)
##   +*                   all networks; the rule that makes a policy
##                        "no network restrictions"
##
## `localhost` is an ordinary hostname: it matches the literal name
## only, not 127.0.0.1 or ::1. Write both rules if both are wanted.
##
## There is no DNS in here on purpose. The proxy asks `allows` about the
## NAME the client requested and resolves only after the allow decision,
## so a fenced process cannot influence resolution at all (fenced
## processes cannot resolve; the DNS channel is closed by the fence).
##
## The default depends on the policy's shape, mirroring the sandbox
## philosophy that things are open until a rule closes them: a list
## containing at least one allow rule denies whatever no rule mentions
## (the allows are the whole world), while a list of only deny rules
## allows whatever no rule mentions (the denies are the only fences).

import std/[algorithm, strutils]
import ../rules

type
  HostMatcher* = object
    ## One compiled host rule, in policy order.
    allow*: bool        ## true for `+`, false for `-`
    isWildcard*: bool   ## host began with `*.`; `host` holds the suffix
    isAll*: bool        ## host == `*` (all networks)
    host*: string       ## lowercase literal hostname/IP, or wildcard suffix
    port*: uint16       ## 0 = all ports

  HostList* = object
    matchers*: seq[HostMatcher]
    hasAllow*: bool   ## any allow matcher present; flips the default

proc toHostList*(hosts: seq[Rule]): HostList =
  ## Compile resolved host rules into matchers, preserving policy order.
  ## `akReadOnly` and `akAsk` host rules are meaningless (read-only and
  ## ask-to-allow apply to paths; the wall has no user to ask) and are
  ## skipped, which denies. Hostnames are lowercased; a leading `*.`
  ## arms the wildcard form.
  for r in hosts:
    if r.kind != rkHost: continue
    case r.access
    of akReadOnly, akAsk: continue
    of akDeny, akWritable: discard
    var m = HostMatcher(allow: r.access == akWritable,
                        host: r.host.toLowerAscii, port: r.port)
    if m.host == "*":
      m.isAll = true
    elif m.host.startsWith("*."):
      m.isWildcard = true
      m.host = m.host[2 .. ^1]
    if m.allow: result.hasAllow = true
    result.matchers.add m

proc normalizeHost*(host: string): string =
  ## The comparison form of a requested host: lowercased, one trailing
  ## FQDN root dot stripped, IPv6 brackets removed.
  result = host.toLowerAscii
  if result.endsWith("."): result = result[0 .. ^2]
  if result.startsWith("[") and result.endsWith("]"):
    result = result[1 .. ^2]

proc coversName(m: HostMatcher; h: string): bool =
  ## Does the matcher name `h`? `h` is already in `normalizeHost` form;
  ## the matcher's port is not looked at.
  if m.isAll: true
  elif m.isWildcard: h == m.host or h.endsWith("." & m.host)
  else: h == m.host

proc allows*(l: HostList; host: string; port: uint16): bool =
  ## Last-wins decision for `host:port`. When nothing matches the
  ## default is deny for an allowlist-shaped policy (any allow rule)
  ## and allow for a deny-only policy.
  result = not l.hasAllow
  let h = normalizeHost(host)
  for m in l.matchers:
    if m.port != 0 and m.port != port: continue
    if m.coversName(h): result = m.allow

proc allowsAnyPort*(l: HostList; host: string): bool =
  ## Does the policy let anything through to `host` at all, on some
  ## port? The question the fence DNS asks (wall/dns.nim): a port is
  ## not known at resolution time, the connect decides it. A bare
  ## rule for the name decides the whole name, an allow for one port
  ## makes it reachable, a deny for one port leaves the other rules to
  ## speak; the default is as in `allows`.
  result = not l.hasAllow
  let h = normalizeHost(host)
  for m in l.matchers:
    if not m.coversName(h): continue
    if m.port == 0: result = m.allow
    elif m.allow: result = true

proc winningPorts*(l: HostList; host: string): seq[uint16] =
  ## The ports the allow rules for `host` still stand for, ascending.
  ## An allow rule is superseded when a later rule naming the host
  ## decides its whole scope (a later bare rule, or a later rule for
  ## the same port); the others contribute: `0` when a bare allow
  ## survives (every port), otherwise its port. So `allow host` then
  ## `deny host:22` still yields `@[0]`: the carve-out cannot be
  ## expressed as a list of ports. Empty when no allow survives. A
  ## deny-only policy leaves unlisted hosts open; that default is not
  ## an allow rule and is not reported here.
  let h = normalizeHost(host)
  for i, m in l.matchers:
    if not m.allow or not m.coversName(h): continue
    var superseded = false
    for j in i + 1 ..< l.matchers.len:
      let n = l.matchers[j]
      if n.coversName(h) and (n.port == 0 or n.port == m.port):
        superseded = true
        break
    if not superseded:
      if m.port == 0: return @[0'u16]
      if m.port notin result: result.add m.port
  result.sort
