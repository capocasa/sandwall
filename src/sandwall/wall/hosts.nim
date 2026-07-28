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
## The default is deny: a policy with host rules fences the network, so
## a HostList is only consulted when fencing is on, and within it
## silence means no.

import std/strutils
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

proc toHostList*(hosts: seq[Rule]): HostList =
  ## Compile resolved host rules into matchers, preserving policy order.
  ## `akReadOnly` host rules are meaningless (read-only applies to paths)
  ## and skipped. Hostnames are lowercased; a leading `*.` arms the
  ## wildcard form.
  for r in hosts:
    if r.kind != rkHost: continue
    case r.access
    of akReadOnly: continue
    of akDeny, akWritable: discard
    var m = HostMatcher(allow: r.access == akWritable,
                        host: r.host.toLowerAscii, port: r.port)
    if m.host == "*":
      m.isAll = true
    elif m.host.startsWith("*."):
      m.isWildcard = true
      m.host = m.host[2 .. ^1]
    result.matchers.add m

proc normalizeHost(host: string): string =
  ## The comparison form of a requested host: lowercased, one trailing
  ## FQDN root dot stripped, IPv6 brackets removed.
  result = host.toLowerAscii
  if result.endsWith("."): result = result[0 .. ^2]
  if result.startsWith("[") and result.endsWith("]"):
    result = result[1 .. ^2]

proc allows*(l: HostList; host: string; port: uint16): bool =
  ## Last-wins decision for `host:port`. Deny when nothing matches.
  let h = normalizeHost(host)
  for m in l.matchers:
    if m.port != 0 and m.port != port: continue
    let hit =
      if m.isAll: true
      elif m.isWildcard: h == m.host or h.endsWith("." & m.host)
      else: h == m.host
    if hit: result = m.allow
