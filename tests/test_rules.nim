## Unit tests for the policy DSL: parsing, classification, cascade,
## checkPath, resolve, render. Pure logic, no sandboxing involved.

import std/[os, strutils, unittest]
import sandwall/rules

const proj = when defined(windows): r"C:\work\proj" else: "/work/proj"

suite "target classification":
  test "absolute paths":
    check classifyTarget("/home/carlo") == rkPath
    check classifyTarget("/") == rkPath
  test "windows drive paths":
    check classifyTarget("C:\\Users\\x") == rkPath
    check classifyTarget("c:/work") == rkPath
  test "tilde and relative":
    check classifyTarget("~/.config") == rkPath
    check classifyTarget("./foo") == rkPath
    check classifyTarget(".") == rkPath
    check classifyTarget("") == rkPath
  test "hosts":
    check classifyTarget("api.stripe.com") == rkHost
    check classifyTarget("1.2.3.4") == rkHost
    check classifyTarget("::1") == rkHost
    check classifyTarget("*") == rkHost

suite "host parsing":
  test "bare hostname, all ports":
    let (h, p) = parseHost("api.stripe.com")
    check h == "api.stripe.com" and p == 0
  test "hostname with port":
    let (h, p) = parseHost("api.stripe.com:443")
    check h == "api.stripe.com" and p == 443
  test "ipv4":
    let (h, p) = parseHost("10.0.0.1")
    check h == "10.0.0.1" and p == 0
    let (h2, p2) = parseHost("10.0.0.1:8080")
    check h2 == "10.0.0.1" and p2 == 8080
  test "ipv6 bare and bracketed":
    let (h, p) = parseHost("::1")
    check h == "::1" and p == 0
    let (h2, p2) = parseHost("[::1]:9090")
    check h2 == "::1" and p2 == 9090
  test "star":
    let (h, p) = parseHost("*")
    check h == "*" and p == 0
  test "garbage rejected":
    expect ValueError: discard parseHost("bad host!")
    expect ValueError: discard parseHost("host:notaport")
    expect ValueError: discard parseHost("host:99999")
    expect ValueError: discard parseHost("999.1.1.1")
    expect ValueError: discard parseHost("-leading-dash.com")
    expect ValueError: discard parseHost("")

suite "path parsing":
  test "bare code means project dir":
    let p = parsePolicy("allow\n", proj)
    check p.rules.len == 1
    check p.rules[0].kind == rkPath
    check p.rules[0].access == akWritable
    check p.rules[0].path == proj.normalizedPath
  test "arbitrary whitespace between verb and target":
    let p = parsePolicy("deny\t\t/secret\n  allow    /tmp\n", proj)
    check p.rules.len == 2
    check p.rules[0].access == akDeny
    check p.rules[1].access == akWritable
  test "host starting with a verb parses as host, not verb+rest":
    let p = parsePolicy("deny.corp.internal\nreadout.example.com\n", proj)
    check p.rules.len == 2
    check p.rules[0].kind == rkHost and p.rules[0].host == "deny.corp.internal"
    check p.rules[1].kind == rkHost and p.rules[1].host == "readout.example.com"
  test "relative resolves against project dir":
    let p = parsePolicy("readonly ./src\n", proj)
    check p.rules[0].access == akReadOnly
    check p.rules[0].path == (proj / "src").normalizedPath
  test "absolute kept, cleaned":
    when not defined(windows):
      let p = parsePolicy("deny /tmp/../etc\n", proj)
      check p.rules[0].path == "/etc"
  test "comments, blanks, garbage skipped":
    let p = parsePolicy("# note\n\nallow /tmp\n? bogus\n", proj)
    check p.rules.len == 1
    check p.rules[0].path == (when defined(windows): "\\tmp" else: "/tmp")

suite "checkPath":
  const text = "deny /\nallow /tmp\nallow ./\nreadonly /var\n"
  let pol = parsePolicy(text, proj)
  test "last covering rule wins":
    check pol.checkPath((proj / "main.nim").normalizedPath) == akWritable
    when not defined(windows):
      check pol.checkPath("/tmp/x") == akWritable
      check pol.checkPath("/var/log") == akReadOnly
      check pol.checkPath("/etc/passwd") == akDeny
  test "deny default for the unmentioned":
    let p2 = parsePolicy("allow ./\n", proj)
    when not defined(windows):
      check p2.checkPath("/elsewhere") == akDeny
  test "later deny overrides earlier allow":
    let p3 = parsePolicy("allow /a\ndeny /a\n", proj)
    when not defined(windows):
      check p3.checkPath("/a/f") == akDeny
  test "host rules never affect paths":
    let p4 = parsePolicy("allow example.com\n", proj)
    when not defined(windows):
      check p4.checkPath("/anything") == akDeny

suite "resolve":
  test "writable/readonly split, denies dropped":
    let pol = parsePolicy("allow /a\nreadonly /b\ndeny /c\nallow /a\ndeny /b\n", proj)
    let r = pol.resolve()
    when not defined(windows):
      check r.writable == @["/a"]
      check r.readonly.len == 0
  test "host rules pass through, last-wins per host:port key":
    let pol = parsePolicy("allow a.com\ndeny a.com\nallow b.com:443\nallow a.com:80\n", proj)
    let r = pol.resolve()
    check r.hosts.len == 3
    check r.hosts[0].host == "a.com" and r.hosts[0].port == 0
    check r.hosts[0].access == akDeny
    check r.hosts[1].host == "b.com" and r.hosts[1].port == 443
    check r.hosts[2].host == "a.com" and r.hosts[2].port == 80
  test "deny host rules survive resolve":
    let pol = parsePolicy("allow a.com\ndeny b.com\n", proj)
    let r = pol.resolve()
    check r.hosts.len == 2
    check r.hosts[0].access == akWritable
    check r.hosts[1].host == "b.com" and r.hosts[1].access == akDeny

suite "cascade":
  test "repo supersedes system":
    let pol = parseCascaded("allow /shared\n", "deny /shared\nallow /repo\n", proj)
    when not defined(windows):
      check pol.checkPath("/shared/x") == akDeny
      check pol.checkPath("/repo/x") == akWritable
  test "repo dash-slash resets system allows":
    let pol = parseCascaded("allow /\n", "deny /\nallow ./\n", proj)
    when not defined(windows):
      check pol.checkPath("/etc") == akDeny
      check pol.checkPath((proj / "f").normalizedPath) == akWritable
  test "default text parses to the documented policy":
    let pol = parsePolicy(defaultPolicyText(), proj)
    check pol.checkPath(proj.normalizedPath) == akWritable
    when not defined(windows):
      check pol.checkPath("/tmp/x") == akWritable
      check pol.checkPath("/root/x") == akDeny
  test "empty system level adds no rules":
    # Regression: loadCascaded substitutes the default text only for an
    # absent repo file; an absent system file contributes nothing.
    # Doubling the default made every rule appear twice in renders.
    let pol = parseCascaded("", defaultPolicyText(), proj)
    check pol.rules.len == parsePolicy(defaultPolicyText(), proj).rules.len

suite "render and append":
  test "render shows kinds and ports":
    let pol = parsePolicy("allow ./\nreadonly /lib\ndeny /secret\nallow a.com:443\nallow *\n", proj)
    let s = renderPolicy(pol)
    check "allow " in s and "readonly  " in s and "deny  " in s
    check "a.com:443" in s
    check "*\n" in s
  test "appendRule writes the literal target":
    let f = getTempDir() / "sandwall-test-policy"
    removeFile(f)
    check appendRule(f, "./src", akReadOnly)
    check appendRule(f, "", akWritable)
    check appendRule(f, "api.x.com:8443", akWritable)
    check readFile(f) == "readonly ./src\nallow\nallow api.x.com:8443\n"
    removeFile(f)
