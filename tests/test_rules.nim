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
  test "bare names are project-relative paths":
    # a bare single-label word is ambiguous: a valid hostname wins,
    # anything else is a project-relative path
    check classifyTarget("foo") == rkHost
    check classifyTarget("src/main.nim") == rkPath
    check classifyTarget("a b") == rkPath
  test "hosts":
    check classifyTarget("api.stripe.com") == rkHost
    check classifyTarget("1.2.3.4") == rkHost
    check classifyTarget("::1") == rkHost
    check classifyTarget("*") == rkHost
    # a name with a space can never be a host; bad dotted targets
    # fail parseHost later and are dropped, never become paths
    check classifyTarget("bad host!") == rkPath
    check classifyTarget("999.1.1.1") == rkHost

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
    check p.len == 1
    check p[0].kind == rkPath
    check p[0].access == akWritable
    check p[0].path == proj.normalizedPath
  test "arbitrary whitespace between verb and target":
    let p = parsePolicy("deny\t\t/secret\n  allow    /tmp\n", proj)
    check p.len == 2
    check p[0].access == akDeny
    check p[1].access == akWritable
  test "host starting with a verb parses as host, not verb+rest":
    let p = parsePolicy("deny.corp.internal\nreadout.example.com\n", proj)
    check p.len == 2
    check p[0].kind == rkHost and p[0].host == "deny.corp.internal"
    check p[1].kind == rkHost and p[1].host == "readout.example.com"
  test "relative resolves against project dir":
    let p = parsePolicy("readonly ./src\n", proj)
    check p[0].access == akReadOnly
    check p[0].path == (proj / "src").normalizedPath
  test "bare relative resolves against project dir":
    let p = parsePolicy("allow src/foo\ndeny .git\n", proj)
    check p.len == 2
    check p[0].path == (proj / "src/foo").normalizedPath
    check p[1].path == (proj / ".git").normalizedPath
  test "bare single label is a host, not a path":
    # ambiguity resolves to the host; project-relative paths need a
    # slash, a dot, or ./
    let p = parsePolicy("allow out\n", proj)
    check p.len == 1 and p[0].kind == rkHost
  test "bad dotted host is dropped, not turned into a path":
    check parsePolicy("allow 999.1.1.1\n", proj).len == 0
  test "absolute kept, cleaned":
    when not defined(windows):
      let p = parsePolicy("deny /tmp/../etc\n", proj)
      check p[0].path == "/etc"
  test "comments, blanks, garbage skipped":
    let p = parsePolicy("# note\n\nallow /tmp\nallow bad host!\n", proj)
    check p.len == 2
    check p[0].path == (when defined(windows): "\\tmp" else: "/tmp")
    # a name with a space is a path line, not a bad host
    check p[1].kind == rkPath

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

suite "concatenated levels":
  # Cascade semantics are the consumer's job (3code concatenates its
  # levels and parses once); these tests pin the property that makes
  # that work: later text supersedes earlier text in one parse.
  test "later text supersedes earlier":
    let pol = parsePolicy("allow /shared\n" & "\n" & "deny /shared\nallow /repo\n", proj)
    when not defined(windows):
      check pol.checkPath("/shared/x") == akDeny
      check pol.checkPath("/repo/x") == akWritable
  test "later deny-slash resets earlier allows":
    let pol = parsePolicy("allow /\n" & "\n" & "deny /\nallow ./\n", proj)
    when not defined(windows):
      check pol.checkPath("/etc") == akDeny
      check pol.checkPath((proj / "f").normalizedPath) == akWritable

suite "render and append":
  test "hidden rules are enforced but not rendered":
    var pol = parsePolicy("allow ./\n", proj)
    pol.add Rule(access: akReadOnly, kind: rkPath, hidden: true,
                 path: (proj / ".sandbox").normalizedPath)
    pol.add Rule(access: akDeny, kind: rkPath, hidden: true,
                 path: (proj / "guarded").normalizedPath)
    check pol.checkPath((proj / ".sandbox").normalizedPath) == akReadOnly
    check pol.checkPath((proj / "guarded").normalizedPath) == akDeny
    check pol.checkPath((proj / "other").normalizedPath) == akWritable
    let s = renderPolicy(pol)
    check ".sandbox" notin s
    check "guarded" notin s
    check "allow" in s
    # Hidden rules survive resolve like any other.
    let r = pol.resolve()
    check (proj / ".sandbox").normalizedPath in r.readonly
    # A policy of only hidden rules renders as the empty policy.
    let onlyHidden = @[Rule(access: akReadOnly, kind: rkPath,
                            hidden: true,
                            path: (proj / ".sandbox").normalizedPath)]
    check renderPolicy(onlyHidden) == "(no sandbox rules)"

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

  test "appendRule moves an existing rule to the end":
    let f = getTempDir() / "sandwall-test-policy"
    writeFile(f, "# comment\nallow ./src\nreadonly /lib\n")
    check appendRule(f, "./src", akDeny)
    check readFile(f) == "# comment\nreadonly /lib\ndeny ./src\n"
    # flipping back strips the deny
    check appendRule(f, "./src", akWritable)
    check readFile(f) == "# comment\nreadonly /lib\nallow ./src\n"
    removeFile(f)

  test "appendRule host rules match on host:port, not the verb":
    let f = getTempDir() / "sandwall-test-policy"
    writeFile(f, "allow a.com:443\nallow a.com\ndeny b.com\n")
    # same host, different port: both rules survive
    check appendRule(f, "a.com:80", akDeny)
    check readFile(f) == "allow a.com:443\nallow a.com\ndeny b.com\ndeny a.com:80\n"
    # bare host strips the bare-host rule only
    check appendRule(f, "a.com", akDeny)
    check readFile(f) == "allow a.com:443\ndeny b.com\ndeny a.com:80\ndeny a.com\n"
    removeFile(f)

  test "appendRule leaves verb-prefix hosts and other paths alone":
    let f = getTempDir() / "sandwall-test-policy"
    writeFile(f, "deny.corp.internal\nallow ./src\nallow ./src2\n")
    check appendRule(f, "./src", akDeny)
    check readFile(f) == "deny.corp.internal\nallow ./src2\ndeny ./src\n"
    removeFile(f)

suite "contract and normalize":
  test "contractPath":
    check contractPath((proj / "foo").normalizedPath, proj) == "./foo"
    check contractPath((proj / "a" / "foo").normalizedPath, proj) == "a/foo"
    check contractPath(proj.normalizedPath, proj) == ""
    check contractPath((proj / ".git").normalizedPath, proj) == ".git"
    when not defined(windows):
      check contractPath("/etc/passwd", proj) == "/etc/passwd"
      let home = getHomeDir().normalizedPath
      check contractPath(home / "foo", proj) == "~/foo"
      check contractPath(home, proj) == "~"

  test "renderPolicy contracts paths with projectDir":
    let pol = parsePolicy("allow\ndeny .git\nreadonly ~/x\nallow /etc\n", proj)
    let s = renderPolicy(pol, proj)
    check "allow     \n" in s or "allow   \n" in s
    check "deny      .git\n" in s or "deny    .git\n" in s
    check "~/x" in s
    check proj notin s
    when not defined(windows):
      check "/etc" in s

  test "appendRule normalizes targets to the portable form":
    let f = getTempDir() / "sandwall-test-policy"
    removeFile(f)
    check appendRule(f, (proj / "src").normalizedPath, akReadOnly, proj)
    check appendRule(f, "./build", akWritable, proj)
    check appendRule(f, "out dir/x", akWritable, proj)
    check readFile(f) == "readonly ./src\nallow ./build\nallow out dir/x\n"
    # absolute home target contracts to ~
    let home = getHomeDir().normalizedPath
    check appendRule(f, home / "dl", akDeny, proj)
    check readFile(f) == "readonly ./src\nallow ./build\nallow out dir/x\ndeny ~/dl\n"
    removeFile(f)

  test "appendRule dedupes ./foo, foo, and absolute forms":
    let f = getTempDir() / "sandwall-test-policy"
    writeFile(f, "# c\nallow ./src\nreadonly /lib\n")
    check appendRule(f, "dir/src", akDeny, proj)
    check readFile(f) == "# c\nallow ./src\nreadonly /lib\ndeny dir/src\n"
    check appendRule(f, "./src", akDeny, proj)
    check readFile(f) == "# c\nreadonly /lib\ndeny dir/src\ndeny ./src\n"
    check appendRule(f, (proj / "src").normalizedPath, akWritable, proj)
    check readFile(f) == "# c\nreadonly /lib\ndeny dir/src\nallow ./src\n"
    # a pre-existing absolute rule in the file matches the same path
    writeFile(f, "deny " & (proj / "x").normalizedPath & "\n")
    check appendRule(f, "./x", akWritable, proj)
    check readFile(f) == "allow ./x\n"
    # host targets pass through unchanged even with projectDir set
    check appendRule(f, "a.com:443", akWritable, proj)
    check "allow a.com:443" in readFile(f)
    removeFile(f)
