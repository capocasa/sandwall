import std/unittest
import sandwall/rules
import sandwall/wall/hosts

const proj = when defined(windows): r"C:\work" else: "/work"

proc listOf(text: string): HostList =
  parsePolicy(text, proj).resolve().hosts.toHostList()

suite "host list matching":
  test "deny-only policy defaults to allow":
    # Open by default: a policy that only names denies blocks exactly
    # those; anything unmentioned goes through. (An empty HostList is
    # never consulted at all - no host rules means no fence.)
    let l = listOf("deny evil.com\n")
    check not l.allows("evil.com", 443)
    check l.allows("example.com", 443)
    check not listOf("deny evil.com\nallow good.com\n").allows("other.com", 443)

  test "exact allow and deny":
    let l = listOf("allow example.com\ndeny evil.com\n")
    check l.allows("example.com", 443)
    check l.allows("example.com", 22)
    check not l.allows("evil.com", 443)
    check not l.allows("other.com", 443)

  test "last-wins both directions":
    check listOf("allow a.com\ndeny a.com\n").allows("a.com", 80) == false
    check listOf("deny a.com\nallow a.com\n").allows("a.com", 80) == true

  test "wildcard covers subdomains and apex only":
    let l = listOf("allow *.example.com\n")
    check l.allows("api.example.com", 443)
    check l.allows("deep.api.example.com", 443)
    check l.allows("example.com", 443)          # apex included
    check not l.allows("notexample.com", 443)
    check not l.allows("example.com.evil.com", 443)

  test "port rules":
    let l = listOf("allow host.com:443\n")
    check l.allows("host.com", 443)
    check not l.allows("host.com", 80)
    check listOf("allow host.com\n").allows("host.com", 65535)
    let d = listOf("allow host.com\ndeny host.com:22\n")
    check not d.allows("host.com", 22)
    check d.allows("host.com", 443)

  test "star is all networks":
    check listOf("allow *\n").allows("anything.at.all", 1)
    check listOf("deny x.com\nallow *\n").allows("x.com", 443)  # later allow * wins
    let l = listOf("allow *\ndeny x.com\n")
    check not l.allows("x.com", 443)
    check l.allows("y.com", 443)

  test "ip literals":
    check listOf("allow 1.2.3.4\n").allows("1.2.3.4", 443)
    check not listOf("allow 1.2.3.4\n").allows("1.2.3.5", 443)
    check listOf("allow [::1]:8080\n").allows("::1", 8080)
    check listOf("allow [::1]:8080\n").allows("[::1]", 8080)
    check not listOf("allow [::1]:8080\n").allows("::1", 9090)

  test "case and trailing dot normalisation":
    check listOf("allow EXAMPLE.com\n").allows("example.COM", 443)
    check listOf("allow example.com\n").allows("example.com.", 443)

  test "readonly host rules are skipped":
    # readonly is meaningless for hosts and skipped; a readonly-only
    # policy has no effective host rules, so the open default applies.
    check listOf("readonly example.com\n").allows("example.com", 443)

  test "localhost is an ordinary name":
    let l = listOf("allow localhost\n")
    check l.allows("localhost", 8080)
    check not l.allows("127.0.0.1", 8080)

suite "wildcard parsing":
  test "leading *. validates as a host rule":
    let pol = parsePolicy("allow *.example.com\n", proj)
    let hosts = pol.resolve().hosts
    check hosts.len == 1
    check hosts[0].host == "*.example.com"
  test "bad wildcard suffix skipped silently":
    check parsePolicy("allow *.bad_underscore.com\n", proj).resolve().hosts.len == 0
  test "lone star still parses":
    let hosts = parsePolicy("allow *\n", proj).resolve().hosts
    check hosts.len == 1 and hosts[0].host == "*"
