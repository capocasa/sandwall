import std/unittest
import sandwall/rules
import sandwall/wall/hosts

const proj = when defined(windows): r"C:\work" else: "/work"

proc listOf(text: string): HostList =
  parsePolicy(text, proj).resolve().hosts.toHostList()

suite "host list matching":
  test "empty list denies everything":
    check not listOf("").allows("example.com", 443)

  test "exact allow and deny":
    let l = listOf("+example.com\n-evil.com\n")
    check l.allows("example.com", 443)
    check l.allows("example.com", 22)
    check not l.allows("evil.com", 443)
    check not l.allows("other.com", 443)

  test "last-wins both directions":
    check listOf("+a.com\n-a.com\n").allows("a.com", 80) == false
    check listOf("-a.com\n+a.com\n").allows("a.com", 80) == true

  test "wildcard covers subdomains and apex only":
    let l = listOf("+*.example.com\n")
    check l.allows("api.example.com", 443)
    check l.allows("deep.api.example.com", 443)
    check l.allows("example.com", 443)          # apex included
    check not l.allows("notexample.com", 443)
    check not l.allows("example.com.evil.com", 443)

  test "port rules":
    let l = listOf("+host.com:443\n")
    check l.allows("host.com", 443)
    check not l.allows("host.com", 80)
    check listOf("+host.com\n").allows("host.com", 65535)
    let d = listOf("+host.com\n-host.com:22\n")
    check not d.allows("host.com", 22)
    check d.allows("host.com", 443)

  test "star is all networks":
    check listOf("+*\n").allows("anything.at.all", 1)
    check listOf("-x.com\n+*\n").allows("x.com", 443)  # later +* wins
    let l = listOf("+*\n-x.com\n")
    check not l.allows("x.com", 443)
    check l.allows("y.com", 443)

  test "ip literals":
    check listOf("+1.2.3.4\n").allows("1.2.3.4", 443)
    check not listOf("+1.2.3.4\n").allows("1.2.3.5", 443)
    check listOf("+[::1]:8080\n").allows("::1", 8080)
    check listOf("+[::1]:8080\n").allows("[::1]", 8080)
    check not listOf("+[::1]:8080\n").allows("::1", 9090)

  test "case and trailing dot normalisation":
    check listOf("+EXAMPLE.com\n").allows("example.COM", 443)
    check listOf("+example.com\n").allows("example.com.", 443)

  test "read-only host rules are skipped":
    check not listOf("*example.com\n").allows("example.com", 443)

  test "localhost is an ordinary name":
    let l = listOf("+localhost\n")
    check l.allows("localhost", 8080)
    check not l.allows("127.0.0.1", 8080)

suite "wildcard parsing":
  test "leading *. validates as a host rule":
    let pol = parsePolicy("+*.example.com\n", proj)
    let hosts = pol.resolve().hosts
    check hosts.len == 1
    check hosts[0].host == "*.example.com"
  test "bad wildcard suffix skipped silently":
    check parsePolicy("+*.bad_underscore.com\n", proj).resolve().hosts.len == 0
  test "lone star still parses":
    let hosts = parsePolicy("+*\n", proj).resolve().hosts
    check hosts.len == 1 and hosts[0].host == "*"
