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
    let l = listOf("write example.com\ndeny evil.com\n")
    check l.allows("example.com", 443)
    check l.allows("example.com", 22)
    check not l.allows("evil.com", 443)
    check not l.allows("other.com", 443)

  test "last-wins both directions":
    check listOf("write a.com\ndeny a.com\n").allows("a.com", 80) == false
    check listOf("deny a.com\nwrite a.com\n").allows("a.com", 80) == true

  test "wildcard covers subdomains and apex only":
    let l = listOf("write *.example.com\n")
    check l.allows("api.example.com", 443)
    check l.allows("deep.api.example.com", 443)
    check l.allows("example.com", 443)          # apex included
    check not l.allows("notexample.com", 443)
    check not l.allows("example.com.evil.com", 443)

  test "port rules":
    let l = listOf("write host.com:443\n")
    check l.allows("host.com", 443)
    check not l.allows("host.com", 80)
    check listOf("write host.com\n").allows("host.com", 65535)
    let d = listOf("write host.com\ndeny host.com:22\n")
    check not d.allows("host.com", 22)
    check d.allows("host.com", 443)

  test "star is all networks":
    check listOf("write *\n").allows("anything.at.all", 1)
    check listOf("deny x.com\nwrite *\n").allows("x.com", 443)  # later write * wins
    let l = listOf("write *\ndeny x.com\n")
    check not l.allows("x.com", 443)
    check l.allows("y.com", 443)

  test "ip literals":
    check listOf("write 1.2.3.4\n").allows("1.2.3.4", 443)
    check not listOf("write 1.2.3.4\n").allows("1.2.3.5", 443)
    check listOf("write [::1]:8080\n").allows("::1", 8080)
    check listOf("write [::1]:8080\n").allows("[::1]", 8080)
    check not listOf("write [::1]:8080\n").allows("::1", 9090)

  test "case and trailing dot normalisation":
    check listOf("write EXAMPLE.com\n").allows("example.COM", 443)
    check listOf("write example.com\n").allows("example.com.", 443)

  test "read-only host rules are skipped":
    check not listOf("*example.com\n").allows("example.com", 443)

  test "localhost is an ordinary name":
    let l = listOf("write localhost\n")
    check l.allows("localhost", 8080)
    check not l.allows("127.0.0.1", 8080)

suite "wildcard parsing":
  test "leading *. validates as a host rule":
    let pol = parsePolicy("write *.example.com\n", proj)
    let hosts = pol.resolve().hosts
    check hosts.len == 1
    check hosts[0].host == "*.example.com"
  test "bad wildcard suffix skipped silently":
    check parsePolicy("write *.bad_underscore.com\n", proj).resolve().hosts.len == 0
  test "lone star still parses":
    let hosts = parsePolicy("write *\n", proj).resolve().hosts
    check hosts.len == 1 and hosts[0].host == "*"
