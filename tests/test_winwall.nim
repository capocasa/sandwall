import std/[unittest, strutils, net]
import sandwall/wall
import sandwall/wall/[permit, wfp]

proc ip(s: string): IpAddress = parseIpAddress(s)

proc put(a: var array[16, char]; s: string) =
  zeroMem(addr a[0], sizeof(a))
  for i in 0 ..< min(s.len, a.len - 1): a[i] = s[i]

proc resolver(s: string): IpAddrString =
  zeroMem(addr result, sizeof(result))
  result.address.put(s)

## Pure-logic tests for the Windows wall (wfp.nim / winuser.nim).
## Runs on Linux: the FFI half is compile-gated and checked with the
## mingw cross compiler instead (see the compile comment in
## sandwall.nimble). There is no Windows machine in this environment.

suite "wfp pure logic":
  test "proxy port range matches srt":
    check FirstProxyPort == 60080
    check LastProxyPort == 60089
    check validPortRange(FirstProxyPort, LastProxyPort)
    check not validPortRange(0'u16, 60089'u16)
    check not validPortRange(60089'u16, 60080'u16)
    # proxy.nim imports these constants (single source); the srt range
    # values are pinned here so an accidental change is caught.

  test "sddl for user sid":
    let sddl = sddlForUserSid("S-1-5-21-1234567890-1234567891-1234567892-1001")
    check sddl.startsWith("O:LSG:LSD:(A;;CC;;;")
    check sddl.endsWith(")")
    check "S-1-5-21-1234567890-1234567891-1234567892-1001" in sddl

  test "permit filter sddl: the caller owns it and can delete it":
    let sid = "S-1-5-21-1234567890-1234567891-1234567892-1001"
    let sddl = permitFilterSddl(sid)
    check sddl == "O:" & sid & "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00010000;;;" &
      sid & ")"
    # An unelevated spawner cannot assign Administrators as the owner of
    # a filter (BFE fails the add with 1307, ERROR_INVALID_OWNER), so
    # the owner is the caller itself and no group is named at all.
    check sddl.startsWith("O:" & sid & "D:")
    check "G:" notin sddl

  test "dnsServersIn: the FIXED_INFO list sits where iptypes.h puts it":
    # HostName[132] and DomainName[132]: CurrentDnsServer at 264, the
    # list at 272. The first cut assumed 136-byte fields, read the
    # first server's address text as its `next` pointer, and crashed
    # every raw run on Win11 26100.
    var info: FixedInfo
    zeroMem(addr info, sizeof(info))
    check sizeof(info.hostName) == 132
    check cast[int](addr info.currentDnsServer) - cast[int](addr info) == 264
    check cast[int](addr info.dnsServerList) - cast[int](addr info) == 272
    check dnsServersIn(addr info).len == 0
    info.dnsServerList = resolver("10.0.2.3")
    check dnsServersIn(addr info) == @[ip("10.0.2.3")]
    var bad = resolver("not an address")
    var v6 = resolver("2001:db8::53")
    info.dnsServerList.next = addr bad
    bad.next = addr v6
    check dnsServersIn(addr info) == @[ip("10.0.2.3"), ip("2001:db8::53")]

  test "guid byte layout":
    # GUID c38d57d1-05a7-4c33-904f-0fbd964ee60e (ALE_AUTH_CONNECT_V4):
    # first three fields stored little-endian, last 8 bytes as-is.
    let g = parseGuid("c38d57d1-05a7-4c33-904f-0fbd964ee60e")
    let b = guidBytes(g)
    check b[0..3] == [0xd1'u8, 0x57, 0x8d, 0xc3]
    check b[4..5] == [0xa7'u8, 0x05]
    check b[6..7] == [0x33'u8, 0x4c]
    check b[8..15] == [0x90'u8, 0x4f, 0x0f, 0xbd, 0x96, 0x4e, 0xe6, 0x0e]

  test "guid parse round-trips case and ignores dashes":
    let a = parseGuid("C38D57D1-05A7-4C33-904F-0FBD964EE60E")
    let b = parseGuid("c38d57d1-05a7-4c33-904f-0fbd964ee60e")
    check a == b
    check parseGuid(permitV4GuidText) != parseGuid(blockV4GuidText)
    for t in [sublayerGuidText, permitV4GuidText,
        blockV4GuidText, permitV6GuidText, blockV6GuidText]:
      check t.len == 36

suite "wfp per-run permits":
  test "permitFilters: both generations within the grace, deduplicated, sorted":
    let a = PermitEntry(host: "a.test", ports: @[443'u16, 22'u16],
      current: @[ip("192.0.2.2")], previous: @[ip("192.0.2.1")],
      prevUntil: 2000.0)
    let b = PermitEntry(host: "b.test", ports: @[0'u16],
      current: @[ip("192.0.2.2"), ip("2001:db8::1")], prevUntil: Inf)
    let f = permitFilters([a, b], 1500.0)
    check f == @[
      PermitFilter(ip: ip("192.0.2.1"), port: 22),
      PermitFilter(ip: ip("192.0.2.1"), port: 443),
      PermitFilter(ip: ip("192.0.2.2"), port: 0),
      PermitFilter(ip: ip("192.0.2.2"), port: 22),
      PermitFilter(ip: ip("192.0.2.2"), port: 443),
      PermitFilter(ip: ip("2001:db8::1"), port: 0)]
    # the previous generation is gone with its grace
    let later = permitFilters([a, b], 2000.0)
    check later.len == 4
    check later == @[
      PermitFilter(ip: ip("192.0.2.2"), port: 0),
      PermitFilter(ip: ip("192.0.2.2"), port: 22),
      PermitFilter(ip: ip("192.0.2.2"), port: 443),
      PermitFilter(ip: ip("2001:db8::1"), port: 0)]

  test "permitKey: distinct per index and per run, stable for the same inputs":
    let a = permitKey(42, 0)
    check a != permitKey(42, 1)
    check a != permitKey(43, 0)
    check a == permitKey(42, 0)
    for g in [a, permitKey(42, 1), permitKey(0, 0)]:
      check guidBytes(g) != [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # 512 filters in a run: 512 distinct keys
    var seen = 0
    for i in 0 ..< MaxPermitFilters.int:
      for j in 0 ..< i:
        if permitKey(7, i) == permitKey(7, j): inc seen
    check seen == 0

  test "the cap is the plan's 512 pairs":
    check MaxPermitFilters == 512
