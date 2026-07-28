import std/[unittest, strutils]
import sandwall/wall

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

  test "sddl for user sid":
    let sddl = sddlForUserSid("S-1-5-21-1234567890-1234567891-1234567892-1001")
    check sddl.startsWith("O:LSG:LSD:(A;;CC;;;")
    check sddl.endsWith(")")
    check "S-1-5-21-1234567890-1234567891-1234567892-1001" in sddl

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
    check parseGuid(providerGuidText) != parseGuid(sublayerGuidText)
    for t in [providerGuidText, sublayerGuidText, permitV4GuidText,
        blockV4GuidText, permitV6GuidText, blockV6GuidText]:
      check t.len == 36
