import std/[net, options, strutils, unittest]
import sandwall/wall/dns

## The fence DNS codec and the fake-IP pool, without a fence: queries
## are built here, answers parsed back.

proc encodeName(name: string): seq[uint8] =
  ## The wire form of `name` (no trailing dot): labels as received,
  ## case included, then the root label.
  for label in name.split('.'):
    if label.len == 0: continue
    result.add uint8(label.len)
    for c in label: result.add uint8(c)
  result.add 0'u8

proc query(id: uint16; name: string; qtype: uint16; flags = 0x0100'u16;
           arcount: uint16 = 0): seq[uint8] =
  ## One question for `name`, recursion desired unless `flags` says
  ## otherwise; `arcount` claims that many additional records (the
  ## caller appends them).
  let qn = encodeName(name)
  result = @[uint8(id shr 8), uint8(id and 0xff),
             uint8(flags shr 8), uint8(flags and 0xff),
             0, 1, 0, 0, 0, 0,
             uint8(arcount shr 8), uint8(arcount and 0xff)]
  result.add qn
  result.add [uint8(qtype shr 8), uint8(qtype and 0xff), 0, 1]

proc be16(buf: openArray[uint8]; at: int): int =
  (int(buf[at]) shl 8) or int(buf[at + 1])

proc rcodeOf(resp: openArray[uint8]): int = int(resp[3] and 0x0F)

proc counts(resp: openArray[uint8]): tuple[qd, an, ns, ar: int] =
  (be16(resp, 4), be16(resp, 6), be16(resp, 8), be16(resp, 10))

proc answerAddress(resp: openArray[uint8]): IpAddress =
  ## The rdata of the first (only) A answer.
  doAssert resp.len >= 16
  var a = IpAddress(family: IpAddressFamily.IPv4)
  for i in 0 ..< 4: a.address_v4[i] = resp[resp.len - 4 + i]
  a

proc answerSectionAt(resp: openArray[uint8]): int =
  ## Offset of the answer section: past the echoed question.
  var p = 12
  while resp[p] != 0: p.inc int(resp[p]) + 1
  p + 1 + 4

proc readQname(resp: openArray[uint8]; at: int): tuple[wire: seq[uint8], next: int] =
  var p = at
  while true:
    let n = int(resp[p])
    inc p
    if n == 0: break
    p.inc n
  result.wire = resp[at ..< p]
  result.next = p

proc fakeDecision(ip: string): Decide =
  let a = parseIpAddress(ip)
  result = proc (name: string): tuple[decision: DnsDecision, ip: IpAddress] =
    (ddFake, a)

proc answerOf(q: seq[uint8]; decide: Decide): seq[uint8] =
  var qq = q
  reply(qq, decide)

suite "fence DNS codec":
  const fake = "198.18.0.7"

  test "an allowed name gets its fake-IP, the question echoed as received":
    let q = query(0xBEEF, "WWW.Example.COM", uint16(qtA))
    let resp = answerOf(q, fakeDecision(fake))
    # the answer: the qname again, then type, class, ttl, rdlength, 4 bytes
    check resp.len == answerSectionAt(resp) + 17 + 14
    check be16(resp, 0) == 0xBEEF
    check (resp[2] and 0x80) != 0             # QR
    check (resp[2] and 0x78) == 0             # opcode standard query
    check (resp[2] and 0x01) != 0             # RD echoed
    check rcodeOf(resp) == 0
    check counts(resp) == (1, 1, 0, 0)
    let (wire, next) = readQname(resp, 12)
    check wire == encodeName("WWW.Example.COM")   # case kept
    check be16(resp, next) == int(qtA)
    check be16(resp, next + 2) == 1
    let (awire, anext) = readQname(resp, answerSectionAt(resp))
    check awire == wire
    check be16(resp, anext) == int(qtA)      # type
    check be16(resp, anext + 2) == 1         # class IN
    check be16(resp, anext + 8) == 4         # rdlength
    check $answerAddress(resp) == fake

  test "AAAA for an allowed name is NOERROR with no answers":
    let resp = answerOf(query(3, "svc.test", uint16(qtAAAA)), fakeDecision(fake))
    check rcodeOf(resp) == 0
    check counts(resp) == (1, 0, 0, 0)

  test "a denied name is NXDOMAIN, an addressless one SERVFAIL":
    var resp = reply(query(5, "no.test", uint16(qtA)),
                    proc (name: string): tuple[decision: DnsDecision, ip: IpAddress] =
                      (ddNxDomain, IpAddress()))
    check rcodeOf(resp) == 3
    check counts(resp) == (1, 0, 0, 0)
    check readQname(resp, 12).wire == encodeName("no.test")
    resp = reply(query(6, "no.test", uint16(qtAAAA)),
                 proc (name: string): tuple[decision: DnsDecision, ip: IpAddress] =
                   (ddServFail, IpAddress()))
    check rcodeOf(resp) == 2
    check counts(resp) == (1, 0, 0, 0)

  test "other types, classes and opcodes are NOTIMP":
    var resp = answerOf(query(7, "svc.test", 16), fakeDecision(fake))  # TXT
    check rcodeOf(resp) == 4
    check counts(resp) == (1, 0, 0, 0)
    var q = query(8, "svc.test", uint16(qtA))
    q[^1] = 3                                         # class CH
    resp = answerOf(q, fakeDecision(fake))
    check rcodeOf(resp) == 4
    resp = answerOf(query(9, "svc.test", uint16(qtA), flags = 0x0100 or (1'u16 shl 11)),
                    fakeDecision(fake))                # inverse query
    check rcodeOf(resp) == 4

  test "the decision sees the lowercase name without its root dot":
    var seen = ""
    let seenPtr = addr seen
    discard reply(query(10, "Mixed.Case.TEST.", uint16(qtA)),
                  proc (name: string): tuple[decision: DnsDecision, ip: IpAddress] =
                    seenPtr[] = name
                    (ddNxDomain, IpAddress()))
    check seen == "mixed.case.test"

  test "an EDNS0 OPT record is ignored, not echoed":
    var q = query(11, "svc.test", uint16(qtA), arcount = 1)
    # OPT: root owner, type 41, UDP payload size 1232, no rdata
    q.add [0'u8, 0, 41, 4, 0xD0, 0, 0, 0, 0, 0, 0]
    let resp = answerOf(q, fakeDecision(fake))
    check rcodeOf(resp) == 0
    check counts(resp) == (1, 1, 0, 0)
    check answerAddress(resp) == parseIpAddress(fake)

  test "a query that cannot be read gets a header-only SERVFAIL":
    var resp = reply(query(0x4243, "svc.test", uint16(qtA))[0 ..< 9],
                     fakeDecision(fake))
    check resp.len == 12
    check be16(resp, 0) == 0x4243
    check rcodeOf(resp) == 2
    # two questions are not a question this fence can echo
    var two = query(1, "a.test", uint16(qtA))
    two[5] = 2
    two.add encodeName("b.test")
    two.add [0'u8, 1, 0, 1]
    check rcodeOf(reply(two, fakeDecision(fake))) == 2
    # a root query has no name to decide about: NXDOMAIN
    check rcodeOf(answerOf(query(2, "", uint16(qtA)), fakeDecision(fake))) == 3

  test "a compressed qname is refused":
    var q = query(12, "svc.test", uint16(qtA))
    q[16] = 0xC0                           # a pointer where the second label's length sits
    check rcodeOf(answerOf(q, fakeDecision(fake))) == 2

suite "fake-IP pool":
  test "bindings are stable and lowest-free":
    var p = initFakePool()
    let a = p.fakeFor("alpha.test").get
    let b = p.fakeFor("Beta.test").get
    check $a == "198.18.0.1"
    check $b == "198.18.0.2"
    check p.fakeFor("alpha.test").get == a
    check p.fakeFor("ALPHA.TEST").get == a  # the case the DNS layer never sends
    check p.len == 2
    check p.nameFor(a).get == "alpha.test"
    check p.nameFor(b).get == "beta.test"   # stored lowercase
    check p.nameFor(parseIpAddress("198.18.0.3")).isNone
    check p.nameFor(parseIpAddress("198.18.0.0")).isNone
    check p.nameFor(parseIpAddress("127.0.0.1")).isNone
    check p.nameFor(parseIpAddress("::1")).isNone
    # a copy, not the pool's own buffer
    var n = p.nameFor(a).get
    n[0] = 'X'
    check p.nameFor(a).get == "alpha.test"

  test "the pool exhausts and keeps its bindings":
    var p = initFakePool(size = 2)
    check p.fakeFor("one.test").isSome
    check p.fakeFor("two.test").isSome
    check p.fakeFor("three.test").isNone
    check p.fakeFor("one.test").isSome
    check p.nameFor(parseIpAddress("198.18.0.2")).get == "two.test"

  test "the default pool stays inside 198.18.0.0/15":
    var p = initFakePool(size = DefaultFakePoolSize)
    check $p.fakeFor("last.test").get == "198.18.0.1"
    check DefaultFakePoolSize == 131_071
    var q = initFakePool(size = 3)
    check $q.fakeFor("x.test").get == "198.18.0.1"
    check $q.fakeFor("y.test").get == "198.18.0.2"
    check $q.fakeFor("z.test").get == "198.18.0.3"
    # 198.18.0.0 + 131071 = 198.19.255.255, the /15's last address
    check 0xC6120000'u32 + DefaultFakePoolSize == 0xC613FFFF'u32
