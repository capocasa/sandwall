## dns: the fence DNS codec and the fake-IP pool.
##
## Inside the netns the only resolver is the forwarder, reached through
## the bridge's UDP relay (netns.nim). A query for a name the policy
## allows is answered with a stable synthetic address out of
## 198.18.0.0/15 and never a real one: the forwarder resolves the name
## at connect time and re-checks the name's policy then (proxy.nim, the
## raw path). So the pool maps name -> fake-IP and nothing else; the
## binding outlives the netns because the forwarder does.
##
## The answers:
##
##   A, allowed            the fake-IP
##   AAAA, allowed         NOERROR, no answers (the pool is IPv4)
##   denied                NXDOMAIN
##   allowed, no address   SERVFAIL
##   any other type        NOTIMP
##
## The question is echoed byte for byte (case included) and EDNS0 OPT
## records are ignored, not echoed. Queries carry no compression, so
## none is parsed. This module is the wire format and the pool; the
## policy decision is the caller's, through `reply`'s `decide`.

import std/[net, options, strutils, tables]

const
  FakePoolNetwork* = "198.18.0.0/15"
  DefaultFakePoolSize* = 131_071'u32  ## the /15 minus its network address
  DnsMaxPacket* = 4096
  AnswerTtl* = 60'u32                 ## seconds; the binding is stable anyway
  QClassIn* = 1'u16

type
  QType* = enum
    qtA = 1
    qtAAAA = 28

  Rcode* {.pure.} = enum
    rcNoError = 0
    rcFormError = 1
    rcServFail = 2
    rcNxDomain = 3
    rcNotImp = 4

  DnsQuery* = object
    id*: uint16
    opcode*: uint8
    recursionDesired*: bool
    name*: string            ## lowercase, no trailing dot; "" for the root
    qname*: seq[uint8]       ## the qname as received, echoed byte for byte
    qtype*: uint16
    qclass*: uint16

  DnsDecision* {.pure.} = enum
    ddFake       ## the policy allows the name: answer with the address
    ddNxDomain   ## denied: as far as the fence knows the name does not exist
    ddServFail   ## allowed, but nothing stands behind it right now

  Decide* = proc (name: string): tuple[decision: DnsDecision, ip: IpAddress]
    {.gcsafe, raises: [].}

  FakePool* = object
    ## Name -> stable fake address, lowest free one first, never
    ## released: a binding is good for the forwarder's lifetime, so
    ## nothing that learned one is ever sent to a name that came later.
    ## Not thread-safe; the owner serializes (proxy.nim).
    names: seq[string]         ## binding i
    index: Table[string, int]  ## lowercase name -> binding
    size: uint32               ## bindings the pool can hold

# ------------------------------------------------------------- codec

proc be16(buf: openArray[uint8]; at: int): uint16 =
  (uint16(buf[at]) shl 8) or uint16(buf[at + 1])

proc put16(buf: var seq[uint8]; v: uint16) =
  buf.add uint8(v shr 8)
  buf.add uint8(v and 0xff)

proc put32(buf: var seq[uint8]; v: uint32) =
  buf.add uint8(v shr 24)
  buf.add uint8((v shr 16) and 0xff)
  buf.add uint8((v shr 8) and 0xff)
  buf.add uint8(v and 0xff)

proc decodeQname(buf: openArray[uint8]; pos: int):
    tuple[wire: seq[uint8], name: string, next: int] =
  ## The qname at `pos`: its bytes as received, its lowercase dotted
  ## form, and the offset just past it.
  var p = pos
  while true:
    if p >= buf.len: raise newException(ValueError, "qname truncated")
    let n = int(buf[p])
    inc p
    if n == 0: break
    if n > 63:
      raise newException(ValueError, "qname label too long or compressed")
    if p + n > buf.len: raise newException(ValueError, "qname truncated")
    if result.name.len > 0: result.name.add '.'
    for i in 0 ..< n: result.name.add char(buf[p + i])
    p.inc n
    if result.name.len > 255:
      raise newException(ValueError, "qname too long")
  result.wire = newSeq[uint8](p - pos)
  copyMem(addr result.wire[0], unsafeAddr buf[pos], result.wire.len)
  result.name = result.name.toLowerAscii
  result.next = p

proc parseQuery*(buf: openArray[uint8]): DnsQuery =
  ## The question of a query datagram. Raises ValueError when it is not
  ## one well-formed question (a short header, a compressed qname, a
  ## second question): a reply cannot echo what it cannot read.
  if buf.len < 12: raise newException(ValueError, "header truncated")
  result.id = be16(buf, 0)
  let flags = be16(buf, 2)
  result.opcode = uint8((flags shr 11) and 0xF)
  result.recursionDesired = (flags and 0x0100) != 0
  if be16(buf, 4) != 1: raise newException(ValueError, "expected one question")
  let (wire, name, next) = decodeQname(buf, 12)
  if next + 4 > buf.len: raise newException(ValueError, "question truncated")
  result.qname = wire
  result.name = name
  result.qtype = be16(buf, next)
  result.qclass = be16(buf, next + 2)

proc header(id: uint16; flags, qd, an, ns, ar: uint16): seq[uint8] =
  result = newSeq[uint8]()
  result.put16 id
  result.put16 flags
  result.put16 qd
  result.put16 an
  result.put16 ns
  result.put16 ar

proc servFail*(id: uint16): seq[uint8] =
  ## A header-only SERVFAIL for a query that could not be read.
  header(id, 0x8000'u16 or uint16(rcServFail), 0, 0, 0, 0)

proc respond*(q: DnsQuery; rcode: Rcode; answer = none(IpAddress)):
    seq[uint8] =
  ## The reply to `q`: the question echoed as received, one A answer
  ## when `answer` is set (rcode NOERROR then), nothing else.
  var flags = 0x8000'u16 or (uint16(q.opcode) shl 11) or uint16(rcode)
  if q.recursionDesired: flags = flags or 0x0100'u16
  result = header(q.id, flags, 1, uint16(answer.isSome), 0, 0)
  result.add q.qname
  result.put16 q.qtype
  result.put16 q.qclass
  if answer.isSome:
    result.add q.qname
    result.put16 q.qtype
    result.put16 QClassIn
    result.put32 AnswerTtl
    result.put16 4
    for b in answer.get.address_v4: result.add b

proc reply*(query: openArray[uint8]; decide: Decide): seq[uint8] =
  ## The datagram to send back for `query`. `decide` is asked about
  ## the lowercase name; see the module header for the answers.
  var q: DnsQuery
  try:
    q = parseQuery(query)
  except ValueError:
    return servFail(if query.len >= 2: be16(query, 0) else: 0)
  if q.opcode != 0 or q.qclass != QClassIn or
      (q.qtype != uint16(qtA) and q.qtype != uint16(qtAAAA)):
    return q.respond(rcNotImp)
  if q.name.len == 0: return q.respond(rcNxDomain)
  let (decision, ip) = decide(q.name)
  case decision
  of ddNxDomain: q.respond(rcNxDomain)
  of ddServFail: q.respond(rcServFail)
  of ddFake:
    if q.qtype == uint16(qtAAAA): q.respond(rcNoError)   # NODATA
    else: q.respond(rcNoError, some(ip))

# --------------------------------------------------------------- pool

proc copy(s: string): string =
  ## A string sharing no allocation with `s`.
  if s.len == 0: return ""
  result = newString(s.len)
  copyMem(addr result[0], unsafeAddr s[0], s.len)

proc addressOf(index: uint32): IpAddress =
  ## Binding `index`: 198.18.0.1 upward.
  let v = 0xC6120000'u32 + index + 1'u32
  IpAddress(family: IpAddressFamily.IPv4,
            address_v4: [uint8(v shr 24), uint8((v shr 16) and 0xff),
                        uint8((v shr 8) and 0xff), uint8(v and 0xff)])

proc initFakePool*(size = DefaultFakePoolSize): FakePool =
  ## An empty pool with room for `size` bindings.
  FakePool(size: size)

proc len*(p: FakePool): int =
  p.names.len

proc fakeFor*(p: var FakePool; name: string): Option[IpAddress] =
  ## The fake address bound to `name` (lowercase, as the DNS layer
  ## hands it over), allocating the lowest free one when the name is
  ## new. `none` when the pool is exhausted: every binding is live.
  let key = name.toLowerAscii
  if p.index.hasKey(key): return some(addressOf(uint32(p.index[key])))
  if p.names.len.uint32 >= p.size: return none(IpAddress)
  let i = p.names.len
  p.names.add copy(key)
  p.index[copy(key)] = i
  some(addressOf(uint32(i)))

proc nameFor*(p: FakePool; ip: IpAddress): Option[string] =
  ## The name bound to `ip`, as a private copy; `none` when `ip` is not
  ## one of this pool's addresses.
  if ip.family != IpAddressFamily.IPv4: return none(string)
  let a = ip.address_v4
  let v = (uint32(a[0]) shl 24) or (uint32(a[1]) shl 16) or
          (uint32(a[2]) shl 8) or uint32(a[3])
  if v <= 0xC6120000'u32: return none(string)
  let i = v - 0xC6120000'u32 - 1'u32
  if i >= p.names.len.uint32: return none(string)
  some(copy(p.names[i]))
