import std/[locks, nativesockets, net, os, strutils, times, unittest]
import sandwall/wall
import sandwall/wall/permit

## Live loopback tests for the wall proxy. Hermetic: everything binds
## 127.0.0.1:0 and only 127.0.0.1/localhost are ever contacted. The
## resolver-backed cases inject a scripted resolver and a virtual clock
## through the permit set, so no test waits on DNS or on the wall clock.

proc startEcho(): tuple[sock: Socket, port: uint16] =
  ## A one-shot TCP echo server on a background thread.
  result.sock = newSocket(buffered = false)
  result.sock.setSockOpt(OptReuseAddr, true)
  result.sock.bindAddr(Port(0), "127.0.0.1")
  result.sock.listen()
  result.port = uint16(result.sock.getLocalAddr()[1])
  # Detached echo thread. Heap Thread slot: createThread hands the new
  # thread a pointer into the Thread var, so a stack slot dies with
  # this frame while the child still reads the arg.
  type Ctx = tuple[sock: Socket, port: uint16]
  let slot = cast[ptr Thread[Ctx]](allocShared0(sizeof(Thread[Ctx])))
  createThread(slot[], proc(a: Ctx) {.thread.} =
    # Sequential echo loop: one client at a time is enough for the
    # tests, and accepting in a loop keeps the server alive across
    # tests that open more than one connection.
    while true:
      let c = nativesockets.accept(a.sock.getFd(), nil, nil)
      if c == osInvalidSocket: continue
      var buf = newString(4096)
      while true:
        let n = nativesockets.recv(c, addr buf[0], 4096, 0'i32)
        if n <= 0: break
        var off = 0
        while off < n:
          let s = nativesockets.send(c, addr buf[off], (n - off).cint, 0'i32)
          if s <= 0: break
          off.inc s
      nativesockets.close(c)
  , (sock: result.sock, port: result.port))

var tmpDir: string
var echoSock {.threadvar.}: Socket
var echoPort {.threadvar.}: uint16

proc recvLine(c: Socket; timeoutMs: int): string =
  ## Byte-at-a-time line reader over an unbuffered socket (the buffered
  ## net.Socket timeout path is unreliable; we keep the tests raw).
  result = ""
  let deadline = epochTime() + timeoutMs / 1000
  var b: array[1, char]
  while true:
    let remain = int((deadline - epochTime()) * 1000)
    if remain <= 0: raise newException(ValueError, "recvLine timeout")
    var fds = @[c.getFd()]
    if nativesockets.selectRead(fds, remain) <= 0:
      raise newException(ValueError, "recvLine timeout")
    let n = nativesockets.recv(c.getFd(), addr b[0], 1, 0'i32)
    if n == 0: raise newException(ValueError, "recvLine eof")
    if n < 0: raiseOSError(osLastError())
    if b[0] == '\L': return
    if b[0] != '\c': result.add b[0]

proc writePolicy(text: string): string =
  result = tmpDir / "policy.txt"
  writeFile(result, text)

template withPolicy(text: string; body: untyped) =
  let path {.inject.} = writePolicy(text)
  body

type
  Script = ref object
    ## What the proxy's permit set resolves with, and the clock it tells
    ## time by. Both are read from proxy threads: everything handed out
    ## is copied out under the lock, and only plain addresses leave.
    lock: Lock
    next: ResolveResult   ## the answer every lookup gets
    calls: int            ## lookups so far
    t: float              ## the set's idea of now

proc newScript(): Script =
  result = Script()
  initLock(result.lock)
  result.t = epochTime()

proc answer(s: Script; outcome: ResolveOutcome; ips: openArray[string] = []) =
  withLock s.lock:
    s.next = ResolveResult(outcome: outcome)
    for x in ips: s.next.ips.add parseIpAddress(x)

proc callCount(s: Script): int =
  withLock s.lock: result = s.calls

proc advance(s: Script; dt: float) =
  withLock s.lock: s.t += dt

proc permitSetFor(s: Script): PermitSet =
  ## A permit set that resolves through `s` and tells time with it.
  result = newPermitSet(resolver = proc (name: string): ResolveResult
      {.gcsafe, raises: [].} =
    withLock s.lock:
      inc s.calls
      result.outcome = s.next.outcome
      for a in s.next.ips: result.ips.add a)
  result.clock = proc (): float {.gcsafe, raises: [].} =
    withLock s.lock: result = s.t

proc connectStatus(p: WallProxy; target: string): string =
  ## The status line of a CONNECT for `target` through `p`.
  let c = dial("127.0.0.1", Port(p.port), buffered = false)
  defer: c.close()
  c.send("CONNECT " & target & " HTTP/1.1\c\L\c\L")
  recvLine(c, 5_000)

proc echoThrough(p: WallProxy; target: string): bool =
  ## CONNECT `target`, require the 200, and require the echo server's
  ## answer: the tunnel has to carry bytes end to end.
  let c = dial("127.0.0.1", Port(p.port), buffered = false)
  defer: c.close()
  c.send("CONNECT " & target & " HTTP/1.1\c\L\c\L")
  if not recvLine(c, 5_000).contains("200"): return false
  check recvLine(c, 5_000) == ""   # end of headers
  c.send("ping\n")
  recvLine(c, 5_000) == "ping"

proc socksCode(p: WallProxy; atyp: char; raw: string; port: uint16): char =
  ## A SOCKS5 CONNECT for a raw address (`raw` is ATYP's payload).
  ## Returns the reply code, '\x00' when the handshake broke off.
  let c = dial("127.0.0.1", Port(p.port), buffered = false)
  defer: c.close()
  c.send("\x05\x01\x00")
  var buf = newString(64)
  if c.recv(buf, 2, 5_000) != 2: return '\x00'
  c.send("\x05\x01\x00" & atyp & raw & char(port shr 8) & char(port and 0xff))
  if c.recv(buf, 10, 5_000) != 10: return '\x00'
  buf[1]

proc atypBytes(ip: IpAddress): string =
  ## An address as the payload of a SOCKS5 ATYP request.
  case ip.family
  of IpAddressFamily.IPv4:
    for b in ip.address_v4: result.add char(b)
  of IpAddressFamily.IPv6:
    for b in ip.address_v6: result.add char(b)

suite "wall proxy":
  setup:
    tmpDir = getTempDir() / "sandwall_proxy_" & $getCurrentProcessId()
    createDir(tmpDir)
    if echoSock == nil:
      (echoSock, echoPort) = startEcho()
  teardown:
    removeDir(tmpDir)

  test "CONNECT allow tunnels bytes, port-restricted deny gets 403":
    withPolicy "allow 127.0.0.1:" & $echoPort & "\n":
      var p = startWallProxy(path, tmpDir)
      defer: p.stopWallProxy()
      var c = dial("127.0.0.1", Port(p.port), buffered = false)
      c.send("CONNECT 127.0.0.1:" & $echoPort & " HTTP/1.1\c\L\c\L")
      var line = recvLine(c, 5_000)
      check line.contains("200")
      check recvLine(c, 5_000) == ""   # end of headers
      c.send("ping\n")
      let got = recvLine(c, 5_000)
      check got == "ping"
      c.close()
      # same host, a port the policy does not allow: 403
      c = dial("127.0.0.1", Port(p.port), buffered = false)
      let other = uint16(int(echoPort) xor 0x40)
      c.send("CONNECT 127.0.0.1:" & $other & " HTTP/1.1\c\L\c\L")
      line = recvLine(c, 5_000)
      check line.contains("403")
      c.close()

  test "plain HTTP GET is forwarded, rewritten to origin form":
    withPolicy "allow 127.0.0.1\n":
      var p = startWallProxy(path, tmpDir)
      defer: p.stopWallProxy()
      # The echo server reflects whatever the proxy forwards; the
      # request line must have been rewritten from absolute-URI form
      # to origin form, and the body must echo back through the splice.
      let c = dial("127.0.0.1", Port(p.port), buffered = false)
      c.send("GET http://127.0.0.1:" & $echoPort & "/some/path HTTP/1.1\c\L" &
             "Host: 127.0.0.1\c\L\c\L")
      let line = recvLine(c, 5_000)
      check line == "GET /some/path HTTP/1.1"
      c.close()
      # A denied host gets 403 without any upstream contact.
      let d = dial("127.0.0.1", Port(p.port), buffered = false)
      d.send("GET http://elsewhere.invalid/ HTTP/1.1\c\LHost: elsewhere.invalid\c\L\c\L")
      check recvLine(d, 5_000).contains("403")
      d.close()

  test "SOCKS5 allow and ruleset deny":
    withPolicy "allow localhost\n":
      var p = startWallProxy(path, tmpDir)
      defer: p.stopWallProxy()
      var c = dial("127.0.0.1", Port(p.port), buffered = false)
      c.send("\x05\x01\x00")
      var buf = newString(64)
      check c.recv(buf, 2, 5_000) == 2
      check buf[0] == '\x05' and buf[1] == '\x00'
      let name = "localhost"
      c.send("\x05\x01\x00\x03" & char(name.len) & name &
             char(echoPort shr 8) & char(echoPort and 0xff))
      check c.recv(buf, 10, 5_000) == 10
      check buf[1] == '\x00'
      c.send("ping\n")
      var got = ""
      got = recvLine(c, 5_000)
      check got == "ping"
      c.close()
      # disallowed name: reply code 0x02
      c = dial("127.0.0.1", Port(p.port), buffered = false)
      c.send("\x05\x01\x00")
      buf = newString(64)
      discard c.recv(buf, 2, 5_000)
      let bad = "notallowed.example"
      c.send("\x05\x01\x00\x03" & char(bad.len) & bad & "\x01\xBB")
      check c.recv(buf, 10, 5_000) == 10
      check buf[1] == '\x02'
      c.close()

  test "policy reload on mtime change":
    withPolicy "allow example.com\n":
      var p = startWallProxy(path, tmpDir)
      defer: p.stopWallProxy()
      var c = dial("127.0.0.1", Port(p.port), buffered = false)
      c.send("CONNECT 127.0.0.1:" & $echoPort & " HTTP/1.1\c\L\c\L")
      var line = ""
      line = recvLine(c, 5_000)
      check line.contains("403")
      c.close()
      # rewrite the policy, mtime pushed into the future so the change
      # is visible regardless of filesystem timestamp granularity
      discard writePolicy("allow 127.0.0.1\n")
      setLastModificationTime(path, getTime() + initDuration(seconds = 2))
      c = dial("127.0.0.1", Port(p.port), buffered = false)
      c.send("CONNECT 127.0.0.1:" & $echoPort & " HTTP/1.1\c\L\c\L")
      line = ""
      line = recvLine(c, 5_000)
      check line.contains("200")
      c.close()

  # ------------------------------------------- resolver-backed decisions

  test "a name resolves once per refresh":
    withPolicy "allow svc.test:" & $echoPort & "\n":
      let s = newScript()
      s.answer(roAddrs, ["127.0.0.1"])
      var p = startWallProxy(path, tmpDir, permit = permitSetFor(s))
      defer: p.stopWallProxy()
      check p.echoThrough("svc.test:" & $echoPort)
      check p.echoThrough("svc.test:" & $echoPort)
      check s.callCount() == 1
      s.advance(DefaultRefreshS + 1)
      check p.echoThrough("svc.test:" & $echoPort)
      check s.callCount() == 2

  test "an allowed name that does not resolve gets 502":
    withPolicy "allow gone.test:" & $echoPort & "\n":
      let s = newScript()
      s.answer(roNxdomain)
      var p = startWallProxy(path, tmpDir, permit = permitSetFor(s))
      defer: p.stopWallProxy()
      check p.connectStatus("gone.test:" & $echoPort).contains("502")
      check s.callCount() == 1

  test "a transient lookup keeps the stale address serving":
    withPolicy "allow flaky.test:" & $echoPort & "\n":
      let s = newScript()
      s.answer(roAddrs, ["127.0.0.1"])
      var p = startWallProxy(path, tmpDir, permit = permitSetFor(s))
      defer: p.stopWallProxy()
      check p.echoThrough("flaky.test:" & $echoPort)
      s.answer(roTransient)
      s.advance(DefaultRefreshS + 1)
      check p.echoThrough("flaky.test:" & $echoPort)
      check s.callCount() == 2

  test "a rotated address set falls back to the previous one":
    withPolicy "allow rotate.test:" & $echoPort & "\n":
      let s = newScript()
      s.answer(roAddrs, ["127.0.0.1"])
      var p = startWallProxy(path, tmpDir, permit = permitSetFor(s))
      defer: p.stopWallProxy()
      check p.echoThrough("rotate.test:" & $echoPort)
      # the name now resolves to an address nothing listens on
      s.answer(roAddrs, ["127.0.0.2"])
      s.advance(DefaultRefreshS + 1)
      check p.echoThrough("rotate.test:" & $echoPort)
      check s.callCount() == 2
      # past the grace the old address is no longer permitted
      s.advance(GraceS + 1)
      check p.connectStatus("rotate.test:" & $echoPort).contains("502")

  test "a bare IP is decided by address: an IP rule admits it":
    withPolicy "allow 127.0.0.1:" & $echoPort & "\n" &
                "allow [::1]:" & $echoPort & "\n":
      var p = startWallProxy(path, tmpDir)
      defer: p.stopWallProxy()
      check p.echoThrough("127.0.0.1:" & $echoPort)
      # the rule stands for one port only
      let other = uint16(int(echoPort) xor 0x40)
      check p.connectStatus("127.0.0.1:" & $other).contains("403")
      # the IPv6 rule admits ::1; nothing listens there, so it is the
      # dial that fails, not the decision
      check p.connectStatus("[::1]:" & $echoPort).contains("502")

  test "a bare IP is decided by address: an allowlist refuses it":
    withPolicy "allow names.test\n":
      var p = startWallProxy(path, tmpDir)
      defer: p.stopWallProxy()
      check p.connectStatus("127.0.0.1:" & $echoPort).contains("403")
      check p.socksCode('\x01', atypBytes(parseIpAddress("127.0.0.1")),
                        echoPort) == '\x02'
      check p.socksCode('\x04', atypBytes(parseIpAddress("::1")),
                        echoPort) == '\x02'

  test "an allowed name's address is admitted on its own":
    withPolicy "allow svc.test:" & $echoPort & "\n":
      let s = newScript()
      s.answer(roAddrs, ["127.0.0.1"])
      var p = startWallProxy(path, tmpDir, permit = permitSetFor(s))
      defer: p.stopWallProxy()
      check p.echoThrough("svc.test:" & $echoPort)
      # the address the name resolved to is now permitted by itself,
      # and deciding that needs no lookup
      check p.echoThrough("127.0.0.1:" & $echoPort)
      check s.callCount() == 1
