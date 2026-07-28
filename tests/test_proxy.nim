import std/[nativesockets, net, os, posix, strutils, times, unittest]
import sandwall/wall

## Live loopback tests for the wall proxy. Hermetic: everything binds
## 127.0.0.1:0 and only 127.0.0.1/localhost are ever contacted.

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
      let c = posix.accept(a.sock.getFd(), nil, nil)
      if c == osInvalidSocket: continue
      var buf = newString(4096)
      while true:
        let n = posix.recv(c, addr buf[0], 4096, 0'i32)
        if n <= 0: break
        var off = 0
        while off < n:
          let s = posix.send(c, addr buf[off], (n - off).cint, 0'i32)
          if s <= 0: break
          off.inc s
      discard posix.close(c)
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
    var pfd = TPollfd(fd: c.getFd().cint, events: POLLIN)
    if poll(addr pfd, 1, remain.cint) <= 0:
      raise newException(ValueError, "recvLine timeout")
    let n = posix.recv(c.getFd(), addr b[0], 1, 0'i32)
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

suite "wall proxy":
  setup:
    tmpDir = getTempDir() / "sandwall_proxy_" & $getCurrentProcessId()
    createDir(tmpDir)
    if echoSock == nil:
      (echoSock, echoPort) = startEcho()
  teardown:
    removeDir(tmpDir)

  test "CONNECT allow tunnels bytes, port-restricted deny gets 403":
    withPolicy "+127.0.0.1:" & $echoPort & "\n":
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

  test "plain HTTP GET gets 405":
    withPolicy "+127.0.0.1\n":
      var p = startWallProxy(path, tmpDir)
      defer: p.stopWallProxy()
      let c = dial("127.0.0.1", Port(p.port), buffered = false)
      c.send("GET http://example.com/ HTTP/1.1\c\LHost: example.com\c\L\c\L")
      var line = ""
      line = recvLine(c, 5_000)
      check line.contains("405")
      c.close()

  test "SOCKS5 allow and ruleset deny":
    withPolicy "+localhost\n":
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
    withPolicy "+example.com\n":
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
      discard writePolicy("+127.0.0.1\n")
      setLastModificationTime(path, getTime() + initDuration(seconds = 2))
      c = dial("127.0.0.1", Port(p.port), buffered = false)
      c.send("CONNECT 127.0.0.1:" & $echoPort & " HTTP/1.1\c\L\c\L")
      line = ""
      line = recvLine(c, 5_000)
      check line.contains("200")
      c.close()
