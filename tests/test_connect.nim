import std/[nativesockets, net, os, posix, strutils, times, unittest]
import sandwall/wall

## Unit tests for the SOCKS5 client handshake in wall/connect.nim.
## socksConnect's stdin/stdout pump is a terminal concern; here we test
## the handshake by faking stdio through pipes.

proc startEcho(): tuple[sock: Socket, port: uint16] =
  result.sock = newSocket(buffered = false)
  result.sock.setSockOpt(OptReuseAddr, true)
  result.sock.bindAddr(Port(0), "127.0.0.1")
  result.sock.listen()
  result.port = uint16(result.sock.getLocalAddr()[1])
  type Ctx = tuple[sock: Socket]
  let slot = cast[ptr Thread[Ctx]](allocShared0(sizeof(Thread[Ctx])))
  createThread(slot[], proc(a: Ctx) {.thread.} =
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
  , (sock: result.sock))

var tmpDir: string
var echoSock {.threadvar.}: Socket
var echoPort {.threadvar.}: uint16

proc withFakeStdio(stdinData: string; body: proc(): int):
    tuple[code: int, outData: string] =
  ## Run `body` with fd 0 fed `stdinData` and fd 1 captured; restore
  ## the real fds afterwards. Single-threaded test process, so the
  ## temporary fd swap is safe.
  var inPipe: array[2, cint]
  var outPipe: array[2, cint]
  discard posix.pipe(inPipe)
  discard posix.pipe(outPipe)
  let savedIn = posix.dup(0)
  let savedOut = posix.dup(1)
  discard posix.dup2(inPipe[0], 0)
  discard posix.dup2(outPipe[1], 1)
  discard posix.close(inPipe[0])
  discard posix.close(outPipe[1])
  # Feed stdin from a thread so a large payload cannot deadlock the pipe.
  type Feed = tuple[fd: cint, data: string]
  let slot = cast[ptr Thread[Feed]](allocShared0(sizeof(Thread[Feed])))
  createThread(slot[], proc(a: Feed) {.thread.} =
    var off = 0
    while off < a.data.len:
      let w = posix.write(a.fd, unsafeAddr a.data[off], a.data.len - off)
      if w <= 0: break
      off.inc w
    discard posix.close(a.fd)
  , (inPipe[1], stdinData))
  let code = body()
  discard posix.close(1)   # EOF for the reader
  discard posix.dup2(savedIn, 0)
  discard posix.dup2(savedOut, 1)
  discard posix.close(savedIn)
  discard posix.close(savedOut)
  var outData = ""
  var buf = newString(4096)
  while true:
    let n = posix.read(outPipe[0], addr buf[0], 4096)
    if n <= 0: break
    outData.setLen(outData.len + n)
    copyMem(addr outData[outData.len - n], addr buf[0], n)
  discard posix.close(outPipe[0])
  (code, outData)

suite "wall connect":
  setup:
    tmpDir = getTempDir() / "sandwall_connect_" & $getCurrentProcessId()
    createDir(tmpDir)
    if echoSock == nil:
      (echoSock, echoPort) = startEcho()
  teardown:
    removeDir(tmpDir)

  test "SOCKS5 handshake against the wall proxy, tunnel carries bytes":
    let policy = tmpDir / "policy.txt"
    writeFile(policy, "allow 127.0.0.1:" & $echoPort & "\n")
    var p = startWallProxy(policy, tmpDir)
    defer: p.stopWallProxy()
    let (code, outData) = withFakeStdio("ping\n") do () -> int:
      socksConnect(p.port, "127.0.0.1", echoPort)
    check code == 0
    check outData == "ping\n"

  test "denied target returns 1":
    let policy = tmpDir / "policy.txt"
    writeFile(policy, "allow example.com\n")
    var p = startWallProxy(policy, tmpDir)
    defer: p.stopWallProxy()
    let (code, _) = withFakeStdio("") do () -> int:
      socksConnect(p.port, "127.0.0.1", echoPort)
    check code == 1

  test "no proxy listening returns 1":
    let (code, _) = withFakeStdio("") do () -> int:
      socksConnect(1, "127.0.0.1", echoPort)
    check code == 1
