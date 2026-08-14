import std/[nativesockets, net, os, posix, strutils, times, unittest]
import sandwall
import sandwall/wall

## Tests for the POSIX network fences. Every fenced scenario runs in a
## forked child so the test process itself stays un-fenced (same
## fork/wait pattern as test_sandbox.nim).

when defined(linux):
  proc runScenario(body: proc(): bool): bool =
    let pid = forkNimbox()
    if pid == 0:
      var ok = false
      try: ok = body()
      except CatchableError: ok = false
      exitnow(if ok: 0 else: 1)
    result = int(wait(pid)) == 0

  proc tryConnect(host: string; port: uint16; timeoutMs: int): bool =
    ## true when the connect succeeds within the timeout.
    let fd = posix.socket(AF_INET, SOCK_STREAM, 0)
    if fd == osInvalidSocket: return false
    defer: discard posix.close(fd)
    let nb = fcntl(fd, F_GETFL, 0)
    discard fcntl(fd, F_SETFL, nb or O_NONBLOCK)
    var sa: Sockaddr_in
    sa.sin_family = TSa_Family(AF_INET)
    sa.sin_port = nativesockets.htons(port)
    sa.sin_addr.s_addr = inet_addr(host)
    let r = posix.connect(fd, cast[ptr SockAddr](addr sa),
                          SockLen(sizeof(sa)))
    if r == 0: return true
    if osLastError().cint != EINPROGRESS: return false
    var pfd = TPollfd(fd: fd.cint, events: POLLOUT)
    if poll(addr pfd, 1, timeoutMs.cint) <= 0: return false
    var soerr: cint
    var slen = SockLen(sizeof(soerr))
    if getsockopt(fd, SOL_SOCKET, SO_ERROR, addr soerr, addr slen) != 0:
      return false
    soerr == 0

  suite "wall netns fence (linux)":
    test "netns keeps loopback, kills external egress":
      check runScenario(proc(): bool =
        # A fresh netns has only its own `lo`, so listener and client
        # both live INSIDE the fence: loopback must stay alive.
        try:
          enterNetns()
        except OSError:
          # userns unavailable on this host: skip (warn-and-continue
          # posture; nothing to assert)
          return true
        let srv = newSocket(buffered = false)
        srv.setSockOpt(OptReuseAddr, true)
        srv.bindAddr(Port(0), "127.0.0.1")
        srv.listen()
        let port = uint16(srv.getLocalAddr()[1])
        if not tryConnect("127.0.0.1", port, 2_000): return false
        # documentation IP, guaranteed dead: any fast failure passes,
        # the point is it does NOT connect
        if tryConnect("192.0.2.1", 80, 1_000): return false
        true)

    test "bridge splices netns loopback to the host proxy over unix socket":
      let tmp = getTempDir() / "sandwall_wall_" & $getCurrentProcessId()
      createDir(tmp)
      defer: removeDir(tmp)
      # parent side: echo server + proxy on tcp AND a unix socket
      let echoSock = newSocket(buffered = false)
      echoSock.setSockOpt(OptReuseAddr, true)
      echoSock.bindAddr(Port(0), "127.0.0.1")
      echoSock.listen()
      let echoPort = uint16(echoSock.getLocalAddr()[1])
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
      , (sock: echoSock))
      let policy = tmp / "policy.txt"
      writeFile(policy, "allow 127.0.0.1\n")
      let sockPath = tmp / "proxy.sock"
      var p = startWallProxy(policy, tmp, unixSockPath = sockPath)
      defer: p.stopWallProxy()
      check runScenario(proc(): bool =
        try:
          enterNetns()
        except OSError:
          return true   # userns unavailable: skip
        let bridgePort = bridgeToUnix(0, sockPath)
        # SOCKS5 handshake through the bridge to the proxy, then echo
        let c = dial("127.0.0.1", Port(bridgePort), buffered = false)
        c.send("\x05\x01\x00")
        var buf = newString(64)
        if c.recv(buf, 2, 5_000) != 2 or buf[1] != '\x00': return false
        let name = "127.0.0.1"
        c.send("\x05\x01\x00\x03" & char(name.len) & name &
               char(echoPort shr 8) & char(echoPort and 0xff))
        if c.recv(buf, 10, 5_000) != 10 or buf[1] != '\x00': return false
        c.send("ping\n")
        var b: array[1, char]
        var got = ""
        while got.len < 5:
          if c.recv(buf, 1, 5_000) != 1: return false
          b[0] = buf[0]
          got.add b[0]
        got == "ping\n")

when defined(macosx):
  import sandwall/seatbelt

  suite "wall seatbelt egress fence (macos)":
    test "egress=false emits loopback-only network allows":
      let fenced = seatbelt.buildProfile(["/tmp"], [], [], egress = false)
      check "(allow network-outbound (remote ip \"localhost:*\"))" in fenced
      check "(allow network-inbound (local ip \"localhost:*\"))" in fenced
      # open egress is unrestricted: bare allows, no remote filter
      let open = seatbelt.buildProfile(["/tmp"], [], [])
      check "(allow network-outbound)\n" in open
      check "(allow network-inbound)\n" in open
      check "localhost:*" notin open

    test "readonly under a writable root subtracts the write":
      # A bare allow-read under a writable root leaves the root's
      # file-write* grant in force; readonly must punch a write-deny
      # hole (the policy-file guard relies on this).
      let p = seatbelt.buildProfile(["/tmp"], ["/tmp/policy"], [])
      check "(deny file-write*" in p
      check "(literal \"/tmp/policy\")" in p
