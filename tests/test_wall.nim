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

when defined(linux):
  import std/[options, strutils]
  import sandwall/wall/permit

  proc recvSome(c: Socket; timeoutMs = 5_000): string =
    ## Whatever the socket has within the timeout, "" at EOF or timeout.
    var pfd = TPollfd(fd: c.getFd().cint, events: POLLIN, revents: 0)
    if poll(addr pfd, 1, timeoutMs.cint) <= 0: return ""
    var buf = newString(4096)
    let n = nativesockets.recv(c.getFd(), addr buf[0], 4096, 0'i32)
    if n <= 0: return ""
    buf[0 ..< n]

  proc resolveHere(name: string): seq[IpAddress] =
    ## What this process's resolver says, the way a plain client asks.
    var it = getAddrInfo(name, Port(0))
    defer: freeAddrInfo(it)
    while it != nil:
      if it.ai_addr != nil and it.ai_family == toInt(AF_INET):
        let sa = cast[ptr Sockaddr_in](it.ai_addr)
        var ip = IpAddress(family: IpAddressFamily.IPv4)
        copyMem(addr ip.address_v4[0], addr sa.sin_addr, 4)
        result.add ip
      it = it.ai_next

  proc inFakePool(ip: IpAddress): bool =
    ip.family == IpAddressFamily.IPv4 and ip.address_v4[0] == 198'u8 and
      (ip.address_v4[1] == 18'u8 or ip.address_v4[1] == 19'u8)

  suite "wall raw mode (linux, needs userns + nft)":
    test "fence DNS answers, nft redirects, the forwarder decides":
      # Host side: an echo server and the forwarder with its unix
      # listener and the fence DNS socket; the resolver is scripted so
      # no test waits on real DNS. The child then enters the netns and
      # puts the raw fence up exactly as restrict() would, without the
      # Landlock and exec in between: the test code is the command.
      let tmp = getTempDir() / "sandwall_raw_" & $getCurrentProcessId()
      createDir(tmp)
      defer: removeDir(tmp)
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
      writeFile(policy, "allow svc.test:" & $echoPort & "\nallow gone.test\n")
      let loopback = parseIpAddress("127.0.0.1")
      let ps = newPermitSet(resolver = proc (name: string): ResolveResult
          {.gcsafe, raises: [].} =
        if name == "svc.test":
          ResolveResult(outcome: roAddrs, ips: @[loopback])
        else:
          ResolveResult(outcome: roNxdomain))
      let sockPath = tmp / "proxy.sock"
      let dnsPath = tmp / "dns.sock"
      var p = startWallProxy(policy, tmp, unixSockPath = sockPath,
                             permit = ps, dnsSockPath = dnsPath)
      defer: p.stopWallProxy()
      # The gate is the child's to judge: it is the one entering the
      # netns. Exit 2 = no userns or no nft here, a skip, not a failure.
      let gate = forkNimbox()
      if gate == 0:
        try:
          enterNetns()
        except OSError:
          exitnow(2)
        exitnow(if findNft().len == 0: 2 else: 0)
      var gstatus: cint
      discard posix.waitpid(gate, gstatus, 0)
      if WIFEXITED(gstatus) and WEXITSTATUS(gstatus) == 2:
        echo "  skipped: userns or nft unavailable on this host"
        skip()
      else:
        check runScenario(proc(): bool =
          try:
            enterNetns()
          except OSError:
            return false
          var f = prepareRawFence(sockPath, dnsPath)
          startRawBridges(f)
          # the child's own loopback listener stays reachable: the
          # redirect is for non-loopback only
          let own = newSocket(buffered = false)
          own.setSockOpt(OptReuseAddr, true)
          own.bindAddr(Port(0), "127.0.0.1")
          own.listen()
          let ownPort = uint16(own.getLocalAddr()[1])
          if not tryConnect("127.0.0.1", ownPort, 2_000): return false
          # the fence DNS: an allowed name resolves to a pool address
          # (through the relay, to the forwarder), a denied one does not
          let addrs = resolveHere("svc.test")
          if addrs.len == 0 or not inFakePool(addrs[0]): return false
          var denied = false
          try:
            discard resolveHere("elsewhere.test")
          except CatchableError:
            denied = true
          if not denied: return false
          var gone = false      # allowed, but no address: SERVFAIL
          try:
            discard resolveHere("gone.test")
          except CatchableError:
            gone = true
          if not gone: return false
          # plain connect by name through the redirect: the forwarder
          # maps the fake-IP back to the name and the echo answers
          let c = dial("svc.test", Port(echoPort), buffered = false)
          c.send("ping\n")
          if recvSome(c) != "ping\n": return false
          c.close()
          # a port the rule does not stand for: the forwarder logs DENY
          # (visible above) and closes; the client sees EOF
          let d = dial("svc.test", Port(23), buffered = false)
          d.send("hello\n")
          if recvSome(d, 3_000) != "": return false
          d.close()
          true)
      check p.port != 0

# Profile generation is pure string assembly, so it runs on every
# POSIX host (the seatbelt module itself links on Linux too).
when defined(posix):
  import sandwall/seatbelt

  suite "seatbelt egress fence profile":
    test "egress=false emits loopback-only network allows":
      let fenced = seatbelt.buildProfile(["/tmp"], [], [], egress = false)
      check "(allow network-outbound (remote ip \"localhost:*\"))" in fenced
      check "(allow network-inbound (local ip \"localhost:*\"))" in fenced
      # unix IPC survives the fence: a fenced build still needs its
      # local sockets (MSBuild worker nodes under the temp dir), and
      # unix sockets are no more network-namespaced on Linux - the
      # netns fence leaves them to the path rules there too.
      check "(allow network-bind (local unix-socket\n" &
        "  (subpath \"/private/tmp\")))" in fenced
      check "(allow network-outbound (remote unix-socket\n" &
        "  (subpath \"/private/tmp\")))" in fenced
      # open egress is unrestricted: bare allows, no remote filter
      let open = seatbelt.buildProfile(["/tmp"], [], [])
      check "(allow network-outbound)\n" in open
      check "(allow network-inbound)\n" in open
      check "localhost:*" notin open
      # the open branch's unfiltered allows are not unix socket grants:
      # TCP is unrestricted, unix sockets stay path-scoped
      check "(allow network-bind (local unix-socket))" notin open

    test "readonly under a writable root subtracts the write":
      # A bare allow-read under a writable root leaves the root's
      # file-write* grant in force; readonly must punch a write-deny
      # hole (the policy-file guard relies on this). The literal is
      # the privatized spelling: seatbelt rewrites /tmp and friends
      # to their /private targets because subpath filters match the
      # resolved vnode path.
      let p = seatbelt.buildProfile(["/tmp"], ["/tmp/policy"], [])
      check "(deny file-write*" in p
      check "(literal \"/private/tmp/policy\")" in p
      check "(literal \"/tmp/policy\")" notin p
