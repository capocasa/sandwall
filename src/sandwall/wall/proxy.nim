## proxy: the wall's single network egress point.
##
## A threaded HTTP CONNECT + SOCKS5 proxy on 127.0.0.1 that enforces the
## policy's HostList per target and hot-reloads the policy file on mtime
## change. Fenced processes reach the outside world only through here,
## so the fence (chunk 3) can be simple: block everything, permit
## loopback. Compiles on POSIX (poll) and Windows (WSAPoll); the unix
## listener is POSIX-only.
##
## Access control: the listener binds 127.0.0.1 only, never 0.0.0.0, and
## there is no authentication. Loopback binding IS the access control -
## any local process may use the proxy, by design; the confinement lives
## on the sandboxed side, which cannot reach anywhere else.
##
## The allow decision is purely string-based on the name the client
## requested (see hosts.nim). DNS resolution happens here, after the
## allow decision, via the OS resolver. Denies are logged to stderr;
## allows are silent unless `verbose` is set.

import std/[locks, nativesockets, net, os, strutils, syncio, times]
when defined(posix):
  import std/posix
else:
  import winlean except Socket

import ../rules
import ./hosts

type
  ClientArg = ref object
    ## Handoff to a per-connection worker thread. A ref (GC heap), not
    ## allocShared: nim refs are thread-safe to pass between threads as
    ## long as only one thread owns it at a time, which is exactly the
    ## accept -> worker handoff here. (allocShared'd memory holding a
    ## ptr back into ProxyShared is fine too, but ref is simpler.)
    sh: ptr ProxyShared
    fd: SocketHandle

  WallProxy* = object
    sock: Socket              ## listener on 127.0.0.1
    acceptCtx: pointer        ## heap ProxyCtx for stopWallProxy
    port*: uint16             ## actual bound port
    policyPath*: string       ## file to reload on mtime change
    projectDir*: string       ## for relative policy targets
    verbose*: bool

  ProxyShared = object
    ## Everything the accept/client threads need, heap-allocated and
    ## shared. `list` holds the allowlist under `lock`; `listMtime` is
    ## written only by the accept thread.
    lock: Lock
    list: HostList
    listMtime: float
    policyPath: string
    projectDir: string
    verbose: bool
    listeners: seq[SocketHandle]  ## tcp listener, then optional unix socket
    running: bool

  ProxyCtx = ref object
    sh: ProxyShared
    acceptThread: Thread[ptr ProxyShared]

const
  handshakeTimeout = 30_000   ## ms to read the initial request
  upstreamTimeout = 15_000    ## ms to connect+read the upstream
  spliceBuf = 64 * 1024

when defined(windows):
  # Minimal winsock portability layer: the proxy code below is written
  # against poll/recv/send/close; on Windows those map to WSAPoll and
  # the ws2_32 calls. closesocket comes from wfp.nim's winlean (this
  # module's own winlean import excludes Socket, so an unqualified
  # import would collide).
  import std/winlean as wl
  # SocketHandle is already `int` in winlean, so only
  # the narrow casts differ (handles stay in the low 32 bits in
  # practice; every socket this file creates goes through WSAPoll for
  # readiness, so a handle that does not would simply stall, never
  # corrupt).
  type
    TPollfdW = object
      fd: SocketHandle
      events, revents: int16
  proc wsaPoll(fds: ptr TPollfdW; nfds: culong; timeout: cint): cint
    {.stdcall, dynlib: "ws2_32", importc: "WSAPoll".}
  proc wsaRecv(s: SocketHandle; buf: pointer; len, flags: cint): cint
    {.stdcall, dynlib: "ws2_32", importc: "recv".}
  proc wsaSend(s: SocketHandle; buf: pointer; len, flags: cint): cint
    {.stdcall, dynlib: "ws2_32", importc: "send".}
  proc wsaSocket(af, typ, protocol: cint): SocketHandle
    {.stdcall, dynlib: "ws2_32", importc: "socket".}
  proc wsaConnect(s: SocketHandle; name: ptr SockAddr; namelen: cint): cint
    {.stdcall, dynlib: "ws2_32", importc: "connect".}
  proc wsaAccept(s: SocketHandle; a: ptr SockAddr; n: ptr cint): SocketHandle
    {.stdcall, dynlib: "ws2_32", importc: "accept".}
  proc wsaShutdown(s: SocketHandle; how: cint): cint
    {.stdcall, dynlib: "ws2_32", importc: "shutdown".}
  proc wsaIoctl(s: SocketHandle; cmd: clong; argp: ptr culong): cint
    {.stdcall, dynlib: "ws2_32", importc: "ioctlsocket".}
  proc inetNtopW(family: cint; pAddr: pointer; buf: WideCString;
                 len: csize_t): WideCString
    {.stdcall, dynlib: "ws2_32", importc: "InetNtopW".}
  const
    POLLIN_W: int16 = 0x0300    # POLLRDNORM|POLLRDBAND
    POLLOUT_W: int16 = 0x0010   # POLLWRNORM
    POLLERR_W: int16 = 0x0001
    POLLHUP_W: int16 = 0x0002
    POLLNVAL_W: int16 = 0x0004
    FIONBIO_W: clong = -2147195266  # 0x8004667E as signed long
  proc pollW(fds: ptr TPollfdW; nfds: int; timeout: cint): cint =
    wsaPoll(fds, nfds.culong, timeout)
  template interruptedW(): bool = osLastError().cint == WSAEINTR

proc closeSock(fd: SocketHandle) =
  when defined(posix):
    discard posix.close(fd)
  else:
    discard wl.closesocket(fd)

# ------------------------------------------------------------- policy

proc loadList(sh: var ProxyShared) =
  ## Load (or reload) the allowlist from the policy file.
  let hosts = loadPolicy(sh.policyPath, sh.projectDir).resolve().hosts
  let l = hosts.toHostList()
  withLock sh.lock:
    sh.list = l
  sh.listMtime =
    if fileExists(sh.policyPath):
      getLastModificationTime(sh.policyPath).toUnixFloat()
    else: 0.0

proc maybeReload(sh: var ProxyShared) =
  ## Called before each accept: one stat per connection, reload on
  ## mtime change. Cheap enough to keep the proxy always current.
  let m = if fileExists(sh.policyPath):
            getLastModificationTime(sh.policyPath).toUnixFloat()
          else: 0.0
  if m != sh.listMtime: sh.loadList()

proc allowed(sh: var ProxyShared; host: string; port: uint16): bool =
  withLock sh.lock:
    result = sh.list.allows(host, port)
  if not result:
    stderr.writeLine("sandwall proxy: DENY " & host & ":" & $port)
  elif sh.verbose:
    stderr.writeLine("sandwall proxy: allow " & host & ":" & $port)

# ---------------------------------------------------------- raw fds
# After the handshake everything runs on unbuffered fds under poll();
# using net.Socket's buffered reads would hide already-buffered bytes
# from poll.

proc recvFd(fd: SocketHandle; buf: pointer; len: int; timeoutMs = -1): int =
  ## Blocking read of exactly `len` bytes with an optional overall
  ## millisecond timeout via poll. SOCKS5 greeting/request fields are
  ## fixed-size and the peer may split them across packets (the unix
  ## bridge splices whatever chunks the TCP side delivered), so a
  ## single short recv must not truncate the message. Returns -1 on
  ## error/EOF-before-complete, `len` on success.
  var off = 0
  let deadline = if timeoutMs >= 0: epochTime() + timeoutMs / 1000
                 else: 0.0
  while off < len:
    if timeoutMs >= 0:
      let remain = int((deadline - epochTime()) * 1000)
      if remain <= 0: return -1
      when defined(posix):
        var pfd = TPollfd(fd: fd.cint, events: POLLIN)
        let r = poll(addr pfd, 1, remain.cint)
        if r <= 0: return -1
        if (pfd.revents and (POLLERR or POLLNVAL)) != 0: return -1
        if (pfd.revents and POLLIN) == 0: return -1  # HUP without data
      else:
        var pfd = TPollfdW(fd: fd, events: POLLIN_W)
        let r = pollW(addr pfd, 1, remain.cint)
        if r <= 0: return -1
        if (pfd.revents and (POLLERR_W or POLLNVAL_W)) != 0: return -1
        if (pfd.revents and POLLIN_W) == 0: return -1
    when defined(posix):
      let n = posix.recv(fd, cast[pointer](cast[int](buf) + off),
                         (len - off).cint, 0'i32).int
    else:
      let n = wsaRecv(fd, cast[pointer](cast[int](buf) + off),
                      (len - off).cint, 0).int
    if n <= 0: return -1
    off.inc n
  len

proc sendFd(fd: SocketHandle; data: string): bool =
  ## Write all of `data`, ignoring SIGPIPE.
  var off = 0
  while off < data.len:
    when defined(posix):
      let flags = when defined(linux): MSG_NOSIGNAL else: 0'i32
      let n = posix.send(fd, addr data[off], (data.len - off).cint, flags)
      if n <= 0:
        if n < 0 and osLastError().cint == EINTR: continue
        return false
      off.inc n
    else:
      let n = wsaSend(fd, addr data[off], (data.len - off).cint, 0)
      if n <= 0:
        if n < 0 and interruptedW(): continue
        return false
      off.inc n
  true

proc dialUp(host: string; port: uint16): SocketHandle =
  ## Resolve and connect to `host:port` with a single overall timeout.
  ## DNS resolution happens here, after the allow decision, via the OS
  ## resolver. Returns osInvalidSocket on failure.
  var aiList: ptr AddrInfo
  let portStr = $port
  if getaddrinfo(host, portStr.cstring, nil, aiList) != 0:
    return osInvalidSocket
  defer: freeAddrInfo(aiList)
  let deadline = epochTime() + upstreamTimeout / 1000
  var it = aiList
  while it != nil:
    when defined(posix):
      let fd = posix.socket(it.ai_family, it.ai_socktype, it.ai_protocol)
    else:
      let fd = wsaSocket(it.ai_family, it.ai_socktype, it.ai_protocol)
    if fd != osInvalidSocket:
      when defined(posix):
        let nb = fcntl(fd, F_GETFL, 0)
        if nb >= 0:
          discard fcntl(fd, F_SETFL, nb or O_NONBLOCK)
          if posix.connect(fd, it.ai_addr, it.ai_addrlen) < 0:
            let err = osLastError().cint
            if err == EINPROGRESS:
              let remain = int((deadline - epochTime()) * 1000)
              if remain > 0:
                var pfd = TPollfd(fd: fd.cint, events: POLLOUT)
                if poll(addr pfd, 1, remain.cint) > 0 and
                   (pfd.revents and POLLOUT) != 0:
                  var soerr: cint
                  var slen = SockLen(sizeof(soerr))
                  if getsockopt(fd, SOL_SOCKET, SO_ERROR, addr soerr,
                                addr slen) == 0 and soerr == 0:
                    discard fcntl(fd, F_SETFL, nb)  # back to blocking
                    return fd
            elif err == EINTR:
              discard fcntl(fd, F_SETFL, nb)
              return fd
        discard posix.close(fd)
      else:
        var nbMode: culong = 1
        if wsaIoctl(fd, FIONBIO_W, addr nbMode) == 0:
          if wsaConnect(fd, it.ai_addr, it.ai_addrlen.cint) < 0:
            let err = osLastError().cint
            if err == WSAEWOULDBLOCK:
              let remain = int((deadline - epochTime()) * 1000)
              if remain > 0:
                var pfd = TPollfdW(fd: fd, events: POLLOUT_W)
                if pollW(addr pfd, 1, remain.cint) > 0 and
                   (pfd.revents and POLLOUT_W) != 0:
                  var soerr: cint
                  var slen = SockLen(sizeof(soerr))
                  if getsockopt(fd, SOL_SOCKET, SO_ERROR, addr soerr,
                                addr slen) == 0 and soerr == 0:
                    nbMode = 0
                    discard wsaIoctl(fd, FIONBIO_W, addr nbMode)
                    return fd
            elif err == WSAEINTR:
              nbMode = 0
              discard wsaIoctl(fd, FIONBIO_W, addr nbMode)
              return fd
        discard closesocket(fd)
    it = it.ai_next
  osInvalidSocket

# ------------------------------------------------------------- splice

proc splice(a, b: SocketHandle) =
  ## Forward bytes between `a` and `b` until both directions hit EOF,
  ## half-closing the write side on each EOF. No timeout: long-lived
  ## TLS tunnels must survive idle.
  var bufA = newString(spliceBuf)
  var bufB = newString(spliceBuf)
  var aDead = false   # a -> b direction closed
  var bDead = false   # b -> a direction closed
  proc shutdownWr(fd: SocketHandle) =
    when defined(posix):
      discard posix.shutdown(fd, SHUT_WR)
    else:
      discard wsaShutdown(fd, 1)  # SD_SEND
  while not (aDead and bDead):
    # A dead direction's fd is removed from the poll set (fd < 0
    # makes poll ignore the entry): events=0 does NOT suffice,
    # error conditions (POLLERR|POLLHUP) are reported
    # unconditionally and the loop would busy-spin on the corpse.
    when defined(posix):
      var fds: array[2, TPollfd]
      fds[0] = TPollfd(fd: if aDead: -1.cint else: a.cint,
                       events: POLLIN)
      fds[1] = TPollfd(fd: if bDead: -1.cint else: b.cint,
                       events: POLLIN)
      let r = poll(addr fds[0], 2, -1)
      if r < 0:
        if osLastError().cint == EINTR: continue
        break
      template revAt(i: int): untyped = fds[i].revents
    else:
      var fds: array[2, TPollfdW]
      fds[0] = TPollfdW(fd: if aDead: osInvalidSocket else: a,
                        events: POLLIN_W)
      fds[1] = TPollfdW(fd: if bDead: osInvalidSocket else: b,
                        events: POLLIN_W)
      let r = pollW(addr fds[0], 2, -1)
      if r < 0:
        if interruptedW(): continue
        break
      template revAt(i: int): untyped = int(fds[i].revents)
    let evIn = when defined(posix): int(POLLIN or POLLHUP)
               else: int(POLLIN_W or POLLHUP_W)
    let evErr = when defined(posix): int(POLLERR or POLLNVAL)
                else: int(POLLERR_W or POLLNVAL_W)
    for i in 0 .. 1:
      let rev = revAt(i)
      if rev == 0: continue
      let (src, dst, buf) =
        if i == 0: (a, b, addr bufA[0])
        else: (b, a, addr bufB[0])
      let dead = if i == 0: addr aDead else: addr bDead
      if (rev and evErr) != 0:
        if not dead[]:
          shutdownWr(dst)
          dead[] = true
        continue
      if (rev and evIn) != 0:
        when defined(posix):
          let n = posix.recv(src, buf, spliceBuf.cint, 0'i32)
        else:
          let n = wsaRecv(src, buf, spliceBuf.cint, 0)
        if n > 0:
          var s = newString(n.int)
          copyMem(addr s[0], buf, n.int)
          if not sendFd(dst, s):
            if not dead[]:
              shutdownWr(dst)
              dead[] = true
        else:
          if not dead[]:
            shutdownWr(dst)
            dead[] = true

# ----------------------------------------------------------- protocols

proc parseHostPort(target: string): tuple[host: string, port: uint16] =
  ## Split `host:port`, tolerating the IPv6 bracket form.
  if target.startsWith("["):
    let c = target.find(']')
    if c < 0 or c + 2 > target.len: raise newException(ValueError, "bad target")
    result.host = target[1 .. c - 1]
    result.port = uint16(parseUInt(target[c + 2 .. ^1]))
  else:
    let c = target.rfind(':')
    if c < 0: raise newException(ValueError, "bad target")
    result.host = target[0 .. c - 1]
    result.port = uint16(parseUInt(target[c .. ^1][1 .. ^1]))

proc readHttpHead(fd: SocketHandle; first: char): string =
  ## Read the request line plus headers up to the blank line.
  ## `first` is the byte already consumed by the protocol peek.
  result = $first
  let deadline = epochTime() + handshakeTimeout / 1000
  var b: array[1, char]
  while true:
    if result.len > 32 * 1024:
      raise newException(ValueError, "header too large")
    let remain = int((deadline - epochTime()) * 1000)
    if remain <= 0 or recvFd(fd, addr b[0], 1, remain) != 1:
      raise newException(ValueError, "header read timeout")
    result.add b[0]
    if result.endsWith("\c\L\c\L") or result.endsWith("\L\L"): return

proc serveConnect(sh: var ProxyShared; fd: SocketHandle; first: char) =
  ## Handle one HTTP request: CONNECT (a tunnel) or any other method
  ## with an absolute-URI target (plain HTTP, forwarded).
  let head = readHttpHead(fd, first)
  let line = head.splitLines()[0]
  let parts = line.splitWhitespace()
  if parts.len < 2:
    discard sendFd(fd, "HTTP/1.1 400 Bad Request\c\L\c\L")
    return
  var host: string
  var port: uint16
  if parts[0] == "CONNECT":
    try:
      (host, port) = parseHostPort(parts[1])
    except ValueError:
      discard sendFd(fd, "HTTP/1.1 400 Bad Request\c\L\c\L")
      return
    if not sh.allowed(host, port):
      discard sendFd(fd, "HTTP/1.1 403 Forbidden\c\L\c\L")
      return
    let up = dialUp(host, port)
    if up == osInvalidSocket:
      discard sendFd(fd, "HTTP/1.1 502 Bad Gateway\c\L\c\L")
      return
    if not sendFd(fd, "HTTP/1.1 200 Connection Established\c\L\c\L"):
      closeSock(up)
      return
    splice(fd, up)
    closeSock(up)
  else:
    # Plain HTTP through the proxy: the request target is an
    # absolute URI (http://host[:port]/path). The allow decision
    # still runs on the requested name; the request line is rewritten
    # to origin form before forwarding so the upstream sees a normal
    # request.
    let uri = parts[1]
    if not uri.toLowerAscii.startsWith("http://"):
      discard sendFd(fd, "HTTP/1.1 400 Bad Request\c\L" &
        "sandwall: absolute http:// URI required\c\L\c\L")
      return
    let authority = uri[7 .. ^1].split('/', 1)[0]
    try:
      (host, port) = parseHostPort(authority)
    except ValueError:
      host = authority
      port = 80
    let path = if uri.len > 7 + authority.len: uri[7 + authority.len .. ^1]
               else: "/"
    if not sh.allowed(host, port):
      discard sendFd(fd, "HTTP/1.1 403 Forbidden\c\L\c\L")
      return
    let up = dialUp(host, port)
    if up == osInvalidSocket:
      discard sendFd(fd, "HTTP/1.1 502 Bad Gateway\c\L\c\L")
      return
    let crlf = head.find("\c\L\c\L") >= 0
    let nl = if crlf: "\c\L" else: "\L"
    let splitAt = if crlf: head.find("\c\L\c\L") else: head.find("\L\L")
    var fwd = parts[0] & " " & path
    if parts.len > 2: fwd.add " " & parts[2]
    fwd.add nl & head[line.len + nl.len ..< splitAt] & nl & nl
    if not sendFd(up, fwd):
      closeSock(up)
      return
    splice(fd, up)
    closeSock(up)

proc ip4String(a: array[4, char]): string =
  $uint8(a[0]) & "." & $uint8(a[1]) & "." & $uint8(a[2]) & "." & $uint8(a[3])

proc ip6String(a: array[16, char]): string =
  when defined(posix):
    var in6: In6Addr
    copyMem(addr in6, unsafeAddr a[0], 16)
    result = newString(64)
    let r = inet_ntop(AF_INET.cint, addr in6, result.cstring, 64)
    if r == nil: raise newException(ValueError, "bad IPv6 address")
    result.setLen(r.len)
  else:
    var buf = newWideCString("", 64)
    let r = inetNtopW(23, unsafeAddr a[0], buf, 64)  # AF_INET6
    if r == nil: raise newException(ValueError, "bad IPv6 address")
    result = $buf

proc socksReply(fd: SocketHandle; code: char) =
  discard sendFd(fd, "\x05" & code & "\x00\x01\x00\x00\x00\x00\x00\x00")

proc serveSocks5(sh: var ProxyShared; fd: SocketHandle; first: char) =
  ## Handle one SOCKS5 session. No authentication (loopback only).
  ## `first` is the version byte already consumed by the protocol peek.
  var head: array[2, char]
  head[0] = first
  if recvFd(fd, addr head[1], 1, handshakeTimeout) != 1:
    raise newException(ValueError, "socks greeting truncated")
  let nmethods = int(head[1])
  var methods = newString(nmethods)
  if nmethods > 0 and
     recvFd(fd, addr methods[0], nmethods, handshakeTimeout) != nmethods:
    raise newException(ValueError, "socks methods truncated")
  if not sendFd(fd, "\x05\x00"): return   # no auth
  var req: array[4, char]
  if recvFd(fd, addr req[0], 4, handshakeTimeout) != 4:
    raise newException(ValueError, "socks request truncated")
  if req[0] != '\x05':
    raise newException(ValueError, "bad socks version")
  if req[1] != '\x01':
    socksReply(fd, '\x07')   # command not supported
    return
  var host: string
  case req[3]
  of '\x01':
    var a: array[4, char]
    if recvFd(fd, addr a[0], 4, handshakeTimeout) != 4:
      raise newException(ValueError, "socks ipv4 truncated")
    host = ip4String(a)
  of '\x03':
    var ln: array[1, char]
    if recvFd(fd, addr ln[0], 1, handshakeTimeout) != 1:
      raise newException(ValueError, "socks domain truncated")
    let n = int(ln[0])
    var d = newString(n)
    if recvFd(fd, addr d[0], n, handshakeTimeout) != n:
      raise newException(ValueError, "socks domain truncated")
    host = d
  of '\x04':
    var a: array[16, char]
    if recvFd(fd, addr a[0], 16, handshakeTimeout) != 16:
      raise newException(ValueError, "socks ipv6 truncated")
    host = ip6String(a)
  else:
    socksReply(fd, '\x08')   # address type not supported
    return
  var pb: array[2, char]
  if recvFd(fd, addr pb[0], 2, handshakeTimeout) != 2:
    raise newException(ValueError, "socks port truncated")
  let port = (uint16(uint8(pb[0])) shl 8) or uint16(uint8(pb[1]))
  if not sh.allowed(host, port):
    socksReply(fd, '\x02')   # not allowed by ruleset
    return
  let up = dialUp(host, port)
  if up == osInvalidSocket:
    socksReply(fd, '\x05')   # connection refused
    return
  if not sendFd(fd, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"):
    closeSock(up)
    return
  splice(fd, up)
  closeSock(up)

proc serveClient(sh: var ProxyShared; fd: SocketHandle) =
  ## One client connection, already accepted. Peek the first byte to
  ## pick the protocol: 0x05 is SOCKS5, anything else is parsed as an
  ## HTTP request where only CONNECT is accepted.
  try:
    var b: array[1, char]
    if recvFd(fd, addr b[0], 1, handshakeTimeout) != 1: return
    if b[0] == '\x05':
      serveSocks5(sh, fd, b[0])
    else:
      serveConnect(sh, fd, b[0])
  except CatchableError:
    discard
  finally:
    closeSock(fd)

proc clientThread(ca: ClientArg) {.thread.} =
  ## Serve one accepted connection. Thread-per-connection: a kept-alive
  ## tunnel (splice has no idle timeout, deliberately) must not starve
  ## the next CONNECT behind it.
  ca.sh[].serveClient(ca.fd)

proc serveAsync(sh: ptr ProxyShared; fd: SocketHandle) =
  ## Hand an accepted connection to a fresh worker thread. The Thread
  ## object lives on the shared heap, not this frame: the worker
  ## thread's wrapper writes `thrd.core = nil` back through it AFTER
  ## the client has been served, long past this proc's return
  ## (stack-allocated, that write is a use-after-return that crashes
  ## the worker). The handle is then deliberately leaked; it is ~40
  ## bytes per connection on a per-run proxy. Detached, never joined.
  let t = cast[ptr Thread[ClientArg]](allocShared0(sizeof(Thread[ClientArg])))
  try:
    createThread(cast[var Thread[ClientArg]](t), clientThread,
                 ClientArg(sh: sh, fd: fd))
    when defined(posix):
      discard pthread_detach(cast[Pthread](t.sys))
  except ResourceExhaustedError:
    deallocShared(t)
    sh[].serveClient(fd)

proc acceptThread(sh: ptr ProxyShared) {.thread.} =
  while sh.running:
    var listener = osInvalidSocket
    when defined(posix):
      var pfds = newSeq[TPollfd](sh.listeners.len)
      for i, l in sh.listeners:
        pfds[i] = TPollfd(fd: l.cint, events: POLLIN)
      if poll(addr pfds[0], pfds.len.Tnfds, 200) <= 0:
        continue   # timeout or error: re-check sh.running
      for pfd in pfds:
        if (pfd.revents and POLLIN) != 0:
          listener = SocketHandle(pfd.fd)
          break
    else:
      var pfds = newSeq[TPollfdW](sh.listeners.len)
      for i, l in sh.listeners:
        pfds[i] = TPollfdW(fd: l, events: POLLIN_W)
      if pollW(addr pfds[0], pfds.len, 200) <= 0:
        continue
      for pfd in pfds:
        if (pfd.revents and POLLIN_W) != 0:
          listener = pfd.fd
          break
    if listener == osInvalidSocket: continue
    # Ready without O_NONBLOCK: accept must not return EAGAIN because
    # the forked bridge (or the fenced consumer) drained the pending
    # connection first. That is fine - one of the proxy processes got
    # it.
    let fd = when defined(posix): posix.accept(listener, nil, nil)
             else: wsaAccept(listener, nil, nil)
    if fd == osInvalidSocket:
      when defined(posix):
        if osLastError().cint == EINTR: continue
      else:
        if interruptedW(): continue
      if not sh.running: break
      sleep(10)
      continue
    sh[].maybeReload()
    sh.serveAsync(fd)

# ------------------------------------------------------------- public

when defined(posix):
  proc listenUnix(path: string): SocketHandle =
    ## Bind and listen on the AF_UNIX socket at `path`, replacing a stale
    ## file. Filesystem permissions on the socket are the access control:
    ## a unix listener exists only as the fenced side's bridge target.
    result = posix.socket(AF_UNIX, SOCK_STREAM, 0)
    if result == osInvalidSocket: raiseOSError(osLastError())
    var sa: Sockaddr_un
    sa.sun_family = TSa_Family(AF_UNIX)
    if path.len >= sa.sun_path.len:
      raise newException(ValueError, "sandwall proxy: unix socket path too long: " & path)
    copyMem(addr sa.sun_path[0], cstring(path), path.len + 1)
    removeFile(path)
    if bindSocket(result, cast[ptr SockAddr](addr sa), SockLen(sizeof(sa))) != 0:
      raiseOSError(osLastError())
    if nativesockets.listen(result) != 0:
      raiseOSError(osLastError())
    # World-writable: a fenced child may run as another uid (Windows fence
    # story aside, uid mapping makes this moot on Linux) and the socket is
    # the sanctioned egress; the policy, not the file mode, is the ACL.
    discard chmod(path, 0o777)

proc startProxyListeners(policyPath, projectDir: string; port: uint16;
                         unixSockPath: string; verbose: bool): WallProxy =
  ## Shared body of the public startWallProxy variants: bind the TCP
  ## loopback listener (plus a unix listener when unixSockPath is set),
  ## load the policy, spawn the accept loop.
  let sock = newSocket(buffered = false)
  sock.setSockOpt(OptReuseAddr, true)
  sock.bindAddr(Port(port), "127.0.0.1")
  sock.listen()
  let p = cast[ptr ProxyCtx](allocShared0(sizeof(ProxyCtx)))
  p[] = ProxyCtx(sh: ProxyShared(policyPath: policyPath,
                                 projectDir: projectDir,
                                 verbose: verbose,
                                 running: true))
  p.sh.listeners.add(sock.getFd())
  when defined(posix):
    if unixSockPath.len > 0:
      p.sh.listeners.add(listenUnix(unixSockPath))
  initLock(p.sh.lock)
  p.sh.loadList()
  createThread(p.acceptThread, acceptThread, addr p.sh)
  result.sock = sock
  result.acceptCtx = p
  result.port = uint16(sock.getLocalAddr()[1])
  result.policyPath = policyPath
  result.projectDir = projectDir
  result.verbose = verbose

proc startWallProxy*(policyPath: string; projectDir: string;
                     port: uint16 = 0; verbose = false): WallProxy =
  ## Bind 127.0.0.1:port (0 = ephemeral), load the policy, spawn the
  ## accept loop on a background thread. Port 0 lets the caller read
  ## back `proxy.port`; consumers that need a fixed port range (the
  ## Windows fence story) pass explicit ports instead.
  when defined(windows):
    # The AC fence permits loopback egress only to remote ports
    # 60080-60089 (FirstProxyPort..LastProxyPort in wfp.nim, mirrored
    # here to keep the import graph acyclic: wfp must not see this
    # module's winlean-portability layer). An ephemeral port is
    # unreachable through the fence: try each port in the permitted
    # range until one binds.
    const firstProxyPort = 60080'u16
    const lastProxyPort = 60089'u16
    for p in firstProxyPort .. lastProxyPort:
      try:
        return startProxyListeners(policyPath, projectDir, p, "", verbose)
      except CatchableError:
        continue
    raise newException(OSError,
      "sandwall proxy: no free port in the fence range " &
      $firstProxyPort & "-" & $lastProxyPort)
  else:
    startProxyListeners(policyPath, projectDir, port, "", verbose)

proc startWallProxy*(policyPath: string; projectDir: string;
                     unixSockPath: string; port: uint16 = 0;
                     verbose = false): WallProxy =
  ## As startWallProxy, plus a second listener on the AF_UNIX socket at
  ## `unixSockPath`. A filesystem unix socket crosses netns boundaries,
  ## so this is how the unfenced parent offers the proxy to a fenced
  ## child (see wall/netns.nim). Same accept loop, family AF_UNIX; peer
  ## address checks are skipped (filesystem perms are the ACL).
  startProxyListeners(policyPath, projectDir, port, unixSockPath, verbose)

when defined(posix):
  proc proxyChild(dir, policyPath, projectDir: string; sockFd: SocketHandle;
                  deathFd, portFd: cint; verbose: bool) =
    ## The forked proxy's whole lifetime: serve until the death pipe
    ## says the sandboxed command tree is gone, then clean up the run
    ## dir and exit. The dir exists only while this process lives, so a
    ## crashed parent never leaves a listening proxy behind; the dir is
    ## recreated below when the parent vanished before the child started
    ## (the kernel keeps the bound sockets either way, this is for the
    ## unix listener path and cleanup symmetry).
    createDir(dir)
    let ctx = cast[ptr ProxyCtx](allocShared0(sizeof(ProxyCtx)))
    ctx[] = ProxyCtx(sh: ProxyShared(policyPath: policyPath,
                                     projectDir: projectDir,
                                     verbose: verbose,
                                     running: true))
    ctx.sh.listeners.add(sockFd)
    when defined(linux):
      ctx.sh.listeners.add(listenUnix(dir / "proxy.sock"))
    initLock(ctx.sh.lock)
    ctx.sh.loadList()
    var sa: Sockaddr_in
    var slen = SockLen(sizeof(sa))
    if getsockname(sockFd, cast[ptr SockAddr](addr sa), addr slen) != 0:
      raiseOSError(osLastError())
    let port = uint16(nativesockets.ntohs(sa.sin_port))
    # Port back to the parent over a pipe: plain write(), not sendFd
    # (posix.send is for sockets and fails ENOTSOCK on pipes).
    var ps = $port
    discard posix.write(portFd, addr ps[0], ps.len)
    discard posix.close(portFd)
    while true:
      var fds = @[TPollfd(fd: deathFd, events: POLLIN, revents: 0)]
      for l in ctx.sh.listeners:
        fds.add TPollfd(fd: l.cint, events: POLLIN, revents: 0)
      let r = poll(addr fds[0], fds.len.Tnfds, -1)
      if r < 0:
        if osLastError().cint == EINTR: continue
        break
      if fds[0].revents != 0: break   # command tree is gone
      for i in 1 ..< fds.len:
        if (fds[i].revents and POLLIN) == 0: continue
        let fd = posix.accept(SocketHandle(fds[i].fd), nil, nil)
        if fd == osInvalidSocket:
          if osLastError().cint == EINTR: continue
          sleep(10)
          continue
        ctx.sh.maybeReload()
        (addr ctx.sh).serveAsync(fd)
        break
    for l in ctx.sh.listeners:
      discard posix.close(l)
    deinitLock(ctx.sh.lock)
    deallocShared(ctx)
    removeDir(dir)


type
  SpawnedProxy* = object
    ## A per-invocation wall proxy, forked before any restriction is
    ## applied so it keeps full network access. Lives exactly as long
    ## as the sandboxed command tree (death pipe); there is one proxy
    ## per run and never a shared instance.
    port*: uint16          ## loopback TCP port the proxy bound
    runDir*: string        ## holds proxy.sock (linux) and any policy copy
    sockPath*: string      ## AF_UNIX listener, linux only ("" elsewhere)
    pid*: int32   ## Posix Pid; unused on Windows

when defined(posix):
  proc spawnWallProxy*(policyPath, projectDir: string;
                       runDir = ""; verbose = false): SpawnedProxy =
    ## Fork the wall proxy as a child process and return where it
    ## listens. Call BEFORE restrict()/exec: after exec the in-process
    ## proxy threads would be gone, and after restrict the child would
    ## inherit the fence and be useless. `policyPath` is watched for
    ## mtime changes, so editing the rules file between (or during) runs
    ## is picked up on the next connection.
    ##
    ## The run dir (/tmp/sandwall-PID) is removed by the child on exit.
    ## The child exits as soon as the last holder of the death pipe is
    ## gone, which is when the restricting process and every descendant
    ## of the command it exec'd have died.
    let runDir = if runDir.len > 0: runDir
                 else: getTempDir() / ("sandwall-" & $getCurrentProcessId())
    createDir(runDir)
    let sock = newSocket(buffered = false)
    sock.setSockOpt(OptReuseAddr, true)
    sock.bindAddr(Port(0), "127.0.0.1")
    sock.listen()
    var deathPipe, portPipe: array[2, cint]
    if posix.pipe(deathPipe) != 0 or posix.pipe(portPipe) != 0:
      raiseOSError(osLastError())
    let pid = posix.fork()
    if pid == 0:
      discard posix.close(deathPipe[1])
      discard posix.close(portPipe[0])
      try:
        proxyChild(runDir, policyPath, projectDir, sock.getFd(),
                   deathPipe[0], portPipe[1], verbose)
      except CatchableError:
        discard
      exitnow(0)
    if pid < 0:
      raiseOSError(osLastError())
    discard posix.close(deathPipe[0])
    discard posix.close(portPipe[1])
    var buf = newString(8)
    let n = posix.read(portPipe[0], addr buf[0], 8)
    discard posix.close(portPipe[0])
    if n <= 0:
      raise newException(IOError, "sandwall: wall proxy failed to start")
    buf.setLen(n)
    result.port = uint16(parseInt(buf))
    result.runDir = runDir
    when defined(linux):
      result.sockPath = runDir / "proxy.sock"
    result.pid = pid
    # The death pipe write end is intentionally left open and leaked:
    # the exec'd command and its descendants hold it, and its close is
    # what tells the proxy child to exit. Same trick as the netns
    # bridge (wall/netns.nim).


proc stopWallProxy*(p: var WallProxy) =
  ## Close the listener, join the accept thread. Client threads are
  ## detached; closing their sockets on process exit is the OS's job.
  if p.sock == nil: return
  let ctx = cast[ptr ProxyCtx](p.acceptCtx)
  ctx.sh.running = false
  joinThread(ctx.acceptThread)
  when defined(posix):
    p.sock.close()
  else:
    closeSock(p.sock.getFd())
  p.sock = nil
  deinitLock(ctx.sh.lock)
  deallocShared(ctx)
  p.acceptCtx = nil


proc setProxyEnv*(port: uint16) =
  ## Point the process's proxy env at the wall proxy on 127.0.0.1:port.
  ## http(s)_proxy for CONNECT, ALL_PROXY=socks5h so DNS happens at the
  ## proxy (a fenced child has no resolver). NO_PROXY is cleared on
  ## purpose: loopback targets must go through the proxy too, since the
  ## fence permits only loopback and the allowlist lives in the proxy.
  ## WALL_PROXY_PORT is for tools that speak to the proxy directly
  ## (the connect adapter reads it).
  let hp = "http://127.0.0.1:" & $port
  let sp = "socks5h://127.0.0.1:" & $port
  putEnv("http_proxy", hp)
  putEnv("https_proxy", hp)
  putEnv("HTTP_PROXY", hp)
  putEnv("HTTPS_PROXY", hp)
  putEnv("ALL_PROXY", sp)
  putEnv("all_proxy", sp)
  putEnv("NO_PROXY", "")
  putEnv("no_proxy", "")
  putEnv("WALL_PROXY_PORT", $port)
