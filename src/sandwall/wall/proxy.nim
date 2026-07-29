## proxy: the wall's single network egress point.
##
## A threaded HTTP CONNECT + SOCKS5 proxy on 127.0.0.1 that enforces the
## policy's HostList per target and hot-reloads the policy file on mtime
## change. Fenced processes reach the outside world only through here,
## so the fence (chunk 3) can be simple: block everything, permit
## loopback.
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

import std/[locks, nativesockets, net, os, posix, strutils, syncio, times]

import ../rules
import ./hosts

type
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
      var pfd = TPollfd(fd: fd.cint, events: POLLIN)
      let r = poll(addr pfd, 1, remain.cint)
      if r <= 0: return -1
      if (pfd.revents and (POLLERR or POLLNVAL)) != 0: return -1
      if (pfd.revents and POLLIN) == 0: return -1  # HUP without data
    let n = posix.recv(fd, cast[pointer](cast[int](buf) + off),
                       (len - off).cint, 0'i32).int
    if n <= 0: return -1
    off.inc n
  len

proc sendFd(fd: SocketHandle; data: string): bool =
  ## Write all of `data`, ignoring SIGPIPE.
  var off = 0
  while off < data.len:
    let flags = when defined(linux): MSG_NOSIGNAL else: 0'i32
    let n = posix.send(fd, addr data[off], (data.len - off).cint, flags)
    if n <= 0:
      if n < 0 and osLastError().cint == EINTR: continue
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
    let fd = posix.socket(it.ai_family, it.ai_socktype, it.ai_protocol)
    if fd != osInvalidSocket:
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
  while not (aDead and bDead):
    var fds: array[2, TPollfd]
    # A dead direction's fd is removed from the poll set (fd < 0
    # makes poll ignore the entry): events=0 does NOT suffice,
    # error conditions (POLLERR|POLLHUP) are reported
    # unconditionally and the loop would busy-spin on the corpse.
    fds[0] = TPollfd(fd: if aDead: -1.cint else: a.cint,
                     events: POLLIN)
    fds[1] = TPollfd(fd: if bDead: -1.cint else: b.cint,
                     events: POLLIN)
    let r = poll(addr fds[0], 2, -1)
    if r < 0:
      if osLastError().cint == EINTR: continue
      break
    for i in 0 .. 1:
      let rev = fds[i].revents
      if rev == 0: continue
      let (src, dst, buf) =
        if i == 0: (a, b, addr bufA[0])
        else: (b, a, addr bufB[0])
      let dead = if i == 0: addr aDead else: addr bDead
      if (rev and (POLLERR or POLLNVAL)) != 0:
        if not dead[]:
          discard posix.shutdown(dst, SHUT_WR)
          dead[] = true
        continue
      if (rev and (POLLIN or POLLHUP)) != 0:
        let n = posix.recv(src, buf, spliceBuf.cint, 0'i32)
        if n > 0:
          var s = newString(n.int)
          copyMem(addr s[0], buf, n.int)
          if not sendFd(dst, s):
            if not dead[]:
              discard posix.shutdown(dst, SHUT_WR)
              dead[] = true
        else:
          if not dead[]:
            discard posix.shutdown(dst, SHUT_WR)
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
  ## Handle one HTTP CONNECT. Only CONNECT is valid; anything else
  ## gets 405 (the proxy is not a general HTTP proxy).
  let head = readHttpHead(fd, first)
  let line = head.splitLines()[0]
  let parts = line.splitWhitespace()
  if parts.len < 2 or parts[0] != "CONNECT":
    discard sendFd(fd, "HTTP/1.1 405 Method Not Allowed\c\L\c\L")
    return
  var host: string
  var port: uint16
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
    discard posix.close(up)
    return
  splice(fd, up)
  discard posix.close(up)

proc ip4String(a: array[4, char]): string =
  $uint8(a[0]) & "." & $uint8(a[1]) & "." & $uint8(a[2]) & "." & $uint8(a[3])

proc ip6String(a: array[16, char]): string =
  var in6: In6Addr
  copyMem(addr in6, unsafeAddr a[0], 16)
  result = newString(64)
  let r = inet_ntop(AF_INET.cint, addr in6, result.cstring, 64)
  if r == nil: raise newException(ValueError, "bad IPv6 address")
  result.setLen(r.len)

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
    discard posix.close(up)
    return
  splice(fd, up)
  discard posix.close(up)

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
    discard posix.close(fd)

proc acceptThread(sh: ptr ProxyShared) {.thread.} =
  while sh.running:
    var pfds = newSeq[TPollfd](sh.listeners.len)
    for i, l in sh.listeners:
      pfds[i] = TPollfd(fd: l.cint, events: POLLIN)
    if poll(addr pfds[0], pfds.len.Tnfds, 200) <= 0:
      continue   # timeout or error: re-check sh.running
    var listener = osInvalidSocket
    for pfd in pfds:
      if (pfd.revents and POLLIN) != 0:
        listener = SocketHandle(pfd.fd)
        break
    if listener == osInvalidSocket: continue
    # Ready without O_NONBLOCK: accept must not return EAGAIN because
    # the forked bridge (or the fenced consumer) drained the pending
    # connection first. That is fine - one of the proxy processes got
    # it.
    let fd = posix.accept(listener, nil, nil)
    if fd == osInvalidSocket:
      if osLastError().cint == EINTR: continue
      if not sh.running: break
      sleep(10)
      continue
    sh[].maybeReload()
    sh[].serveClient(fd)
    # Sequential: one client at a time. This keeps the accept loop
    # single-threaded, which keeps it correct when a consumer forks
    # after startWallProxy: the proxy then serves the loopback AND the
    # unix listener from both processes. (Thread-per-connection here
    # left the freshly accepted fd served only by the parent's thread,
    # which fenced children bridged to the unix listener never reach.)

# ------------------------------------------------------------- public

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

proc stopWallProxy*(p: var WallProxy) =
  ## Close the listener, join the accept thread. Client threads are
  ## detached; closing their sockets on process exit is the OS's job.
  if p.sock == nil: return
  let ctx = cast[ptr ProxyCtx](p.acceptCtx)
  ctx.sh.running = false
  joinThread(ctx.acceptThread)
  p.sock.close()
  p.sock = nil
  deinitLock(ctx.sh.lock)
  deallocShared(ctx)
  p.acceptCtx = nil
