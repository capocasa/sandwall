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
## The allow decision has two halves. A name is checked against the
## HostList as a string (see hosts.nim) and then resolved through the
## permit set (permit.nim), which answers with the addresses that still
## stand for the rule. The proxy dials addresses, never names: a request
## for an IP is decided by the same set, so a rule that was withdrawn
## stops being dialable too. Denies are logged to stderr; allows are
## silent unless `verbose` is set.
##
## Linux raw mode (wall/netns.nim) needs no env vars in the child and
## reaches this proxy twice: TCP connections that nft redirected arrive
## through the unix listener with an `SWRAW <ip> <port>` line ahead of
## the bytes, naming the original destination, which is a fake-IP the
## fence DNS (wall/dns.nim) handed out; and DNS queries arrive as
## datagrams on a second unix socket, answered by policy with a stable
## fake-IP per allowed name. The pool of bindings lives here because
## this process outlives the netns.

import std/[locks, nativesockets, net, options, os, strutils, syncio, times]
when defined(posix):
  import std/posix
else:
  import winlean except Socket

import ../rules
import ./dns
import ./hosts
import ./permit
from ./wfp import FirstProxyPort, LastProxyPort
import ./sockshim

type
  ClientArg = ref object
    ## Handoff to a per-connection worker thread. A ref (GC heap), not
    ## allocShared: nim refs are thread-safe to pass between threads as
    ## long as only one thread owns it at a time, which is exactly the
    ## accept -> worker handoff here. (allocShared'd memory holding a
    ## ptr back into ProxyShared is fine too, but ref is simpler.)
    sh: ptr ProxyShared
    fd: SocketHandle
    dns: bool              ## a DNS datagram (`query`, from `peer`), not a connection
    query: string
    when defined(posix):
      peer: Sockaddr_un
      peerLen: SockLen

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
    ps: PermitSet              ## the addresses behind the names in `list`
    ownPermit: bool            ## this proxy created `ps` and closes it
    dnsFd: SocketHandle        ## fence DNS listener (unix datagram, posix; else invalid)
    fakeLock: Lock             ## `fakes`, under its own lock: DNS workers write, raw readers read
    fakes: FakePool            ## fake-IP -> name bindings, for this proxy's lifetime

  ProxyCtx = ref object
    ## Must stay a GC ref rooted from WallProxy.acceptCtx. Storing only
    ## an untraced pointer (allocShared + cast) lets ORC collect the
    ## strings/seqs inside `sh` while the accept thread still uses them:
    ## that is the interactive SIGSEGV after a fenced curl on Windows.
    sh: ProxyShared
    acceptThread: Thread[ptr ProxyShared]

  WallProxy* = object
    sock: Socket              ## listener on 127.0.0.1
    acceptCtx: ProxyCtx       ## GC-rooted accept/client state
    port*: uint16             ## actual bound port
    policyPath*: string       ## file to reload on mtime change
    projectDir*: string       ## for relative policy targets
    verbose*: bool

const
  handshakeTimeout = 30_000   ## ms to read the initial request
  upstreamTimeout = 15_000    ## ms to connect+read the upstream
  spliceBuf = 64 * 1024
  rawPrefix = "SWRAW "      ## the netns bridge's original-destination line
  rawLineMax = 128

# ------------------------------------------------------------- policy

proc loadList(sh: var ProxyShared) =
  ## Load (or reload) the allowlist from the policy file, and start the
  ## address set over with it: a rule that went away must stop being
  ## resolved and dialed. The policy's IP-literal allow rules go into the
  ## set as they are, because nothing else will ever look those up.
  let hosts = loadPolicy(sh.policyPath, sh.projectDir).resolve().hosts
  let l = hosts.toHostList()
  withLock sh.lock:
    sh.list = l
  sh.listMtime =
    if fileExists(sh.policyPath):
      getLastModificationTime(sh.policyPath).toUnixFloat()
    else: 0.0
  sh.ps.clear()
  for m in l.matchers:
    if m.allow and not m.isAll and not m.isWildcard and isIpAddress(m.host):
      discard sh.ps.getOrResolve(m.host, l.winningPorts(m.host))

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

type
  Verdict {.pure.} = enum
    vAllowed    ## dial `ips`
    vDenied     ## the policy does not allow this target
    vNoAddress  ## the name is allowed, but has no address to serve

proc dialable(sh: var ProxyShared; ent: PermitEntry): seq[IpAddress] =
  ## The addresses to dial for an entry: `current`, then `previous`
  ## while its grace runs, so a rotation does not cut off a peer still
  ## holding the old address.
  result = ent.current
  if sh.ps.clock() < ent.prevUntil: result.add ent.previous

proc fakeName(sh: var ProxyShared; ip: IpAddress): Option[string] =
  ## The name behind a fake address, as a private copy: DNS workers
  ## write the pool, this thread keeps only what it copied out.
  withLock sh.fakeLock: result = sh.fakes.nameFor(ip)

proc fakeFor(sh: var ProxyShared; name: string): Option[IpAddress] =
  withLock sh.fakeLock: result = sh.fakes.fakeFor(name)

proc dnsDecide(sh: var ProxyShared; name: string):
    tuple[decision: DnsDecision, ip: IpAddress] =
  ## Policy first, by name: a port is not known at resolution time
  ## (the connect checks it), so a rule for any port makes the name
  ## resolvable. Then the permit set: an allowed name nothing resolves
  ## behind is SERVFAIL, so a typo reports as a resolution failure
  ## rather than as a dead tunnel. The set is warmed on the way, and
  ## the connect that follows finds the entry fresh.
  withLock sh.lock:
    if not sh.list.allowsAnyPort(name):
      result.decision = ddNxDomain
  if result.decision == ddNxDomain:
    stderr.writeLine("sandwall proxy: dns DENY " & name)
    return
  var won: seq[uint16]
  withLock sh.lock:
    won = sh.list.winningPorts(name)
  if sh.ps.getOrResolve(name, won).isNone:
    result.decision = ddServFail
    if sh.verbose:
      stderr.writeLine("sandwall proxy: dns " & name & ": no address")
    return
  let ip = sh.fakeFor(name)
  if ip.isNone:
    result.decision = ddServFail
    stderr.writeLine("sandwall proxy: dns " & name &
                     ": fake-IP pool exhausted")
    return
  result.decision = ddFake
  result.ip = ip.get
  if sh.verbose:
    stderr.writeLine("sandwall proxy: dns " & name & " -> " & $ip.get)

proc dnsReply(sh: var ProxyShared; query: string): seq[uint8] =
  ## The fence DNS's answer to one query datagram (wall/dns.nim builds
  ## it; this decides).
  let p = addr sh
  proc decide(name: string): tuple[decision: DnsDecision, ip: IpAddress]
      {.gcsafe, raises: [].} =
    try:
      p[].dnsDecide(name)
    except CatchableError:
      (ddServFail, IpAddress())   # nothing stands behind it right now
  var q = newSeq[uint8](query.len)
  for i, c in query: q[i] = uint8(c)
  dns.reply(q, decide)

when defined(posix):
  proc dnsServe(sh: var ProxyShared; query: string; peer: Sockaddr_un;
                peerLen: SockLen) =
    ## Answer one datagram from `peer`, to `peer`: the relay's per-query
    ## socket, which is gone if the client stopped waiting.
    let resp = sh.dnsReply(query)
    if resp.len > 0:
      discard posix.sendto(sh.dnsFd, addr resp[0], resp.len, 0,
                           cast[ptr SockAddr](unsafeAddr peer), peerLen)

proc admit(sh: var ProxyShared; host: string; port: uint16):
    tuple[verdict: Verdict, ips: seq[IpAddress]] =
  ## The one decision behind CONNECT, plain HTTP and SOCKS5. A name is
  ## decided by the HostList and then resolved through the permit set,
  ## which answers with the addresses that still stand for the rule:
  ## `current`, then `previous` while its grace runs, so a rotation does
  ## not cut off a peer holding the old address. An IP literal is decided
  ## by the set alone (an entry put there by an IP rule, or one that an
  ## allowed name resolved to); with no entry, the policy's own decision
  ## about the literal stands, which is what an open default and `+*`
  ## mean. `ips` is empty unless the verdict is `vAllowed`.
  var ip: IpAddress
  let literal = try:
      ip = parseIpAddress(host)
      true
    except ValueError:
      false
  if literal:
    let e = sh.ps.matchIp(ip, port)
    if e.isSome:
      let ent = e.get
      if sh.verbose:
        stderr.writeLine("sandwall proxy: allow " & $ip & ":" & $port &
                         " (" & ent.host & ")")
      return (vAllowed, @[ip])
    if sh.allowed($ip, port): return (vAllowed, @[ip])
    return (vDenied, @[])
  if not sh.allowed(host, port): return (vDenied, @[])
  var won: seq[uint16]
  withLock sh.lock:
    won = sh.list.winningPorts(host)
  let e = sh.ps.getOrResolve(host, won)
  if e.isNone:
    stderr.writeLine("sandwall proxy: no address for " & host & ":" & $port)
    return (vNoAddress, @[])
  result.verdict = vAllowed
  result.ips = sh.dialable(e.get)

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
  if data.len == 0: return true
  sendAll(fd, addr data[0], data.len)

proc dialUp(ips: seq[IpAddress]; port: uint16;
              via: ptr IpAddress = nil): SocketHandle =
  ## Connect to the first of `ips` that accepts, within one overall
  ## timeout shared by every address. The addresses come from the permit
  ## set: a name is resolved once there and never again here, so the dial
  ## cannot reach an address the decision did not just stand for.
  ## `via`, when given, gets the address that accepted. Returns
  ## osInvalidSocket when none accepted.
  if ips.len == 0: return osInvalidSocket
  let deadline = epochTime() + upstreamTimeout / 1000
  # Each address gets its own slice of the budget, not the whole of it:
  # on macOS a connect to a loopback neighbour nothing listens on never
  # completes (Linux refuses it at once), and one black-holed address
  # under a shared deadline would starve the rotated-set grace address
  # behind it.
  let sliceMs = max(min(upstreamTimeout, 2000) div max(ips.len, 1), 500)
  for ip in ips:
    var sa: Sockaddr_storage
    var slen: SockLen
    toSockAddr(ip, Port(port), sa, slen)
    let domain = case ip.family
                 of IpAddressFamily.IPv4: Domain.AF_INET
                 of IpAddressFamily.IPv6: Domain.AF_INET6
    when defined(posix):
      let fd = posix.socket(toInt(domain), toInt(SockType.SOCK_STREAM), 0)
    else:
      let fd = wsaSocket(toInt(domain), toInt(SockType.SOCK_STREAM), 0)
    if fd != osInvalidSocket:
      when defined(posix):
        let nb = fcntl(fd, F_GETFL, 0)
        if nb >= 0:
          discard fcntl(fd, F_SETFL, nb or O_NONBLOCK)
          if posix.connect(fd, cast[ptr SockAddr](addr sa), slen) < 0:
            let err = osLastError().cint
            if err == EINPROGRESS:
              let remain = min(int((deadline - epochTime()) * 1000),
                               sliceMs)
              if remain > 0:
                var pfd = TPollfd(fd: fd.cint, events: POLLOUT)
                if poll(addr pfd, 1, remain.cint) > 0 and
                   (pfd.revents and POLLOUT) != 0:
                  var soerr: cint
                  var optLen = SockLen(sizeof(soerr))
                  if getsockopt(fd, SOL_SOCKET, SO_ERROR, addr soerr,
                                addr optLen) == 0 and soerr == 0:
                    discard fcntl(fd, F_SETFL, nb)  # back to blocking
                    if via != nil: via[] = ip
                    return fd
            elif err == EINTR:
              discard fcntl(fd, F_SETFL, nb)
              return fd
        discard posix.close(fd)
      else:
        var nbMode: culong = 1
        if wsaIoctl(fd, FIONBIO_W, addr nbMode) == 0:
          if wsaConnect(fd, cast[ptr SockAddr](addr sa), slen.cint) < 0:
            let err = osLastError().cint
            if err == WSAEWOULDBLOCK:
              let remain = min(int((deadline - epochTime()) * 1000),
                               sliceMs)
              if remain > 0:
                var pfd = TPollfdW(fd: fd, events: POLLOUT_W)
                if pollW(addr pfd, 1, remain.cint) > 0 and
                   (pfd.revents and POLLOUT_W) != 0:
                  var soerr: cint
                  var optLen = SockLen(sizeof(soerr))
                  if getsockopt(fd, SOL_SOCKET, SO_ERROR, addr soerr,
                                addr optLen) == 0 and soerr == 0:
                    nbMode = 0
                    discard wsaIoctl(fd, FIONBIO_W, addr nbMode)
                    if via != nil: via[] = ip
                    return fd
            elif err == WSAEINTR:
              nbMode = 0
              discard wsaIoctl(fd, FIONBIO_W, addr nbMode)
              return fd
        sockshim.closeSock(fd)
  osInvalidSocket

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

proc readHttpHead(fd: SocketHandle; pre: string): string =
  ## Read the request line plus headers up to the blank line. `pre` is
  ## what the protocol peek already consumed.
  result = pre
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

proc serveConnect(sh: var ProxyShared; fd: SocketHandle; pre: string) =
  ## Handle one HTTP request: CONNECT (a tunnel) or any other method
  ## with an absolute-URI target (plain HTTP, forwarded).
  let head = readHttpHead(fd, pre)
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
    let d = sh.admit(host, port)
    if d.verdict == vDenied:
      discard sendFd(fd, "HTTP/1.1 403 Forbidden\c\L\c\L")
      return
    let up = dialUp(d.ips, port)
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
    let d = sh.admit(host, port)
    if d.verdict == vDenied:
      discard sendFd(fd, "HTTP/1.1 403 Forbidden\c\L\c\L")
      return
    let up = dialUp(d.ips, port)
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
    var a: array[4, uint8]
    if recvFd(fd, addr a[0], 4, handshakeTimeout) != 4:
      raise newException(ValueError, "socks ipv4 truncated")
    host = $IpAddress(family: IpAddressFamily.IPv4, address_v4: a)
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
    var a: array[16, uint8]
    if recvFd(fd, addr a[0], 16, handshakeTimeout) != 16:
      raise newException(ValueError, "socks ipv6 truncated")
    host = $IpAddress(family: IpAddressFamily.IPv6, address_v6: a)
  else:
    socksReply(fd, '\x08')   # address type not supported
    return
  var pb: array[2, char]
  if recvFd(fd, addr pb[0], 2, handshakeTimeout) != 2:
    raise newException(ValueError, "socks port truncated")
  let port = (uint16(uint8(pb[0])) shl 8) or uint16(uint8(pb[1]))
  let d = sh.admit(host, port)
  if d.verdict == vDenied:
    socksReply(fd, '\x02')   # not allowed by ruleset
    return
  if d.verdict == vNoAddress:
    socksReply(fd, '\x04')   # host unreachable: no address to serve
    return
  let up = dialUp(d.ips, port)
  if up == osInvalidSocket:
    socksReply(fd, '\x05')   # connection refused
    return
  if not sendFd(fd, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"):
    closeSock(up)
    return
  splice(fd, up)
  closeSock(up)

proc readRawLine(fd: SocketHandle; pre: string): string =
  ## The rest of the bridge's `SWRAW <ip> <port>` line after `pre`
  ## (the prefix already matched), up to the newline, bounded. "" when
  ## it never came.
  result = pre
  var b: array[1, char]
  while result.len < rawLineMax:
    if recvFd(fd, addr b[0], 1, handshakeTimeout) != 1: return ""
    if b[0] == '\L': return
    result.add b[0]
  return ""

proc serveRaw(sh: var ProxyShared; fd: SocketHandle; target: string) =
  ## One connection the netns bridge redirected here, `target` being
  ## `<ip> <port>`, where it was going. The ip is a fake-IP the fence
  ## DNS handed out: its name goes through the same decision as CONNECT
  ## (HostList, then the permit set), so a rule withdrawn since the
  ## answer was given is still enforced here. A bare ip is admitted
  ## only by an address some allowed name resolved to; the policy's
  ## default does not vouch for it, fail closed. Nothing is told to
  ## the client: the dial happening, or the connection closing, is the
  ## whole protocol.
  let parts = target.splitWhitespace()
  var ip: IpAddress
  var port: uint16
  var wellFormed = false
  if parts.len == 2:
    try:
      ip = parseIpAddress(parts[0])
      let p = parseUInt(parts[1])
      if p <= 65535:
        port = uint16(p)
        wellFormed = true
    except ValueError:
      discard
  if not wellFormed:
    stderr.writeLine("sandwall proxy: DENY malformed raw target " &
      target)
    return
  let name = sh.fakeName(ip)
  var ips: seq[IpAddress]
  if name.isSome:
    let d = sh.admit(name.get, port)
    if d.verdict != vAllowed: return   # admit logged the reason
    ips = d.ips
  else:
    let e = sh.ps.matchIp(ip, port)
    if e.isNone:
      stderr.writeLine("sandwall proxy: DENY " & $ip & ":" & $port &
                       " (raw, no allowed name stands for it)")
      return
    ips = sh.dialable(e.get)
  var via: IpAddress
  let up = dialUp(ips, port, addr via)
  if up == osInvalidSocket:
    stderr.writeLine("sandwall proxy: raw " & $ip & ":" & $port &
                     " refused or unreachable")
    return
  if sh.verbose:
    stderr.writeLine("sandwall proxy: raw " &
      (if name.isSome: name.get else: $ip) & " fake=" & $ip &
      " real=" & $via & ":" & $port)
  splice(fd, up)
  closeSock(up)

proc serveClient(sh: var ProxyShared; fd: SocketHandle) =
  ## One client connection, already accepted. Peek the first byte to
  ## pick the protocol: 0x05 is SOCKS5, `SWRAW ` is the netns bridge
  ## naming a redirected connection's original destination, anything
  ## else is parsed as an HTTP request where only CONNECT is accepted.
  try:
    var b: array[1, char]
    if recvFd(fd, addr b[0], 1, handshakeTimeout) != 1: return
    if b[0] == '\x05':
      serveSocks5(sh, fd, b[0])
      return
    var pre = $b[0]
    if b[0] == rawPrefix[0]:
      # as much of the prefix as matches, so a short non-match falls
      # back to the HTTP parser with every byte it would have read
      while pre.len < rawPrefix.len and rawPrefix.startsWith(pre):
        if recvFd(fd, addr b[0], 1, handshakeTimeout) != 1: return
        pre.add b[0]
      if pre == rawPrefix:
        serveRaw(sh, fd, readRawLine(fd, ""))
        return
    serveConnect(sh, fd, pre)
  except CatchableError:
    discard
  finally:
    closeSock(fd)

proc clientThread(ca: ClientArg) {.thread.} =
  ## Serve one accepted connection, or answer one DNS datagram.
  ## Thread-per-request: a kept-alive tunnel (splice has no idle
  ## timeout, deliberately) must not starve the next CONNECT behind it,
  ## and a first resolution must not stall the accept loop.
  when defined(posix):
    if ca.dns: ca.sh[].dnsServe(ca.query, ca.peer, ca.peerLen)
    else: ca.sh[].serveClient(ca.fd)
  else:
    ca.sh[].serveClient(ca.fd)

proc spawnWorker(sh: ptr ProxyShared; arg: ClientArg): bool =
  ## Hand one request to a fresh worker thread. The Thread object
  ## lives on the shared heap, not this frame: the worker thread's
  ## wrapper writes `thrd.core = nil` back through it AFTER the client
  ## has been served, long past this proc's return (stack-allocated,
  ## that write is a use-after-return that crashes the worker). The
  ## handle is then deliberately leaked; it is ~40 bytes per connection
  ## on a per-run proxy. Detached, never joined. False when no thread
  ## could be made, so the caller serves the request inline.
  let t = cast[ptr Thread[ClientArg]](allocShared0(sizeof(Thread[ClientArg])))
  try:
    createThread(cast[var Thread[ClientArg]](t), clientThread, arg)
    when defined(posix):
      discard pthread_detach(cast[Pthread](t.sys))
    true
  except ResourceExhaustedError:
    deallocShared(t)
    false

proc serveAsync(sh: ptr ProxyShared; fd: SocketHandle) =
  ## Hand an accepted connection to a fresh worker thread.
  if not spawnWorker(sh, ClientArg(sh: sh, fd: fd)):
    sh[].serveClient(fd)

when defined(posix):
  proc serveDnsAsync(sh: ptr ProxyShared; query: string; peer: Sockaddr_un;
                     peerLen: SockLen) =
    ## Hand one DNS datagram to a fresh worker thread: the first
    ## resolution of a name blocks as long as the resolver does, and
    ## that must not hold up the accept loop.
    if not spawnWorker(sh, ClientArg(sh: sh, dns: true, query: query,
                                     peer: peer, peerLen: peerLen)):
      sh[].dnsServe(query, peer, peerLen)

  proc recvDns(sh: var ProxyShared) =
    ## Take one datagram off the DNS listener and hand it to a worker.
    var buf: array[DnsMaxPacket, char]
    var peer: Sockaddr_un
    var plen = SockLen(sizeof(peer))
    let n = posix.recvfrom(sh.dnsFd, addr buf[0], buf.len, 0,
                           cast[ptr SockAddr](addr peer), addr plen)
    if n <= 0: return
    var query = newString(n)
    copyMem(addr query[0], addr buf[0], n)
    (addr sh).serveDnsAsync(query, peer, plen)

proc acceptThread(sh: ptr ProxyShared) {.thread.} =
  while sh.running:
    var listener = osInvalidSocket
    when defined(posix):
      let hasDns = sh.dnsFd != osInvalidSocket
      var pfds = newSeq[TPollfd](sh.listeners.len + 1)
      for i, l in sh.listeners:
        pfds[i] = TPollfd(fd: l.cint, events: POLLIN)
      pfds[^1] = TPollfd(fd: if hasDns: sh.dnsFd.cint else: -1, events: POLLIN)
      if poll(addr pfds[0], pfds.len.Tnfds, 200) <= 0:
        continue   # timeout or error: re-check sh.running
      if hasDns and (pfds[^1].revents and POLLIN) != 0:
        sh[].maybeReload()
        sh[].recvDns()
      for pfd in pfds[0 ..< sh.listeners.len]:
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

  proc listenUnixDgram(path: string): SocketHandle =
    ## Bind the AF_UNIX datagram socket at `path`: the fence DNS's
    ## listener, where the netns bridge's relay sends the child's
    ## queries. Datagrams, not a stream: a query is self-contained and
    ## needs no accept. Same file mode and ACL reasoning as listenUnix.
    result = posix.socket(AF_UNIX, SOCK_DGRAM, 0)
    if result == osInvalidSocket: raiseOSError(osLastError())
    var sa: Sockaddr_un
    sa.sun_family = TSa_Family(AF_UNIX)
    if path.len >= sa.sun_path.len:
      discard posix.close(result)
      raise newException(ValueError, "sandwall proxy: unix socket path too long: " & path)
    copyMem(addr sa.sun_path[0], cstring(path), path.len + 1)
    removeFile(path)
    if bindSocket(result, cast[ptr SockAddr](addr sa), SockLen(sizeof(sa))) != 0:
      let e = osLastError()
      discard posix.close(result)
      raiseOSError(e)
    discard chmod(path, 0o777)

proc startProxyListeners(policyPath, projectDir: string; port: uint16;
                         unixSockPath: string; verbose: bool;
                         permit: PermitSet; dnsSockPath = ""): WallProxy =
  ## Shared body of the public startWallProxy variants: bind the TCP
  ## loopback listener (plus a unix listener when unixSockPath is set,
  ## and a unix datagram listener for the fence DNS when dnsSockPath is
  ## set), load the policy, spawn the accept loop. A nil `permit` means
  ## the proxy makes its own set and closes it in stopWallProxy.
  let sock = newSocket(buffered = false)
  sock.setSockOpt(OptReuseAddr, true)
  sock.bindAddr(Port(port), "127.0.0.1")
  sock.listen()
  let p = ProxyCtx(sh: ProxyShared(policyPath: policyPath,
                                   projectDir: projectDir,
                                   verbose: verbose,
                                   running: true,
                                   ps: if permit.isNil: newPermitSet()
                                       else: permit,
                                   ownPermit: permit.isNil,
                                   dnsFd: osInvalidSocket,
                                   fakes: initFakePool()))
  p.sh.listeners.add(sock.getFd())
  when defined(posix):
    if unixSockPath.len > 0:
      p.sh.listeners.add(listenUnix(unixSockPath))
    if dnsSockPath.len > 0:
      p.sh.dnsFd = listenUnixDgram(dnsSockPath)
  initLock(p.sh.lock)
  initLock(p.sh.fakeLock)
  p.sh.loadList()
  createThread(p.acceptThread, acceptThread, addr p.sh)
  result.sock = sock
  result.acceptCtx = p
  result.port = uint16(sock.getLocalAddr()[1])
  result.policyPath = policyPath
  result.projectDir = projectDir
  result.verbose = verbose

proc startWallProxy*(policyPath: string; projectDir: string;
                     port: uint16 = 0; verbose = false;
                     permit: PermitSet = nil): WallProxy =
  ## Bind 127.0.0.1:port (0 = ephemeral), load the policy, spawn the
  ## accept loop on a background thread. Port 0 lets the caller read
  ## back `proxy.port`; consumers that need a fixed port range (the
  ## Windows fence story) pass explicit ports instead. A passed
  ## `permit` is used but not owned: the caller keeps it, seeds it,
  ## closes it. The names the policy allows are resolved through it.
  when defined(windows):
    # The fence permits loopback egress only to remote ports
    # FirstProxyPort..LastProxyPort (wfp.nim, the single source: the
    # WFP permit filters and this bind loop must agree or the fenced
    # child cannot reach the proxy). An ephemeral port is unreachable
    # through the fence: try each port in the range until one binds.
    for p in FirstProxyPort .. LastProxyPort:
      try:
        return startProxyListeners(policyPath, projectDir, p, "", verbose,
                                  permit)
      except CatchableError:
        continue
    raise newException(OSError,
      "sandwall proxy: no free port in the fence range " &
      $FirstProxyPort & "-" & $LastProxyPort)
  else:
    startProxyListeners(policyPath, projectDir, port, "", verbose, permit)

proc startWallProxy*(policyPath: string; projectDir: string;
                     unixSockPath: string; port: uint16 = 0;
                     verbose = false; permit: PermitSet = nil;
                     dnsSockPath: string = ""): WallProxy =
  ## As startWallProxy, plus a second listener on the AF_UNIX socket at
  ## `unixSockPath`. A filesystem unix socket crosses netns boundaries,
  ## so this is how the unfenced parent offers the proxy to a fenced
  ## child (see wall/netns.nim). Same accept loop, family AF_UNIX; peer
  ## address checks are skipped (filesystem perms are the ACL). Same
  ## `permit` contract as the other overload.
  ##
  ## `dnsSockPath` (posix) adds the fence DNS: an AF_UNIX datagram
  ## listener that answers the netns bridge's relay by policy with
  ## stable fake-IPs, the Linux raw mode's resolver (wall/dns.nim).
  startProxyListeners(policyPath, projectDir, port, unixSockPath, verbose,
                      permit, dnsSockPath)

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
    let ctx = ProxyCtx(sh: ProxyShared(policyPath: policyPath,
                                       projectDir: projectDir,
                                       verbose: verbose,
                                       running: true,
                                       ps: newPermitSet(),
                                       ownPermit: true,
                                       dnsFd: osInvalidSocket,
                                       fakes: initFakePool()))
    ctx.sh.listeners.add(sockFd)
    when defined(linux):
      ctx.sh.listeners.add(listenUnix(dir / "proxy.sock"))
      # the raw path's resolver end (wall/netns.nim relays UDP 53 to it)
      ctx.sh.dnsFd = listenUnixDgram(dir / "dns.sock")
    initLock(ctx.sh.lock)
    initLock(ctx.sh.fakeLock)
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
    let hasDns = ctx.sh.dnsFd != osInvalidSocket
    while true:
      var fds = @[TPollfd(fd: deathFd, events: POLLIN, revents: 0)]
      for l in ctx.sh.listeners:
        fds.add TPollfd(fd: l.cint, events: POLLIN, revents: 0)
      fds.add TPollfd(fd: if hasDns: ctx.sh.dnsFd.cint else: -1, events: POLLIN)
      let r = poll(addr fds[0], fds.len.Tnfds, -1)
      if r < 0:
        if osLastError().cint == EINTR: continue
        break
      if fds[0].revents != 0: break   # command tree is gone
      let dnsAt = fds.len - 1
      if hasDns and (fds[dnsAt].revents and POLLIN) != 0:
        ctx.sh.maybeReload()
        ctx.sh.recvDns()
      for i in 1 ..< dnsAt:
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
  let ctx = p.acceptCtx
  if ctx != nil:
    ctx.sh.running = false
    joinThread(ctx.acceptThread)
  when defined(posix):
    p.sock.close()
  else:
    closeSock(p.sock.getFd())
  p.sock = nil
  if ctx != nil:
    if ctx.sh.ownPermit: ctx.sh.ps.close()
    deinitLock(ctx.sh.lock)
    when defined(posix):
      deinitLock(ctx.sh.fakeLock)
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
