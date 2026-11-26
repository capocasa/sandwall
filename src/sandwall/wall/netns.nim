## netns: the Linux half of the wall's kernel fence.
##
## `enterNetns` extends the mask.nim user+mount namespace with
## CLONE_NEWNET. A fresh network namespace has only `lo` (brought up
## here via SIOCSIFFLAGS) and no external interface, so every
## non-loopback egress - TCP, UDP, DNS - fails at the kernel. The only
## way off the machine is the forwarder (wall/proxy.nim), reached
## through unix-socket bridges out of this module. There are two ways
## in, and a run uses one or the other:
##
##   env mode (the original bridge). The parent runs the forwarder on
##   a unix socket inside the sandbox's writable tree; a filesystem
##   unix socket crosses netns boundaries because it is a file, not a
##   network object. `bridgeToUnix` listens on 127.0.0.1:PORT inside
##   the netns and splices each accepted connection to that unix
##   socket; proxy env vars in the child point at 127.0.0.1:PORT.
##
##   raw mode (`prepareRawFence` + `startRawBridges`). The child needs
##   no env vars and no shim: nft redirects every TCP connection to a
##   non-loopback address onto a raw listener here, the bridge reads
##   the original destination with SO_ORIGINAL_DST and tells the
##   forwarder where the connection was going (`SWRAW <ip> <port>`,
##   then it splices). The destination is a fake-IP out of 198.18.0.0/15
##   that the fence DNS handed out: a UDP relay from 127.0.0.1:53 to
##   the forwarder's `dns.sock` answers the child's queries by policy
##   (wall/dns.nim). The forwarder owns the fake-IP bindings, so they
##   outlive the netns. Loopback is not redirected, so the child's own
##   services keep working.
##
## Ordering contract for the fenced child:
##   maskDenied(denied) / restrict(...) -> enterNetns() ->
##   [prepareRawFence] -> bridges -> exec.
## In practice restrict() runs the whole sequence (see restrict.nim):
## the userns is created once with CLONE_NEWNET included, so the net
## fence must be requested before or with the first restriction. The
## raw half goes up before Landlock (nft needs exec, the resolv.conf
## bind mount is a mount), the forked relays after it, so they inherit
## the domain; a bridge is a dedicated PROCESS (not a thread): exec()
## would kill any in-process thread along with the image.
##
## The Landlock fs rules must still allow connect()ing to the unix
## sockets: they must live in a directory the policy leaves writable
## (a per-box tmp dir), so the fence cannot be used with a policy that
## mounts the socket dir read-only.
##
## Raw mode can fail (no nft, no mount permission). It fails before
## anything is half up: `prepareRawFence` raises RawUnavailableError
## and the caller exits 75 with `RawMarker` on stderr, which is the
## parent's signal to run the command again in env mode (restrict.nim
## and the standalone CLI; 3code does the same from its side).

when defined(linux):
  import std/[net, nativesockets, os, posix, strutils]
  import ../mask
  import ./dns
  import ./sockshim

  const
    SIOCGIFFLAGS = 0x8913.culong
    SIOCSIFFLAGS = 0x8914.culong
    IFF_UP = 0x1.cshort
    IFF_RUNNING = 0x40.cshort
    PR_SET_PDEATHSIG = 1.cint

    RawMarker* = "sandwall: raw unavailable, retrying env"
      ## The one line the fenced child prints before exit 75 when the
      ## raw fence could not go up; the parent re-spawns in env mode
      ## only when it sees it.
    RawFallbackExit* = 75
    SOL_IP = 0               ## the ip level; getsockopt wants a plain cint here
    SO_ORIGINAL_DST = 80
    DnsRelayPort* = 53'u16     ## where the child's resolv.conf points
    DnsRelayWaitMs = 5_000     ## per query, matching the resolver's own patience
    ResolvConf = "/etc/resolv.conf"
    FakePoolPrefixLen = 15'u8

  proc ioctl(fd: cint; request: culong; arg: pointer): cint
      {.importc, header: "<sys/ioctl.h>".}
  proc prctl(option: cint; arg2: culong): cint
      {.importc, header: "<sys/prctl.h>", varargs.}
  proc if_nametoindex(ifname: cstring): cuint {.importc, header: "<net/if.h>".}

  type IfReq {.importc: "struct ifreq", header: "<net/if.h>".} = object
    ifr_name: array[16, char]
    ifr_flags: cshort ## start of the union; flags member sits at offset 0

  type RawUnavailableError* = object of CatchableError
    ## The raw fence could not be put up. Raised by `prepareRawFence`
    ## with nothing half-applied: no Landlock, no masks, no bridge
    ## forked, no resolv.conf mounted. The process is already in the
    ## netns, which cannot be undone, so the only sound answers are to
    ## exit (75, with `RawMarker`) or to stop.

  proc bringLoopbackUp() =
    let fd = posix.socket(AF_INET, SOCK_DGRAM, 0)
    if fd == osInvalidSocket:
      raiseOSError(osLastError())
    defer: discard posix.close(fd)
    var req: IfReq
    copyMem(addr req.ifr_name[0], cstring("lo"), 3)
    if ioctl(fd.cint, SIOCGIFFLAGS, addr req) != 0:
      raiseOSError(osLastError())
    req.ifr_flags = req.ifr_flags or IFF_UP or IFF_RUNNING
    if ioctl(fd.cint, SIOCSIFFLAGS, addr req) != 0:
      raiseOSError(osLastError())

  proc enterNetns*() =
    ## Confine this process (and future children) to loopback-only
    ## networking. Idempotent-safe after maskDenied: both funnel through
    ## mask.ensureUserns, which unshares exactly once per process.
    ## Raises OSError when unprivileged user namespaces are unavailable;
    ## callers follow the established warn-and-continue posture.
    ensureUserns(CLONE_NEWNET_C)
    bringLoopbackUp()

  # ------------------------------------------------------- listeners

  proc boundPort(fd: SocketHandle): uint16 =
    var sa: Sockaddr_in
    var slen = SockLen(sizeof(sa))
    if getsockname(fd, cast[ptr SockAddr](addr sa), addr slen) != 0:
      raiseOSError(osLastError())
    uint16(nativesockets.ntohs(uint16(sa.sin_port)))

  proc listenOn(sockType: cint; port: uint16): SocketHandle =
    ## A socket bound to 127.0.0.1:port (0 = ephemeral) inside the
    ## netns; a TCP one listens. SOCK_CLOEXEC: the exec'd command must
    ## not inherit it, the forked relay keeps it without exec.
    result = posix.socket(AF_INET, sockType or SOCK_CLOEXEC, 0)
    if result == osInvalidSocket: return
    var sa: Sockaddr_in
    sa.sin_family = TSa_Family(AF_INET)
    sa.sin_port = nativesockets.htons(port)
    sa.sin_addr.s_addr = nativesockets.htonl(INADDR_LOOPBACK)
    if bindSocket(result, cast[ptr SockAddr](addr sa), SockLen(sizeof(sa))) != 0 or
       (sockType == SOCK_STREAM and nativesockets.listen(result) != 0):
      discard posix.close(result)
      result = osInvalidSocket

  # --------------------------------------------------------- bridges

  proc dialUnix(path: string): SocketHandle =
    result = posix.socket(AF_UNIX, SOCK_STREAM, 0)
    if result == osInvalidSocket: return
    var sa: Sockaddr_un
    sa.sun_family = TSa_Family(AF_UNIX)
    if path.len >= sa.sun_path.len:
      discard posix.close(result)
      return osInvalidSocket
    copyMem(addr sa.sun_path[0], cstring(path), path.len + 1)
    if posix.connect(result, cast[ptr SockAddr](addr sa),
                     SockLen(sizeof(sa))) != 0:
      discard posix.close(result)
      return osInvalidSocket

  var relayQueries = 0
    ## names the relay's per-query sockets; the process is single-threaded

  proc dialUnixDgram(path, bindPath: string): SocketHandle =
    ## A fresh AF_UNIX datagram socket, connected to `path` and bound to
    ## the filesystem name `bindPath`. One per query (see
    ## dnsRelayProcess): a reply the client stopped waiting for has
    ## nowhere to land once the socket is gone. Bound, because a datagram
    ## sender without an address is anonymous and the forwarder answers
    ## to the sender's address. A FILE, not an abstract name: the
    ## abstract namespace is per network namespace (kernel 3.3+), the
    ## forwarder answers from outside the fence's netns, and its reply
    ## to an abstract address there refuses before it ever reaches a
    ## socket.
    result = posix.socket(AF_UNIX, SOCK_DGRAM, 0)
    if result == osInvalidSocket: return
    var sa: Sockaddr_un
    sa.sun_family = TSa_Family(AF_UNIX)
    if bindPath.len >= sa.sun_path.len or path.len >= sa.sun_path.len:
      discard posix.close(result)
      return osInvalidSocket
    copyMem(addr sa.sun_path[0], cstring(bindPath), bindPath.len + 1)
    removeFile(bindPath)
    if posix.bindSocket(result, cast[ptr SockAddr](addr sa),
                        SockLen(sizeof(sa))) != 0:
      discard posix.close(result)
      return osInvalidSocket
    copyMem(addr sa.sun_path[0], cstring(path), path.len + 1)
    if posix.connect(result, cast[ptr SockAddr](addr sa),
                     SockLen(sizeof(sa))) != 0:
      discard posix.close(result)
      return osInvalidSocket

  proc serveBridgeConn(cfd: SocketHandle; sockPath: string) {.thread.} =
    let up = dialUnix(sockPath)
    if up == osInvalidSocket:
      discard posix.close(cfd)
      return
    splice(cfd, up)
    discard posix.close(up)
    discard posix.close(cfd)

  proc originalDst(cfd: SocketHandle): tuple[ip: IpAddress, port: uint16] =
    ## Where a redirected connection was going before nft sent it here.
    var sa: Sockaddr_in
    var slen = SockLen(sizeof(sa))
    if getsockopt(cfd, SOL_IP, SO_ORIGINAL_DST, addr sa, addr slen) != 0:
      raiseOSError(osLastError())
    var ip = IpAddress(family: IpAddressFamily.IPv4)
    copyMem(addr ip.address_v4[0], addr sa.sin_addr, 4)
    (ip, uint16(nativesockets.ntohs(uint16(sa.sin_port))))

  proc serveRawConn(cfd: SocketHandle; sockPath: string) {.thread.} =
    ## One redirected connection: hand the forwarder its original
    ## destination in the `SWRAW <ip> <port>` line it detects ahead of
    ## any protocol, then splice. The forwarder decides; a denied
    ## target just sees the connection close.
    let dst =
      try: originalDst(cfd)
      except OSError:
        discard posix.close(cfd)
        return
    let up = dialUnix(sockPath)
    if up == osInvalidSocket:
      discard posix.close(cfd)
      return
    let line = "SWRAW " & $dst.ip & " " & $dst.port & "\n"
    if sendAll(up, addr line[0], line.len):
      splice(cfd, up)
    discard posix.close(up)
    discard posix.close(cfd)

  var leaked: seq[Socket]
    ## Bridge listener sockets live until exec/exit; keeping them in a
    ## global stops the net.Socket finalizer from closing the fd.

  proc bridgeProcess(listener: SocketHandle; sockPath: string; raw: bool) =
    ## The bridge's whole lifetime: accept a connection, fork a worker
    ## to splice it, reap finished workers, repeat. Fork-per-connection
    ## because one kept-alive tunnel (a redirect target holding its
    ## first connection open, say) must not starve the next accept;
    ## worker processes are immune to the exec() that would kill
    ## in-process threads. Lifetime is PR_SET_PDEATHSIG set by the
    ## fork child (see forkBridge): the kernel delivers SIGKILL when
    ## the fenced command exits, ending this loop with the bridge.
    while true:
      var status: cint
      discard waitpid(-1.Pid, status, WNOHANG)  # reap one zombie per turn
      var fds = [TPollfd(fd: listener.cint, events: POLLIN, revents: 0)]
      let r = poll(addr fds[0], 1, -1)
      if r < 0:
        if osLastError().cint == EINTR: continue
        return
      if r == 0 or (fds[0].revents and POLLIN) == 0: continue
      let cfd = posix.accept(listener, nil, nil)
      if cfd == osInvalidSocket:
        if osLastError().cint == EINTR: continue
        sleep(10)
        continue
      let wpid = posix.fork()
      if wpid == 0:
        discard posix.close(listener)
        if raw: serveRawConn(cfd, sockPath)
        else: serveBridgeConn(cfd, sockPath)
        exitnow(0)
      discard posix.close(cfd)  # worker owns the connection now
      if wpid < 0:
        # fork failed: serve inline rather than drop the connection
        if raw: serveRawConn(cfd, sockPath)
        else: serveBridgeConn(cfd, sockPath)

  proc parentGone(parentPid: Pid): bool =
    ## PDEATHSIG race guard: a parent that died between fork and prctl
    ## never delivers the signal, and an orphaned relay serves nothing;
    ## the child exits instead of leaking a listener into the netns.
    prctl(PR_SET_PDEATHSIG, SIGKILL.culong) != 0 or
      posix.getppid() != parentPid

  proc forkBridge(listener: SocketHandle; sockPath: string; raw: bool): Pid =
    let parentPid = posix.getpid()
    let pid = posix.fork()
    if pid == 0:
      if parentGone(parentPid): exitnow(0)
      bridgeProcess(listener, sockPath, raw)
      exitnow(0)
    pid

  proc bridgeToUnix*(listenPort: uint16; sockPath: string): uint16 =
    ## Listen on 127.0.0.1:listenPort (0 = ephemeral) inside the netns
    ## and fork a bridge process that splices every accepted connection
    ## to the AF_UNIX socket at sockPath (the host-side proxy
    ## listener). A separate process because exec() would kill an
    ## in-process thread. Call BEFORE exec. Returns the actual bound
    ## port.
    ##
    ## Bridge lifetime: the bridge cannot watch a pipe held by the
    ## fenced command - fd-hygienic children break that (ssh calls
    ## close_range(3, ...) at startup, which used to take the netns's
    ## only egress path down mid-command). Instead the bridge sets
    ## PR_SET_PDEATHSIG(SIGKILL): the signal tracks the parent PID,
    ## which survives exec() unchanged, so it fires exactly when the
    ## process box became (the fenced command) exits. The old concern
    ## that PDEATHSIG misses exec is misplaced: exec does not exit the
    ## forking thread, only process death does.
    let sock = newSocket(buffered = false)
    sock.setSockOpt(OptReuseAddr, true)
    sock.bindAddr(Port(listenPort), "127.0.0.1")
    sock.listen()
    result = uint16(sock.getLocalAddr()[1])
    if forkBridge(sock.getFd(), sockPath, raw = false) < 0:
      raiseOSError(osLastError())
    leaked.add(sock)

  proc dnsRelayProcess(udp: SocketHandle; dnsSockPath: string) =
    ## UDP 127.0.0.1:53 inside the netns <-> the forwarder's dns.sock.
    ## One query at a time, each over its own connected datagram socket,
    ## so a late reply to a query the client gave up on has nowhere to
    ## land. The forwarder answers from memory (policy plus pool), so
    ## the wait is short unless the first resolution of a name is.
    let replyDir = splitFile(dnsSockPath).dir
    while true:
      var buf: array[4096, char]
      var client: Sockaddr_in
      var clen = SockLen(sizeof(client))
      let n = posix.recvfrom(udp, addr buf[0], buf.len, 0,
                             cast[ptr SockAddr](addr client), addr clen)
      if n <= 0:
        if osLastError().cint == EINTR: continue
        sleep(10)
        continue
      inc relayQueries
      let bindPath = replyDir / "relay-" & $getpid() & "-" &
        $relayQueries & ".dg"
      let up = dialUnixDgram(dnsSockPath, bindPath)
      if up == osInvalidSocket: continue
      if posix.send(up, addr buf[0], n, 0) == n:
        var pfd = TPollfd(fd: up.cint, events: POLLIN, revents: 0)
        if poll(addr pfd, 1, DnsRelayWaitMs) > 0 and
           (pfd.revents and POLLIN) != 0:
          let m = posix.recv(up, addr buf[0], buf.len, 0)
          if m > 0:
            discard posix.sendto(udp, addr buf[0], m, 0,
                                 cast[ptr SockAddr](addr client), clen)
      discard posix.close(up)
      removeFile(bindPath)

  proc forkRelay(udp: SocketHandle; dnsSockPath: string): Pid =
    let parentPid = posix.getpid()
    let pid = posix.fork()
    if pid == 0:
      if parentGone(parentPid): exitnow(0)
      dnsRelayProcess(udp, dnsSockPath)
      exitnow(0)
    pid

  # ----------------------------------------------------------- route

  type
    NlMsghdr {.importc: "struct nlmsghdr", header: "<linux/netlink.h>".} = object
      nlmsg_len: uint32
      nlmsg_type: uint16
      nlmsg_flags: uint16
      nlmsg_seq: uint32
      nlmsg_pid: uint32
    NlMsgerr {.importc: "struct nlmsgerr", header: "<linux/netlink.h>".} = object
      error: cint
      msg: NlMsghdr
    SockaddrNl {.importc: "struct sockaddr_nl", header: "<linux/netlink.h>".} = object
      nl_family: cushort
      nl_pad: cushort
      nl_pid: uint32
      nl_groups: uint32
    RtMsg {.importc: "struct rtmsg", header: "<linux/rtnetlink.h>".} = object
      rtm_family: uint8
      rtm_dst_len: uint8
      rtm_src_len: uint8
      rtm_tos: uint8
      rtm_table: uint8
      rtm_protocol: uint8
      rtm_scope: uint8
      rtm_type: uint8
      rtm_flags: uint32
    RtAttr {.importc: "struct rtattr", header: "<linux/rtnetlink.h>".} = object
      rta_len: uint16
      rta_type: uint16
    RouteAttr = object
      attr: RtAttr
      value: uint32
    RouteMsg = object
      nl: NlMsghdr
      rt: RtMsg
      dst: RouteAttr     ## RTA_DST: the network address, network byte order
      prefsrc: RouteAttr ## RTA_PREFSRC: 127.0.0.1, so connections out the
                         ## fake pool have a source address (a source-less
                         ## device route leaves the client at 0.0.0.0 and
                         ## the forwarder's reply has nowhere to go)
      oif: RouteAttr      ## RTA_OIF: the output interface index

  const
    # UAPI numbers (linux/netlink.h, linux/rtnetlink.h); not in Nim's posix
    AF_NETLINK = 16
    NETLINK_ROUTE = 0
    NLMSG_ERROR = 2'u16
    RTM_NEWROUTE = 24'u16
    NlmFRequest = 0x0001'u16
    NlmFAck = 0x0004'u16
    NlmFCreate = 0x0400'u16
    RTA_DST = 1'u16
    RTA_PREFSRC = 7'u16
    RTA_OIF = 4'u16
    RTN_UNICAST = 1'u8
    RTPROT_BOOT = 3'u8
    RT_SCOPE_LINK = 253'u8
    RT_TABLE_MAIN = 254'u8
    # prctl ambient caps: nft keeps CAP_NET_ADMIN across execv although
    # the uid self-map makes the namespace euid non-zero
    PR_CAP_AMBIENT = 47
    PR_CAP_AMBIENT_RAISE = 2
    CAP_NET_ADMIN = 12

  proc routeMessage(network: IpAddress; dstLen: uint8; oif: uint32): RouteMsg =
    ## `ip route add <network>/<len> dev lo scope link`, as one
    ## RTM_NEWROUTE: nothing but the fake pool becomes routable.
    result.nl = NlMsghdr(nlmsg_len: sizeof(RouteMsg).uint32,
                         nlmsg_type: RTM_NEWROUTE,
                         nlmsg_flags: NlmFRequest or NlmFAck or NlmFCreate,
                         nlmsg_seq: 1, nlmsg_pid: 0)
    result.rt = RtMsg(rtm_family: uint8(AF_INET), rtm_dst_len: dstLen,
                      rtm_table: RT_TABLE_MAIN, rtm_protocol: RTPROT_BOOT,
                      rtm_scope: RT_SCOPE_LINK, rtm_type: RTN_UNICAST)
    result.dst = RouteAttr(attr: RtAttr(rta_len: uint16(sizeof(RouteAttr)),
                                        rta_type: RTA_DST))
    copyMem(addr result.dst.value, unsafeAddr network.address_v4[0], 4)
    result.prefsrc = RouteAttr(attr: RtAttr(rta_len: uint16(sizeof(RouteAttr)),
                                            rta_type: RTA_PREFSRC),
                               value: 0x0100_007f'u32)  # 127.0.0.1, bytes 7f 00 00 01
    result.oif = RouteAttr(attr: RtAttr(rta_len: uint16(sizeof(RouteAttr)),
                                        rta_type: RTA_OIF), value: oif)

  proc netlinkRoute(network: IpAddress; dstLen: uint8; oif: uint32) =
    ## Send one RTM_NEWROUTE and read its acknowledgement. Raises
    ## OSError, with the kernel's errno for the route when it refused.
    let fd = posix.socket(AF_NETLINK, SOCK_RAW or SOCK_CLOEXEC, NETLINK_ROUTE)
    if fd == osInvalidSocket: raiseOSError(osLastError())
    defer: discard posix.close(fd)
    var local: SockaddrNl
    local.nl_family = cushort(AF_NETLINK)
    if bindSocket(fd, cast[ptr SockAddr](addr local), SockLen(sizeof(local))) != 0:
      raiseOSError(osLastError())
    var msg = routeMessage(network, dstLen, oif)
    if posix.send(fd, addr msg, sizeof(msg), 0) != sizeof(msg):
      raiseOSError(osLastError())
    var buf: array[4096, uint8]
    let n = posix.recv(fd, addr buf[0], buf.len, 0)
    if n < sizeof(NlMsgerr):
      raise newException(OSError, "netlink: no acknowledgement for the route")
    let hdr = cast[ptr NlMsghdr](addr buf[0])
    if hdr.nlmsg_type != NLMSG_ERROR: return
    # the error follows the reply's own nlmsghdr (NLMSG_DATA), the cast
    # from buf[0] would read that header's nlmsg_len instead
    let err = cast[ptr NlMsgerr](addr buf[sizeof(NlMsghdr)])[].error
    if err != 0: raiseOSError(OSErrorCode(-err), "route add")

  # ------------------------------------------------------------- nft

  proc findNft*(): string =
    ## Where nft is (PATH, then /usr/sbin where distros park it), or
    ## "". The parent probes with this to decide whether to try raw mode
    ## at all; the child looks again when it loads the ruleset.
    result = findExe("nft")
    if result.len == 0 and fileExists("/usr/sbin/nft"): result = "/usr/sbin/nft"

  proc nftRuleset*(rawPort: uint16): string =
    ## The netns's whole ruleset: TCP to anything but loopback (the
    ## fake pool included) lands on the raw listener, where the bridge
    ## reads the original destination. Loopback passes untouched, so
    ## the child's own services stay reachable; host loopback reached
    ## through the forwarder by name does not, in this mode. Netns
    ## local: the table dies with the namespace, no cleanup.
    "table ip sandwall_fwd {\n" &
    "  chain out {\n" &
    "    type nat hook output priority -100;\n" &
    "    meta l4proto tcp ip daddr != 127.0.0.0/8 redirect to :" & $rawPort & "\n" &
    "  }\n" &
    "}\n"

  type
    CapUserHeader {.importc: "struct __user_cap_header_struct",
        header: "<linux/capability.h>".} = object
      version: uint32
      pid: cint
    CapUserData {.importc: "struct __user_cap_data_struct",
        header: "<linux/capability.h>".} = object
      effective, permitted, inheritable: uint32

  proc syscall(n: clong): clong {.importc: "syscall", header: "<unistd.h>",
      varargs.}
  var SYS_capget {.importc: "SYS_capget", header: "<sys/syscall.h>".}: clong
  var SYS_capset {.importc: "SYS_capset", header: "<sys/syscall.h>".}: clong

  proc raiseAmbient(cap: cint) =
    ## Add `cap` to the inheritable set and raise it ambient, best effort.
    ## The raise alone answers EPERM while the cap is not in inheritable
    ## (ambient is a subset of inheritable), so capget/capset first. With
    ## no failure here the cap survives the execv of a non-privileged
    ## binary; a refusal surfaces as nft's own complaint, fail-closed.
    const capsetVersion = 0x20080522'u32
    var hdr = CapUserHeader(version: capsetVersion, pid: 0)
    var data: array[2, CapUserData]
    if syscall(SYS_capget, addr hdr, addr data) != 0: return
    let word = cap div 32
    data[word].inheritable = data[word].inheritable or
      (1'u32 shl (cap mod 32))
    hdr = CapUserHeader(version: capsetVersion, pid: 0)
    if syscall(SYS_capset, addr hdr, addr data) != 0: return
    discard prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE.culong, cap.culong,
                  0, 0)

  proc runNft(nft, rulesPath: string): string =
    ## `nft -f rulesPath`. The first line of nft's complaint when the
    ## ruleset was refused, "" when it was taken. nft's stderr is read
    ## here because the caller decides what the user gets to see.
    var errPipe: array[2, cint]
    if posix.pipe(errPipe) != 0: raiseOSError(osLastError())
    let pid = posix.fork()
    if pid == 0:
      discard posix.close(errPipe[0])
      discard posix.dup2(errPipe[1], 2)
      discard posix.close(errPipe[1])
      let null = posix.open("/dev/null", O_WRONLY)
      if null >= 0:
        discard posix.dup2(null, 1)
        discard posix.close(null)
      var argv = allocCStringArray([nft, "-f", rulesPath])
      # The uid self-map means full ns caps die at exec (euid != 0 in
      # the namespace), and this ruleset needs CAP_NET_ADMIN over the
      # netns. Ambient caps survive exec for an ordinary binary and
      # raising them wants no-new-privs, which ensureUserns set before
      # the unshare. Best effort: a refusal surfaces as nft's own
      # complaint below, the raw fence stays fail-closed.
      raiseAmbient(CAP_NET_ADMIN)
      discard posix.execv(nft.cstring, argv)
      exitnow(127)
    if pid < 0:
      discard posix.close(errPipe[0])
      discard posix.close(errPipe[1])
      raiseOSError(osLastError())
    discard posix.close(errPipe[1])
    var complaint = ""
    var buf: array[1024, char]
    while true:
      let n = posix.read(errPipe[0], addr buf[0], buf.len)
      if n <= 0: break
      let at = complaint.len
      complaint.setLen(at + n)
      copyMem(addr complaint[at], addr buf[0], n)
    discard posix.close(errPipe[0])
    var status: cint
    discard posix.waitpid(pid, status, 0)
    if WIFEXITED(status) and WEXITSTATUS(status) == 0: return ""
    for line in complaint.splitLines():
      if line.strip().len > 0: return line.strip()
    if WIFEXITED(status): "exit " & $WEXITSTATUS(status)
    else: "signal " & $WTERMSIG(status)

  # -------------------------------------------------------- raw fence

  type
    RawFence* = object
      ## The raw path's netns half, between `prepareRawFence` (before
      ## Landlock: route, nft table, resolv.conf, the two listeners)
      ## and `startRawBridges` (after it: the forked relay processes).
      proxySockPath*: string     ## the forwarder's unix listener, both relays' target
      dnsSockPath*: string        ## the forwarder's DNS datagram socket
      rawListener*: SocketHandle  ## TCP 127.0.0.1:rawPort: nft's redirect target
      rawPort*: uint16
      dnsUdp*: SocketHandle       ## UDP 127.0.0.1:53: what the child's resolv.conf names
      rawPid*: Pid
      dnsPid*: Pid

  proc unavailable(why: string) =
    raise newException(RawUnavailableError, "raw fence: " & why)

  proc prepareRawFence*(proxySockPath, dnsSockPath: string): RawFence =
    ## Inside the netns, before Landlock (nft needs exec, the mount
    ## needs the mount namespace as it is): make the fake pool routable,
    ## load the redirect, bind the raw listener and the DNS relay
    ## socket, and put `nameserver 127.0.0.1` over /etc/resolv.conf.
    ## Raises RawUnavailableError and then nothing is half up: the
    ## netns and the mount namespace were the caller's already, the
    ## table and the route die with the netns, no relay is forked and
    ## nothing is mounted past the point of failure.
    if proxySockPath.len == 0 or dnsSockPath.len == 0:
      raise newException(ValueError,
        "sandwall: the raw fence needs the proxy and the dns socket paths")
    let lo = if_nametoindex("lo")
    if lo == 0: unavailable("loopback interface not found")
    try:
      netlinkRoute(parseIpAddress("198.18.0.0"), FakePoolPrefixLen, lo)
    except OSError as e:
      unavailable(FakePoolNetwork & " dev lo: " & e.msg)
    result.proxySockPath = proxySockPath
    result.dnsSockPath = dnsSockPath
    result.rawListener = listenOn(SOCK_STREAM, 0)
    if result.rawListener == osInvalidSocket:
      unavailable("raw listener: " & $osLastError())
    result.rawPort = boundPort(result.rawListener)
    result.dnsUdp = listenOn(SOCK_DGRAM, DnsRelayPort)
    if result.dnsUdp == osInvalidSocket:
      unavailable("UDP 127.0.0.1:" & $DnsRelayPort & ": " & $osLastError())
    let nft = findNft()
    if nft.len == 0: unavailable("nft not found")
    let dir = parentDir(proxySockPath)
    let rulesPath = dir / "nft.conf"
    writeFile(rulesPath, nftRuleset(result.rawPort))
    let complaint = runNft(nft, rulesPath)
    if complaint.len > 0: unavailable("nft: " & complaint)
    let resolv = dir / "resolv.conf"
    writeFile(resolv, "nameserver 127.0.0.1\n")
    try:
      bindMount(resolv, ResolvConf)
    except OSError as e:
      unavailable(e.msg)

  proc startRawBridges*(f: var RawFence) =
    ## After Landlock, so both inherit the domain: fork the raw bridge
    ## and the DNS relay. Raises OSError when a fork fails; a relay
    ## that did start keeps listening, but with the forwarder's
    ## decisions behind it that fails closed like anything else here.
    f.rawPid = forkBridge(f.rawListener, f.proxySockPath, raw = true)
    if f.rawPid < 0: raiseOSError(osLastError())
    f.dnsPid = forkRelay(f.dnsUdp, f.dnsSockPath)
    if f.dnsPid < 0: raiseOSError(osLastError())
