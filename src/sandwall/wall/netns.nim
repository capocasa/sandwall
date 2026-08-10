## netns: the Linux half of the wall's kernel fence.
##
## `enterNetns` extends the mask.nim user+mount namespace with
## CLONE_NEWNET. A fresh network namespace has only `lo` (brought up
## here via SIOCSIFFLAGS) and no external interface, so every
## non-loopback egress - TCP, UDP, DNS - fails at the kernel. The only
## way off the machine is the chunk-2 proxy, reached through the
## unix-socket bridge:
##
##   Parent (unfenced) runs the proxy on host loopback AND on a unix
##   socket inside the sandbox's writable tree. A filesystem unix
##   socket crosses netns boundaries because it is a file, not a
##   network object. Inside the fence, `bridgeToUnix` listens on
##   127.0.0.1:PORT and splices each accepted connection to that unix
##   socket; proxy env vars in the child point at 127.0.0.1:PORT.
##
## Ordering contract for the fenced child:
##   maskDenied(denied) / restrict(...) -> enterNetns() ->
##   bridgeToUnix(...) -> exec.
## In practice restrict() runs the whole sequence (see restrict.nim):
## the userns is created once with CLONE_NEWNET included, so the net
## fence must be requested before or with the first restriction.
## bridgeToUnix forks a dedicated bridge PROCESS (not a thread):
## exec() would kill any in-process thread along with the image.
##
## The Landlock fs rules must still allow connect()ing to the unix
## socket path: the socket must live in a directory the policy leaves
## writable (a per-box tmp dir), so the fence cannot be used with a
## policy that mounts the socket dir read-only.

when defined(linux):
  import std/[net, nativesockets, os, posix]
  import ../mask

  const
    SIOCGIFFLAGS = 0x8913.culong
    SIOCSIFFLAGS = 0x8914.culong
    IFF_UP = 0x1.cshort
    IFF_RUNNING = 0x40.cshort

  proc ioctl(fd: cint; request: culong; arg: pointer): cint
      {.importc, header: "<sys/ioctl.h>".}


  type IfReq {.importc: "struct ifreq", header: "<net/if.h>".} = object
    ifr_name: array[16, char]
    ifr_flags: cshort ## start of the union; flags member sits at offset 0

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

  # ------------------------------------------------------- bridge

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

  proc splice(a, b: SocketHandle) =
    ## Forward bytes between `a` and `b` until both directions hit EOF.
    ## Same loop shape as the proxy's splice.
    var buf = newString(64 * 1024)
    var aDead = false
    var bDead = false
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
        let (src, dst) = if i == 0: (a, b) else: (b, a)
        let dead = if i == 0: addr aDead else: addr bDead
        if (rev and (POLLERR or POLLNVAL)) != 0:
          if not dead[]:
            discard posix.shutdown(dst, SHUT_WR)
            dead[] = true
          continue
        if (rev and (POLLIN or POLLHUP)) != 0:
          let n = posix.recv(src, addr buf[0], buf.len.cint, 0'i32)
          if n > 0:
            var off = 0
            while off < n:
              let flags = when defined(linux): MSG_NOSIGNAL else: 0'i32
              let s = posix.send(dst, addr buf[off], (n - off).cint, flags)
              if s <= 0:
                if s < 0 and osLastError().cint == EINTR: continue
                break
              off.inc s
            if off < n:
              if not dead[]:
                discard posix.shutdown(dst, SHUT_WR)
                dead[] = true
          else:
            if not dead[]:
              discard posix.shutdown(dst, SHUT_WR)
              dead[] = true

  proc serveBridgeConn(cfd: SocketHandle; sockPath: string) {.thread.} =
    let up = dialUnix(sockPath)
    if up == osInvalidSocket:
      discard posix.close(cfd)
      return
    splice(cfd, up)
    discard posix.close(up)
    discard posix.close(cfd)

  var leaked: seq[Socket]
    ## Bridge listener sockets live until exec/exit; keeping them in a
    ## global stops the net.Socket finalizer from closing the fd.

  proc bridgeProcess(listener: SocketHandle; sockPath: string;
                     deathFd: cint) =
    ## The bridge's whole lifetime: accept a connection, fork a worker
    ## to splice it, reap finished workers, repeat. Fork-per-connection
    ## because one kept-alive tunnel (a redirect target holding its
    ## first connection open, say) must not starve the next accept;
    ## worker processes are immune to the exec() that would kill
    ## in-process threads. Polls `deathFd` alongside the listener: EOF
    ## there means the last holder of the fenced command's pipe end is
    ## gone, so the bridge exits; its workers die with it (session).
    while true:
      var status: cint
      discard waitpid(-1.Pid, status, WNOHANG)  # reap one zombie per turn
      var fds = [TPollfd(fd: listener.cint, events: POLLIN, revents: 0),
                 TPollfd(fd: deathFd, events: POLLIN, revents: 0)]
      let r = poll(addr fds[0], 2, -1)
      if r < 0:
        if osLastError().cint == EINTR: continue
        return
      if fds[1].revents != 0:
        return  # parent pipe closed (or errored): command tree is gone
      if (fds[0].revents and POLLIN) == 0: continue
      let cfd = posix.accept(listener, nil, nil)
      if cfd == osInvalidSocket:
        if osLastError().cint == EINTR: continue
        sleep(10)
        continue
      let wpid = posix.fork()
      if wpid == 0:
        discard posix.close(listener)
        discard posix.close(deathFd)
        serveBridgeConn(cfd, sockPath)
        exitnow(0)
      discard posix.close(cfd)  # worker owns the connection now
      if wpid < 0:
        # fork failed: serve inline rather than drop the connection
        serveBridgeConn(cfd, sockPath)

  proc bridgeToUnix*(listenPort: uint16; sockPath: string): uint16 =
    ## Listen on 127.0.0.1:listenPort (0 = ephemeral) inside the netns
    ## and fork a bridge process that splices every accepted connection
    ## to the AF_UNIX socket at sockPath (the host-side proxy
    ## listener). A separate process because exec() would kill an
    ## in-process thread. Call BEFORE exec. Returns the actual bound
    ## port.
    ##
    ## Bridge lifetime: the restricting process (box) exec()s away
    ## right after this call, and PR_SET_PDEATHSIG only fires when the
    ## forking THREAD exits, not on exec - so instead the bridge
    ## watches a pipe whose write end the parent holds. The write fd
    ## is NOT close-on-exec: box's exec closes it implicitly? No -
    ## exec only closes CLOEXEC fds, so the pipe end survives into the
    ## exec'd command and the bridge lives exactly as long as the
    ## fenced command tree (any fork of the command holds the fd too).
    ## When the last holder exits the pipe hits EOF and the bridge
    ## kills itself, releasing the netns.
    let sock = newSocket(buffered = false)
    sock.setSockOpt(OptReuseAddr, true)
    sock.bindAddr(Port(listenPort), "127.0.0.1")
    sock.listen()
    result = uint16(sock.getLocalAddr()[1])
    var deathPipe: array[2, cint]
    if posix.pipe(deathPipe) != 0:
      raiseOSError(osLastError())
    let pid = posix.fork()
    if pid == 0:
      discard posix.close(deathPipe[1])  # child only reads
      bridgeProcess(sock.getFd(), sockPath, deathPipe[0])
      exitnow(0)
    if pid < 0:
      raiseOSError(osLastError())
    discard posix.close(deathPipe[0])  # parent (and its exec) writes
    leaked.add(sock)
