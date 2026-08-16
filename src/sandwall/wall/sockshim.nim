## sockshim: the wall's raw-socket portability layer.
##
## The proxy, the netns bridge and the splice loop are written against
## poll/recv/send/shutdown; on Windows those map to WSAPoll and the
## ws2_32 calls. One module holds that mapping plus the two-socket
## byte-forwarding loop both the proxy and the netns bridge run - the
## loop shape (poll both, recv on readable, write-all to the peer,
## half-close on EOF, drop dead fds from the poll set) is identical
## everywhere and was previously copy-pasted per module.

import std/[os, nativesockets]
when defined(posix):
  import std/posix
else:
  import std/winlean except Socket

const spliceBuf* = 64 * 1024

when defined(windows):
  import std/winlean as wl

  type
    TPollfdW* = object
      fd*: SocketHandle
      events*, revents*: int16
  proc wsaPoll*(fds: ptr TPollfdW; nfds: culong; timeout: cint): cint
    {.stdcall, dynlib: "ws2_32", importc: "WSAPoll".}
  proc wsaRecv*(s: SocketHandle; buf: pointer; len, flags: cint): cint
    {.stdcall, dynlib: "ws2_32", importc: "recv".}
  proc wsaSend*(s: SocketHandle; buf: pointer; len, flags: cint): cint
    {.stdcall, dynlib: "ws2_32", importc: "send".}
  proc wsaSocket*(af, typ, protocol: cint): SocketHandle
    {.stdcall, dynlib: "ws2_32", importc: "socket".}
  proc wsaConnect*(s: SocketHandle; name: ptr SockAddr; namelen: cint): cint
    {.stdcall, dynlib: "ws2_32", importc: "connect".}
  proc wsaAccept*(s: SocketHandle; a: ptr SockAddr; n: ptr cint): SocketHandle
    {.stdcall, dynlib: "ws2_32", importc: "accept".}
  proc wsaShutdown*(s: SocketHandle; how: cint): cint
    {.stdcall, dynlib: "ws2_32", importc: "shutdown".}
  proc wsaIoctl*(s: SocketHandle; cmd: clong; argp: ptr culong): cint
    {.stdcall, dynlib: "ws2_32", importc: "ioctlsocket".}
  proc inetNtopW*(family: cint; pAddr: pointer; buf: WideCString;
                 len: csize_t): WideCString
    {.stdcall, dynlib: "ws2_32", importc: "InetNtopW".}
  const
    POLLIN_W*: int16 = 0x0300    # POLLRDNORM|POLLRDBAND
    POLLOUT_W*: int16 = 0x0010   # POLLWRNORM
    POLLERR_W*: int16 = 0x0001
    POLLHUP_W*: int16 = 0x0002
    POLLNVAL_W*: int16 = 0x0004
    FIONBIO_W*: clong = -2147195266  # 0x8004667E as signed long
  proc pollW*(fds: ptr TPollfdW; nfds: int; timeout: cint): cint =
    wsaPoll(fds, nfds.culong, timeout)
  template interruptedW*(): bool = osLastError().cint == WSAEINTR

proc closeSock*(fd: SocketHandle) =
  when defined(posix):
    discard posix.close(fd)
  else:
    discard wl.closesocket(fd)

proc sendAll*(fd: SocketHandle; buf: pointer; len: int): bool =
  ## Write all `len` bytes, retrying on EINTR. False on a hard error.
  var off = 0
  while off < len:
    when defined(posix):
      let flags = when defined(linux): MSG_NOSIGNAL else: 0'i32
      let n = posix.send(fd, cast[pointer](cast[int](buf) + off),
                         (len - off).cint, flags)
      if n <= 0:
        if n < 0 and osLastError().cint == EINTR: continue
        return false
      off.inc n
    else:
      let n = wsaSend(fd, cast[pointer](cast[int](buf) + off),
                      (len - off).cint, 0)
      if n <= 0:
        if n < 0 and interruptedW(): continue
        return false
      off.inc n
  true

proc shutdownWr*(fd: SocketHandle) =
  when defined(posix):
    discard posix.shutdown(fd, SHUT_WR)
  else:
    discard wsaShutdown(fd, 1)  # SD_SEND

proc splice*(a, b: SocketHandle) =
  ## Forward bytes between `a` and `b` until both directions hit EOF,
  ## half-closing the write side on each EOF. No timeout: long-lived
  ## TLS tunnels must survive idle.
  var bufA = newString(spliceBuf)
  var bufB = newString(spliceBuf)
  var aDead = false   # a -> b direction closed
  var bDead = false   # b -> a direction closed
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
          if not sendAll(dst, buf, n.int):
            if not dead[]:
              shutdownWr(dst)
              dead[] = true
        else:
          if not dead[]:
            shutdownWr(dst)
            dead[] = true
