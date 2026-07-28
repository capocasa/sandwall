## connect: the wall's SOCKS5 client helper.
##
## `socksConnect` connects to the wall proxy, performs the SOCKS5
## no-auth handshake for (host, port), then pumps bytes between
## stdin/stdout and the tunnel. This is exactly the shape git's
## ProxyCommand needs:
##
##   GIT_SSH_COMMAND='ssh -o ProxyCommand="3code wall connect %h %p"'
##
## Exit codes: 0 on clean EOF, 1 on connect/handshake failure (message
## to stderr). Pure stdlib (std/net + std/posix poll loop).

import std/[nativesockets, net, os, posix, syncio]

proc pump(fd: SocketHandle): int =
  ## Bidirectional pump: stdin -> fd, fd -> stdout, until both
  ## directions close. Returns 0 on clean EOF.
  var inDead = false
  var fdDead = false
  var buf = newString(64 * 1024)
  while not (inDead and fdDead):
    var fds: array[2, TPollfd]
    fds[0] = TPollfd(fd: 0, events: if inDead: 0'i16 else: POLLIN)
    fds[1] = TPollfd(fd: fd.cint, events: if fdDead: 0'i16 else: POLLIN)
    let r = poll(addr fds[0], 2, -1)
    if r < 0:
      if osLastError().cint == EINTR: continue
      return 1
    for i in 0 .. 1:
      let rev = fds[i].revents
      if rev == 0: continue
      let (src, dst, dstIsFd) =
        if i == 0: (SocketHandle(0), fd, true)
        else: (fd, SocketHandle(1), false)
      let dead = if i == 0: addr inDead else: addr fdDead
      if (rev and (POLLERR or POLLNVAL)) != 0:
        if not dead[]:
          if dstIsFd: discard posix.shutdown(dst, SHUT_WR)
          dead[] = true
        continue
      if (rev and (POLLIN or POLLHUP)) != 0:
        let n = posix.read(src.cint, addr buf[0], buf.len)
        if n > 0:
          var off = 0
          while off < n:
            let w = posix.write(dst.cint, addr buf[off], n - off)
            if w <= 0:
              if w < 0 and osLastError().cint == EINTR: continue
              return 1
            off.inc w
        else:
          if not dead[]:
            if dstIsFd: discard posix.shutdown(dst, SHUT_WR)
            dead[] = true
  0

proc socksConnect*(proxyPort: uint16; host: string; port: uint16): int =
  ## See module header. 0 clean EOF, 1 connect/handshake failure.
  let sock = try: dial("127.0.0.1", Port(proxyPort), buffered = false)
             except CatchableError:
               stderr.writeLine("sandwall connect: cannot reach proxy on 127.0.0.1:" &
                                $proxyPort)
               return 1
  let fd = sock.getFd()
  template fail(msg: string): untyped =
    stderr.writeLine("sandwall connect: " & msg)
    sock.close()
    return 1
  # greeting: version 5, one method (no auth)
  if not sock.trySend("\x05\x01\x00"):
    fail("proxy write failed")
  var buf = newString(512)
  if sock.recv(buf, 2, 15_000) != 2 or buf[0] != '\x05' or buf[1] != '\x00':
    fail("proxy refused no-auth SOCKS5")
  # request: connect, domain name, port
  if host.len > 255:
    fail("hostname too long")
  let req = "\x05\x01\x00\x03" & char(host.len) & host &
            char(port shr 8) & char(port and 0xff)
  if not sock.trySend(req):
    fail("proxy write failed")
  if sock.recv(buf, 4, 15_000) != 4 or buf[0] != '\x05':
    fail("truncated SOCKS5 reply")
  if buf[1] != '\x00':
    fail("proxy denied " & host & ":" & $port & " (SOCKS5 code " &
         $int(buf[1]) & ")")
  # skip the bound address in the reply
  let skip = case buf[3]
    of '\x01': 4
    of '\x04': 16
    of '\x03':
      if sock.recv(buf, 1, 15_000) != 1: fail("truncated SOCKS5 reply")
      int(buf[0])
    else: fail("bad SOCKS5 reply address type")
  var left = skip + 2
  while left > 0:
    let n = sock.recv(buf, min(left, buf.len), 15_000)
    if n <= 0: fail("truncated SOCKS5 reply")
    left -= n
  result = pump(fd)
  sock.close()
