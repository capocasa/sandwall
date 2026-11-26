## pfdaemon: the privileged half of the macOS pf fence.
##
## `sandwallpf` (the binary) is a LaunchDaemon root runs: it enables pf,
## makes the main ruleset reach the sandwall anchors, loads the orphan
## catch-all, and serves the unix socket in pf.nim's protocol. Decisions
## live in pf.nim; this module is the socket, the peer credential, the
## stdio hand-off and the one-time setup.
##
## The socket never grants privilege: a caller is authenticated by
## LOCAL_PEERCRED against the uid recorded at setup, and anything it has
## exec'd runs as itself, with a marker gid and a fence.
##
## The client side lives here too (`pfPing`, `pfBegin`, `pfExec`...), so a
## spawning process only needs this module.
##
## Compiles on Linux as well, with SO_PEERCRED standing in for
## LOCAL_PEERCRED, which is what lets the protocol be tested off macOS.

import std/[json, os, osproc, sequtils, streams, strutils, times]
import std/posix except Time
{.push warning[Deprecated]: off.}
import std/threadpool
{.pop.}

import ./pf
import ./permit
export pf

const
  PeerCredLevel* = 0          ## SOL_LOCAL on macOS
  PeerCredOpt* = 0x001        ## LOCAL_PEERCRED
  ScmRights* = 1              ## SCM_RIGHTS, same value on every POSIX
  SoPeercred = 17            ## Linux's stand-in for LOCAL_PEERCRED
  MaxRequestBytes* = 1 shl 20
  StdFds* = 3                ## stdin, stdout, stderr travel with exec

type
  Cmsghdr* {.importc: "struct cmsghdr", header: "<sys/socket.h>",
              pure, completeStruct.} = object
    cmsg_len*: SockLen     ## bytes including this header
    cmsg_level*: cint
    cmsg_type*: cint

  Xucred* = object             ## struct xucred, which the SDK keeps private
    cr_version*: cint
    cr_uid*: Uid
    cr_gid*: Gid
    cr_ngroups*: cint
    cr_groups*: array[16, Gid]

  Ucred* {.importc: "struct ucred", header: "<sys/socket.h>",
           pure, final.} = object
    pid*: Pid
    uid*: Uid
    gid*: Gid

# ------------------------------------------------------------- sockets

const
  AncillaryHeaderSize* = (sizeof(Cmsghdr) + sizeof(csize_t) - 1) and
    not (sizeof(csize_t) - 1)
    ## CMSG_DATA: the bytes after a cmsghdr, size_t-aligned

converter rawFd(s: SocketHandle): cint = cint(s)
  ## posix read/write/getsockopt take a plain descriptor.

proc sendAll(fd: SocketHandle; s: string) =
  var off = 0
  while off < s.len:
    let n = posix.write(fd, cast[pointer](s[off].addr), s.len - off)
    if n <= 0: return
    off += n

proc sendLine(fd: SocketHandle; node: JsonNode) =
  sendAll(fd, $node & "\n")

proc recvSome(fd: SocketHandle; buf: pointer; len: int): int =
  result = posix.recv(fd, buf, len.cint, 0)

proc peerUid*(fd: SocketHandle): int =
  ## The uid at the other end of a connected unix socket, -1 unknown.
  when defined(macosx):
    var cred: Xucred
    var len = SockLen(sizeof(cred))
    if getsockopt(fd, PeerCredLevel, PeerCredOpt, addr cred, addr len) != 0:
      return -1
    cred.cr_uid.int
  else:
    var cred: Ucred
    var len = SockLen(sizeof(cred))
    if getsockopt(fd, SOL_SOCKET, SoPeercred, addr cred, addr len) != 0:
      return -1
    cred.uid.int

proc listenUnix(path: string): SocketHandle =
  result = posix.socket(cint(AF_UNIX), SOCK_STREAM, 0)
  if result < 0: raiseOSError(osLastError())
  var sa: Sockaddr_un
  sa.sun_family = TSa_Family(AF_UNIX)
  if path.len >= sa.sun_path.len:
    raise newException(PfError, "socket path too long: " & path)
  copyMem(addr sa.sun_path[0], cstring(path), path.len + 1)
  removeFile(path)
  if bindSocket(result, cast[ptr SockAddr](addr sa),
               SockLen(sizeof(sa))) != 0:
    raiseOSError(osLastError())
  if listen(result, 128) != 0: raiseOSError(osLastError())
  # The listening socket must not travel into an exec'd child.
  discard fcntl(result, F_SETFD, FD_CLOEXEC)

proc connectUnix(path: string): SocketHandle =
  result = posix.socket(cint(AF_UNIX), SOCK_STREAM, 0)
  if result < 0: raiseOSError(osLastError())
  var sa: Sockaddr_un
  sa.sun_family = TSa_Family(AF_UNIX)
  if path.len >= sa.sun_path.len:
    raise newException(PfError, "socket path too long: " & path)
  copyMem(addr sa.sun_path[0], cstring(path), path.len + 1)
  if connect(result, cast[ptr SockAddr](addr sa),
             SockLen(sizeof(sa))) != 0:
    let err = osLastError()
    discard close(result)
    raise newException(PfError, "cannot reach the sandwallpf daemon at " &
      path & ": " & $err)

proc aligned(n: uint): uint = (n + sizeof(csize_t).uint - 1) and
  not (sizeof(csize_t).uint - 1)

proc cmsgEnd(msg: ptr Tmsghdr): uint =
  cast[uint](msg.msg_control) + msg.msg_controllen.uint

proc firstCmsg(msg: ptr Tmsghdr): ptr Cmsghdr =
  ## CMSG_FIRSTHDR, by hand: the C macros are not linkable.
  if msg.msg_controllen.uint < sizeof(Cmsghdr).uint: nil
  else: cast[ptr Cmsghdr](msg.msg_control)

proc nextCmsg(msg: ptr Tmsghdr; cmsg: ptr Cmsghdr): ptr Cmsghdr =
  ## CMSG_NXTHDR, by hand.
  let n = aligned(cast[uint](cmsg) + cmsg.cmsg_len.uint)
  if n + sizeof(Cmsghdr).uint > cmsgEnd(msg): nil
  else: cast[ptr Cmsghdr](n)

proc sendFds(fd: SocketHandle; fds: array[StdFds, cint]) =
  ## Hand `fds` to the peer ahead of the request line (SCM_RIGHTS).
  var byte: char = 'f'
  var iov = IOVec(iov_base: addr byte, iov_len: 1)
  var cbuf: array[64, char]
  var msg = Tmsghdr(msg_iov: addr iov, msg_iovlen: 1,
                    msg_control: addr cbuf[0], msg_controllen: SockLen(cbuf.len))
  let cmsg = firstCmsg(addr msg)
  cmsg.cmsg_level = SOL_SOCKET
  cmsg.cmsg_type = ScmRights
  cmsg.cmsg_len = SockLen(AncillaryHeaderSize + sizeof(cint) * StdFds)
  copyMem(cast[pointer](cast[uint](cmsg) + AncillaryHeaderSize.uint),
          unsafeAddr fds[0], sizeof(cint) * StdFds)
  msg.msg_controllen = cmsg.cmsg_len
  if sendmsg(fd, addr msg, 0) != 1:
    raiseOSError(osLastError())

proc recvFds(fd: SocketHandle): tuple[first: string; fds: seq[cint]] =
  ## The first bytes of the request and any descriptors riding along.
  var byte: char
  var iov = IOVec(iov_base: addr byte, iov_len: 1)
  var cbuf: array[128, char]
  var msg = Tmsghdr(msg_iov: addr iov, msg_iovlen: 1,
                    msg_control: addr cbuf[0], msg_controllen: SockLen(cbuf.len))
  let n = recvmsg(fd, addr msg, 0)
  if n <= 0: return
  result.first.add byte
  var cmsg = firstCmsg(addr msg)
  while not cmsg.isNil:
    if cmsg.cmsg_level == SOL_SOCKET and cmsg.cmsg_type == ScmRights:
      let count = int(cmsg.cmsg_len) - AncillaryHeaderSize
      let base = cast[uint](cmsg) + AncillaryHeaderSize.uint
      for i in 0 ..< (count div sizeof(cint)):
        let fdGot = cast[ptr cint](base + (i * sizeof(cint)).uint)[]
        result.fds.add fdGot
    cmsg = nextCmsg(addr msg, cmsg)

proc readLine(fd: SocketHandle; first: string): string =
  ## The request line, newline included; "" when the peer stops short
  ## of it. A client that never finishes is cut off by the socket's
  ## receive timeout.
  result = first
  var c: char
  while result.len < MaxRequestBytes:
    let n = recvSome(fd, addr c, 1)
    if n <= 0: return ""
    result.add c
    if c == '\n': return
  result = ""

# ---------------------------------------------------------------- serve

proc execChild(fds: seq[cint]; gid: int; uid: int; cwd: string;
               cmd: seq[string]) {.noreturn.} =
  for i in 0 ..< min(fds.len, StdFds):
    if fds[i] != i.cint: discard dup2(fds[i], cint(i))
  discard setsid()
  var failed = ""
  if chdir(cwd) != 0:
    failed = "sandwallpf: cannot chdir to " & cwd & ": " & $(osLastError()) & "\n"
  elif gid > 0 and setgid(Gid(gid)) != 0:
    failed = "sandwallpf: setgid(" & $gid & "): " & $(osLastError()) & "\n"
  elif setuid(Uid(uid)) != 0:
    failed = "sandwallpf: setuid(" & $uid & "): " & $(osLastError()) & "\n"
  if failed.len > 0:
    discard posix.write(2, cstring(failed), failed.len)
    exitnow(126)
  let prog = cmd[0]
  var argv = allocCStringArray(cmd)
  discard execvp(prog.cstring, argv)
  let msg = "sandwallpf: exec " & prog & ": " & $(osLastError()) & "\n"
  discard posix.write(2, cstring(msg), msg.len)
  exitnow(127)

proc doExec(d: ptr DaemonObj; fd: SocketHandle; uid: int; req: JsonNode;
            fds: seq[cint]) =
  defer:
    for f in fds: discard close(f)
  var cmd: seq[string]
  for c in req["cmd"]: cmd.add c.getStr
  let runId = req["runId"].getStr
  let cwd = req["cwd"].getStr
  let gid = execGid(d, runId)
  if fds.len != StdFds or cmd.len == 0 or cwd.len == 0 or gid < 0:
    sendLine(fd, %*{"ok": false, "error": "bad exec request"})
    return
  # Nothing past the fork allocates: the child only dup2s, chdirs,
  # drops and execs, with the strings as plain memory.
  let pid = fork()
  if pid == 0:
    execChild(fds, gid, uid, cwd, cmd)
  if pid < 0:
    sendLine(fd, %*{"ok": false, "error": "fork: " & $(osLastError())})
    return
  markExec(d, runId, pid.int)
  sendLine(fd, %*{"ok": true, "pid": pid})
  var status: cint = 0
  discard waitpid(pid, status, 0)
  markExec(d, runId, 0)
  var code = 1
  if WIFEXITED(status): code = int(WEXITSTATUS(status))
  elif WIFSIGNALED(status): code = 128 + int(WTERMSIG(status))
  sendLine(fd, %*{"ok": true, "exit": code})

proc serveConn(d: ptr DaemonObj; fd: SocketHandle; uid: int) {.gcsafe.} =
  defer: discard close(fd)
  if peerUid(fd) != uid:
    sendLine(fd, %*{"ok": false, "error": "not the account that ran setup"})
    return
  var timeout = Timeval(tv_sec: posix.Time(10), tv_usec: 0)
  discard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, addr timeout,
                     SockLen(sizeof(timeout)))
  let (first, fds) = recvFds(fd)
  if first.len == 0: return
  # An exec's first byte is the SCM_RIGHTS carrier, not request text.
  let line = readLine(fd, if fds.len > 0: "" else: first)
  if line.len == 0:
    sendLine(fd, %*{"ok": false, "error": "truncated request"})
    return
  var req: JsonNode
  try:
    req = parseJson(line)
  except CatchableError as e:
    sendLine(fd, %*{"ok": false, "error": "bad json: " & e.msg})
    return
  if req["op"].getStr == "exec":
    doExec(d, fd, uid, req, fds)
  else:
    sendLine(fd, handle(cast[Daemon](d), req))

proc serve*(sockPath: string; uid: int; d: Daemon) =
  ## Enable pf, put the fence in place, then serve requests forever.
  ## One thread per connection: an `exec` holds its thread until the
  ## child exits, and other runs go on meanwhile.
  ensurePf(d)
  createDir(splitFile(sockPath).dir)
  let lfd = listenUnix(sockPath)
  defer: discard close(lfd)
  setFilePermissions(sockPath, {fpUserRead, fpUserWrite})
  d.log("sandwallpf: serving " & sockPath & " for uid " & $uid)
  while true:
    let fd = accept(lfd, nil, nil)
    if fd < 0:
      if osLastError().int == EINTR: continue
      raiseOSError(osLastError())
    discard fcntl(fd, F_SETFD, FD_CLOEXEC)
    spawn serveConn(cast[ptr DaemonObj](d), fd, uid)

proc defaultPfCtl*(args: openArray[string]; input = ""): tuple[ok: bool;
    output: string] {.gcsafe, raises: [].} =
  try:
    let p = startProcess(PfctlPath, args = @args, options = {poUsePath})
    defer: p.close()
    if input.len > 0:
      p.inputStream.write(input)
      p.inputStream.close()
    let outp = p.outputStream.readAll()
    let errp = p.errorStream.readAll()
    result = (p.waitForExit() == 0, outp & errp)
  except CatchableError as e:
    result = (false, e.msg)

proc stdLog(msg: string) {.gcsafe, raises: [].} =
  try: writeLine(stderr, msg)
  except CatchableError: discard

proc systemGroup(gid: int): bool {.gcsafe, raises: [].} =
  getgrgid(Gid(gid)) != nil

proc newSystemDaemon*(): Daemon =
  newDaemon(defaultPfCtl, proc(): float = epochTime(), systemGroup, stdLog)

proc recordedUid*(): int =
  ## The account `sandwall setup` recorded, -1 when there is none.
  try: parseInt(readFile(PfUidFile).strip)
  except CatchableError: -1

proc daemonMain*(): int =
  let uid = recordedUid()
  if uid < 0:
    stderr.writeLine("sandwallpf: no uid on record at " & PfUidFile &
      "; run `sudo sandwall setup` first")
    return 1
  var d = newSystemDaemon()
  try:
    serve(PfSockPath, uid, d)
  except CatchableError as e:
    stderr.writeLine("sandwallpf: " & e.msg)
    return 1

# --------------------------------------------------------------- client

proc pfCall*(sockPath: string; req: JsonNode): JsonNode =
  ## One request, one reply. Raises PfError when the daemon cannot be
  ## reached or answers nonsense.
  let fd = connectUnix(sockPath)
  defer: discard close(fd)
  var timeout = Timeval(tv_sec: posix.Time(30), tv_usec: 0)
  discard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, addr timeout,
                     SockLen(sizeof(timeout)))
  sendLine(fd, req)
  var line = ""
  var c: char
  while line.len < MaxRequestBytes:
    if recvSome(fd, addr c, 1) <= 0: break
    if c == '\n': break
    line.add c
  if line.len == 0:
    raise newException(PfError, "sandwallpf closed the connection")
  try:
    result = parseJson(line)
  except CatchableError as e:
    raise newException(PfError, "sandwallpf: bad reply: " & e.msg)
  if not result["ok"].getBool:
    raise newException(PfError, "sandwallpf: " & result["error"].getStr)

proc readReply(fd: SocketHandle): JsonNode =
  ## One reply line; the request's newline ends the previous one.
  var line = ""
  var c: char
  while line.len < MaxRequestBytes:
    if recvSome(fd, addr c, 1) <= 0: break
    if c == '\n': break
    line.add c
  if line.len == 0:
    raise newException(PfError, "sandwallpf closed the connection")
  try:
    result = parseJson(line)
  except CatchableError as e:
    raise newException(PfError, "sandwallpf: bad reply: " & e.msg)

proc pingReq*(): JsonNode = %*{"op": "ping"}

proc pfPing*(sockPath = PfSockPath): bool =
  ## Whether the daemon is up and answering. Says nothing about pf.
  try:
    discard pfCall(sockPath, pingReq())
    true
  except PfError:
    false

proc pfBegin*(sockPath: string; loopPorts: openArray[uint16];
              entries: openArray[PermitEntry]): string =
  ## Put a run's fence up and return its run id.
  let rep = pfCall(sockPath, %*{"op": "begin",
    "loopPorts": loopPorts.mapIt(it.int), "snapshot": snapshotJson(entries)})
  result = rep["runId"].getStr

proc pfRefresh*(sockPath, runId: string; loopPorts: openArray[uint16];
                entries: openArray[PermitEntry]) =
  discard pfCall(sockPath, %*{"op": "refresh", "runId": runId,
    "loopPorts": loopPorts.mapIt(it.int), "snapshot": snapshotJson(entries)})

proc pfEnd*(sockPath, runId: string) =
  ## Take a run's fence down. Idempotent: the daemon may have swept it.
  try:
    discard pfCall(sockPath, %*{"op": "end", "runId": runId})
  except PfError:
    discard

proc pfExec*(sockPath, runId: string; cmd: openArray[string];
             cwd: string): int =
  ## Run `cmd` as this uid inside the fence of `runId` ("" = no marker,
  ## an open policy), in `cwd`, with this process's stdio. Blocks until
  ## it exits and returns its exit code. Raises PfError when the daemon
  ## refuses or vanishes; the child then never ran.
  let fd = connectUnix(sockPath)
  defer: discard close(fd)
  # No receive timeout: the exit reply comes when the child exits.
  sendFds(fd, [0.cint, 1.cint, 2.cint])
  sendLine(fd, %*{"op": "exec", "runId": runId, "cmd": @cmd, "cwd": cwd})
  let first = readReply(fd)
  if not first["ok"].getBool:
    raise newException(PfError, "sandwallpf: " & first["error"].getStr)
  let last = readReply(fd)
  if not last["ok"].getBool:
    raise newException(PfError, "sandwallpf: " & last["error"].getStr)
  last["exit"].getInt

# --------------------------------------------------------------- setup

proc plistText(daemon: string): string =
  "  <key>Label</key><string>" & PfLabel & "</string>\n" &
  "  <key>ProgramArguments</key>\n" &
  "  <array><string>" & daemon & "</string></array>\n" &
  "  <key>RunAtLoad</key><true/>\n" &
  "  <key>KeepAlive</key><true/>\n"

proc pfSetup*(uid: int; daemon = ""): string =
  ## The one-time elevated install: record `uid` and load the daemon.
  ## Returns the line to print. Raises OSError on any refusal.
  if geteuid() != 0:
    raise newException(OSError, "sandwall setup needs root: sudo sandwall setup")
  let daemonPath = if daemon.len > 0: daemon
                   else: getCurrentDir() / "sandwallpf"
  if not fileExists(daemonPath):
    raise newException(OSError, "sandwallpf binary not found at " &
      daemonPath)
  createDir(PfStateDir)
  writeFile(PfUidFile, $uid & "\n")
  setFilePermissions(PfStateDir, {fpUserRead, fpUserWrite, fpUserExec,
    fpGroupRead, fpGroupExec, fpOthersRead, fpOthersExec})
  setFilePermissions(PfUidFile, {fpUserRead, fpUserWrite})
  let text = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" &
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" &
    "<plist version=\"1.0\">\n<dict>\n" & plistText(daemonPath) & "</dict>\n</plist>\n"
  writeFile(PfPlistPath, text)
  let boot = execProcess("/bin/launchctl", args = ["bootout", "system/" & PfLabel],
                         options = {poStdErrToStdOut})
  discard boot
  let load = execProcess("/bin/launchctl", args = ["bootstrap", "system", PfPlistPath],
                         options = {poStdErrToStdOut})
  if not load.contains("uccess") and strip(load).len > 0:
    raise newException(OSError, "launchctl bootstrap: " & strip(load))
  "sandwall: setup complete; the sandwallpf daemon is loaded (uid " & $uid & ")"

proc pfUninstall*(): string =
  discard execProcess("/bin/launchctl", args = ["bootout", "system/" & PfLabel],
                      options = {poStdErrToStdOut})
  if fileExists(PfPlistPath): removeFile(PfPlistPath)
  if dirExists(PfStateDir): removeDir(PfStateDir)
  "sandwall: sandwallpf daemon unloaded; pf rules it loaded are gone"

proc pfFenceStatus*(): tuple[installed: bool; running: bool; hint: string] =
  ## Whether the daemon is installed and whether it answers.
  result.installed = fileExists(PfPlistPath)
  result.running = pfPing()
  if not result.installed:
    result.hint = "the sandwallpf daemon is not installed; run `sudo sandwall setup`"
  elif not result.running:
    result.hint = "the sandwallpf daemon is not answering: launchctl print system/" &
      PfLabel
