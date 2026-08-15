## stdio: named-pipe stdout for CPLW children (Windows).
##
## CreateProcessWithLogonW runs the child in a new logon session, and
## handle inheritance does not cross that boundary; the documented
## alternative (CreateProcessAsUserW on a LogonUserW token) needs
## privileges the non-elevated caller does not hold (error 1314). The
## bridge: the sandbox parent creates one named pipe with an everyone
## DACL, passes its name via the inherited environment
## (NIMBOX_OUT_PIPE), and prepends a `stdio-relay` hop to the command
## line. The relay (running INSIDE the sandbox user's logon session)
## opens the pipe by name, installs it as its own stdout+stderr
## (2>&1), and spawns the real command with plain handle inheritance -
## which does work, because relay and command share the logon session.
## The child's stdin stays closed: 3code's bash wrapper feeds stdin
## from a file (`< stdinPath`), so nothing needs to flow in.
##
## The parent pumps pipe -> its own stdout on a background thread that
## ends at EOF (the relay closes its end when the command exits).

when defined(windows):
  import std/[os, strutils, syncio]
  import std/winlean except Socket

  const pipeBuf = 64 * 1024

  type
    RelayPipe* = object
      ## The parent's server end of the child's stdout pipe.
      handle*: Handle
      childName*: string   ## \\.\pipe\... path the relay connects to

  proc createNamedPipeW(lpName: WideCString; dwOpenMode,
      dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize,
      nDefaultTimeOut: DWORD;
      lpSecurityAttributes: pointer): Handle {.stdcall,
      dynlib: "kernel32", importc: "CreateNamedPipeW".}
  proc connectNamedPipe(hNamedPipe: Handle;
      lpOverlapped: pointer): WINBOOL {.stdcall, dynlib: "kernel32",
      importc: "ConnectNamedPipe".}
  proc createFileW(lpFileName: WideCString; dwDesiredAccess,
      dwShareMode: DWORD; lpSecurityAttributes: pointer;
      dwCreationDisposition, dwFlagsAndAttributes: DWORD;
      hTemplateFile: Handle): Handle {.stdcall, dynlib: "kernel32",
      importc: "CreateFileW".}
  proc convertStringSecurityDescriptorToSecurityDescriptorW(
      stringSecurityDescriptor: WideCString; stringSDRevision: DWORD;
      securityDescriptor: ptr pointer;
      securityDescriptorSize: ptr DWORD): WINBOOL {.stdcall,
      dynlib: "advapi32",
      importc: "ConvertStringSecurityDescriptorToSecurityDescriptorW".}

  type
    SecurityAttrs = object
      nLength: DWORD
      lpSecurityDescriptor: pointer
      bInheritHandle: WINBOOL

  var
    sdCache: pointer = nil
    saCache: SecurityAttrs

  proc everyoneSa(): ptr SecurityAttrs =
    ## SECURITY_ATTRIBUTES whose DACL grants Everyone+SYSTEM full
    ## access. The child opens the pipe as a different local user, so
    ## the default owner DACL would deny it. Built once per process.
    if sdCache == nil:
      var size: DWORD = 0
      if convertStringSecurityDescriptorToSecurityDescriptorW(
          newWideCString("D:(A;;GA;;;WD)(A;;GA;;;SY)"), 1,
          addr sdCache, addr size) == 0:
        raise newException(OSError,
          "sandwall stdio: SDDL parse failed (error " & $getLastError() & ")")
      saCache = SecurityAttrs(nLength: DWORD(sizeof(SecurityAttrs)),
        lpSecurityDescriptor: sdCache, bInheritHandle: 0)
    addr saCache

  proc createRelayPipe*(tag: string): RelayPipe =
    ## Create `\\.\pipe\3code-sw-<tag>` for one sandboxed run. The
    ## caller spawns the child with NIMBOX_OUT_PIPE set to
    ## `childName`, then pumps via pumpRelay after the spawn.
    const
      pipeAccessDuplex = 0x00000003
      pipeTypeByte = 0x00000000
      pipeUnlimitedInstances = 255'i32
    let name = r"\\.\pipe\3code-sw-" & tag
    let h = createNamedPipeW(newWideCString(name),
      DWORD(pipeAccessDuplex), DWORD(pipeTypeByte),
      DWORD(pipeUnlimitedInstances), DWORD(pipeBuf), DWORD(pipeBuf),
      30000'i32, everyoneSa())
    if h == INVALID_HANDLE_VALUE:
      raise newException(OSError,
        "sandwall stdio: CreateNamedPipeW failed (error " &
          $getLastError() & ")")
    RelayPipe(handle: h, childName: name)

  proc writeAll(h: Handle; buf: pointer; count: int32) =
    var done: int32 = 0
    while done < count:
      var n: int32 = 0
      if writeFile(h, cast[pointer](cast[uint](buf) + uint(done)),
          count - done, addr n, nil) == 0:
        return
      inc(done, n)

  proc pumpThread(p: ptr RelayPipe) {.thread.} =
    ## Connect the server end, then relay every byte into our stdout
    ## until the relay child closes its end (EOF). Detached; dies at
    ## EOF or when the caller closes the pipe (which reads as EOF).
    let connected = connectNamedPipe(p.handle, nil)
    if connected == 0 and getLastError().int32 != 535:   # PIPE_CONNECTED
      return
    let dst = getStdHandle(STD_OUTPUT_HANDLE)
    var buf = newString(pipeBuf)
    while true:
      var n: int32 = 0
      let ok = readFile(p.handle, addr buf[0], int32(pipeBuf), addr n, nil)
      if ok == 0 or n <= 0:
        break
      writeAll(dst, addr buf[0], n)

  proc pumpRelay*(p: var RelayPipe) =
    ## Start the detached pump thread for `p`.
    let pp = cast[ptr RelayPipe](allocShared0(sizeof(RelayPipe)))
    pp[] = p
    var t: Thread[ptr RelayPipe]
    createThread(t, pumpThread, pp)
    # The thread object is heap-stashed by createThread's copy when the
    # system thread registry is off; leaking the handle is fine - the
    # thread ends at pipe EOF (closeRelay) and the process exit reaps.
    when declared(nimthread_dont_use): discard
    else: discard

  proc closeRelay*(p: var RelayPipe) =
    ## Close the server end; the pump thread sees EOF and exits.
    if p.handle != 0:
      discard closeHandle(p.handle)
      p.handle = 0

  proc waitNamedPipeW(lpNamedPipeName: WideCString;
      nTimeOut: DWORD): WINBOOL {.stdcall, dynlib: "kernel32",
      importc: "WaitNamedPipeW".}
  proc flushFileBuffers(h: Handle): WINBOOL {.stdcall,
      dynlib: "kernel32", importc: "FlushFileBuffers".}

  proc connectChildPipe(name: string): Handle =
    ## The relay side: wait for the pipe to appear, open the client
    ## end (write side), return the handle.
    let wname = newWideCString(name)
    var waited = 0
    while waitNamedPipeW(wname, 1000'i32) == 0:
      # The server exists (the parent created it before spawning us),
      # but between instances a race can return not-found; retry a
      # few times before giving up.
      inc waited
      if waited > 10: return 0
    const genericWrite = 0x40000000'i32
    const openExisting = 3'i32
    createFileW(wname, DWORD(genericWrite), 0'i32, nil,
      DWORD(openExisting), 0'i32, 0)

  proc relayMain*(cmd: openArray[string]): int =
    ## The child-side hop: open NIMBOX_OUT_PIPE as our stdout+stderr
    ## (handles the sandboxed command inherits), spawn `cmd` with
    ## plain CreateProcessW, wait, exit with its code. Runs as the
    ## sandbox user inside the CPLW logon session.
    let pipeName = getEnv("NIMBOX_OUT_PIPE")
    let h = if pipeName.len > 0: connectChildPipe(pipeName) else: 0
    var si: STARTUPINFO
    zeroMem(addr si, sizeof(si))
    si.cb = int32(sizeof(si))
    if h != 0 and h != INVALID_HANDLE_VALUE:
      si.dwFlags = STARTF_USESTDHANDLES
      si.hStdInput = 0
      si.hStdOutput = h
      si.hStdError = h
    var pi: PROCESS_INFORMATION
    zeroMem(addr pi, sizeof(pi))
    var quoted: seq[string]
    for a in cmd:
      if a.find(Whitespace) >= 0 and not a.startsWith('"'):
        quoted.add('"' & a & '"')
      else:
        quoted.add(a)
    # inherit the pipe handle into the real child
    var sa = SECURITY_ATTRIBUTES(nLength: DWORD(sizeof(SECURITY_ATTRIBUTES)),
      lpSecurityDescriptor: nil, bInheritHandle: 1)
    let cmdw: WideCString = newWideCString(quoted.join(" "))
    let nilw: WideCString = nil
    if createProcessW(nilw, cmdw, addr sa, addr sa, 1, 0, nilw, nilw,
        si, pi) == 0:
      if h != 0: discard closeHandle(h)
      return 127
    discard closeHandle(pi.hThread)
    var code: int32 = 0
    discard waitForSingleObject(pi.hProcess, INFINITE)
    discard getExitCodeProcess(pi.hProcess, code)
    discard closeHandle(pi.hProcess)
    if h != 0:
      discard flushFileBuffers(h)
      discard closeHandle(h)
    int(code)
