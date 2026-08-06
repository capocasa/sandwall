## process: run a sandboxed command.
##
## Posix: `forkNimbox`/`exec`/`wait` fork a child, apply the sandbox in the
## child, and exec the target. The parent stays unrestricted so it can run
## privileged commands and clean up. Landlock/Seatbelt confine the calling
## thread and children inherit the restriction, so this fork-then-restrict-in-
## child model works: the parent never calls `restrict`.
##
## Windows has no fork, and a token cannot narrow the current process, only a
## spawned one. `spawnSandboxed` does it in one call: `CreateProcessW` with
## the PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES attribute carrying the
## AppContainer SID prepared by `restrict`, then rolls back the ACLs in a
## defer.
##
## `runSandboxed` is the portable entry that dispatches to the right path.

import std/os
import ./restrict

type
  ExitCode* = distinct int

proc `$`*(e: ExitCode): string = $(int(e))

when defined(windows):
  import std/[winlean, widestrs]
  import ./acl  # currentAppContainerSid, rollbackAcls

  type
    # STARTUPINFOEXW: STARTUPINFO plus the attribute list pointer. winlean
    # has no binding, so define it here. Layout: plain concatenation.
    STARTUPINFOEX = object
      si: STARTUPINFO
      lpAttributeList: pointer

    # SECURITY_CAPABILITIES (winnt.h), 24 bytes on amd64. Empty capabilities
    # (nil/0) means maximum lockdown: no network, no fs beyond DACL grants.
    SECURITY_CAPABILITIES = object
      appContainerSid: pointer
      capabilities: pointer
      capabilityCount: DWORD
      reserved: DWORD

  const
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009'u
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000'i32

  proc setHandleInformation(hObject: Handle; dwMask, dwFlags: DWORD): WINBOOL
      {.stdcall, dynlib: "kernel32", importc: "SetHandleInformation".}

  proc initializeProcThreadAttributeList(list: pointer; count: DWORD;
      flags: DWORD; size: ptr uint): WINBOOL {.stdcall, dynlib: "kernel32",
      importc: "InitializeProcThreadAttributeList".}

  # GOTCHA: the Attribute parameter is a DWORD_PTR passed BY VALUE (Nim
  # `uint`, not `ptr DWORD`). By-reference fails with ERROR_NOT_SUPPORTED.
  proc updateProcThreadAttribute(list: pointer; flags: DWORD; attr: uint;
      value: pointer; size: uint; prev: pointer; retSize: pointer): WINBOOL
      {.stdcall, dynlib: "kernel32", importc: "UpdateProcThreadAttribute".}

  proc deleteProcThreadAttributeList(list: pointer) {.stdcall,
      dynlib: "kernel32", importc: "DeleteProcThreadAttributeList".}

  # winlean's createProcessW takes `var STARTUPINFO`; the extended form
  # needs STARTUPINFOEX, so declare a twin against it.
  proc createProcessExW(lpApplicationName, lpCommandLine: WideCString;
      lpProcessAttributes: ptr SECURITY_ATTRIBUTES;
      lpThreadAttributes: ptr SECURITY_ATTRIBUTES;
      bInheritHandles: WINBOOL; dwCreationFlags: DWORD;
      lpEnvironment, lpCurrentDirectory: WideCString;
      lpStartupInfo: ptr STARTUPINFOEX;
      lpProcessInformation: var PROCESS_INFORMATION): WINBOOL {.stdcall,
      dynlib: "kernel32", importc: "CreateProcessW", sideEffect.}

  proc spawnSandboxed*(cmd: openArray[string]): ExitCode =
    ## Spawn `cmd` in the prepared AppContainer (see `acl.restrictImpl`),
    ## wait for it, and roll back the stamped ACLs in a `defer` so cleanup
    ## runs whether CreateProcess succeeds or the child errors. Raises if no
    ## sandbox was prepared (`restrict` not called) or CreateProcess fails.
    if currentAppContainerSid == nil:
      raise newException(OSError, "sandwall: restrict() must be called first")

    # Rollback runs unconditionally, including on the raise paths below. This
    # is the one mutation-bearing operation in the Windows backend and must
    # never be skipped.
    defer: rollbackAcls(currentAppContainerSid)

    # CreateProcessW wants a single mutable UTF-16 command line. Build it by
    # quoting each arg with the Windows rules (std/os.quoteShellWindows).
    var cmdLine = ""
    for i, a in cmd:
      if i > 0: cmdLine.add(' ')
      cmdLine.add(quoteShellWindows(a))
    if cmdLine.len == 0:
      raise newException(ValueError, "sandwall.spawnSandboxed: empty command")
    let cmdLineW = newWideCString(cmdLine)

    # Attribute list carrying SECURITY_CAPABILITIES: the two-call sizing
    # pattern (first call fails but returns the size), then the update.
    var sc: SECURITY_CAPABILITIES
    sc.appContainerSid = currentAppContainerSid
    sc.capabilities = nil
    sc.capabilityCount = 0
    sc.reserved = 0

    var listSize: uint = 0
    discard initializeProcThreadAttributeList(nil, 1, 0, addr listSize)
    let attrList = alloc0(listSize.int)
    defer: dealloc(attrList)
    if initializeProcThreadAttributeList(attrList, 1, 0, addr listSize) == 0:
      raise newException(OSError,
        "sandwall: InitializeProcThreadAttributeList failed: " & $getLastError())
    defer: deleteProcThreadAttributeList(attrList)
    if updateProcThreadAttribute(attrList, 0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, addr sc,
        uint(sizeof(sc)), nil, nil) == 0:
      raise newException(OSError,
        "sandwall: UpdateProcThreadAttribute failed: " & $getLastError())

    # The AppContainer child cannot run a binary unless CreateProcess is
    # given explicit, valid std handles (STARTF_USESTDHANDLES) and
    # bInheritHandles=TRUE; with plain inherited std handles (bInheritHandles
    # = FALSE) spawning any exe inside the container fails with access denied
    # (verified by probe bisection). Redirect the child's stdout+stderr into
    # an inheritable anonymous pipe we pump back to our own stdout.
    var sa: SECURITY_ATTRIBUTES
    sa.nLength = DWORD(sizeof(sa))
    sa.lpSecurityDescriptor = nil
    sa.bInheritHandle = 1
    var pipeRead, pipeWrite: Handle
    if createPipe(pipeRead, pipeWrite, sa, 0) == 0:
      raise newException(OSError,
        "sandwall: CreatePipe failed: " & $getLastError())
    # The read end stays with the parent; do not let the child inherit it.
    discard setHandleInformation(pipeRead, 1, 0)  # HANDLE_FLAG_INHERIT, off
    defer:
      discard closeHandle(pipeRead)
      discard closeHandle(pipeWrite)

    var six = default(STARTUPINFOEX)
    six.si.cb = DWORD(sizeof(six))
    six.si.dwFlags = DWORD(STARTF_USESTDHANDLES)
    six.si.hStdInput = getStdHandle(STD_INPUT_HANDLE)
    six.si.hStdOutput = pipeWrite
    six.si.hStdError = pipeWrite
    six.lpAttributeList = attrList
    var pi = default(PROCESS_INFORMATION)

    # Explicit lpCurrentDirectory: the AppContainer virtualizes %TEMP%, and
    # inheriting a cwd the container cannot reach breaks cmd's redirects.
    let cwdW = newWideCString(getCurrentDir())
    if createProcessExW(nil, cmdLineW, nil, nil, 1,
        DWORD(EXTENDED_STARTUPINFO_PRESENT), nil, cwdW,
        addr six, pi) == 0:
      raise newException(OSError,
        "sandwall: CreateProcessW failed: " & $getLastError())
    # Parent must close its copy of the write end or reads never see EOF.
    discard closeHandle(pipeWrite)
    pipeWrite = 0
    defer:
      discard closeHandle(pi.hProcess)
      discard closeHandle(pi.hThread)

    # Pump the child's output to our stdout while it runs. ReadFile blocks
    # until data arrives or the pipe closes, so this also naturally waits.
    let outHandle = getStdHandle(STD_OUTPUT_HANDLE)
    var buf: array[4096, char]
    while true:
      var nread: int32 = 0
      let ok = readFile(pipeRead, addr buf[0], int32(buf.len), addr nread, nil)
      if ok == 0 or nread == 0: break
      discard writeFile(outHandle, addr buf[0], nread, nil, nil)

    # Ensure the child has fully exited (the pump ends at pipe close, which
    # is process exit, but wait to be certain before reading the exit code).
    let w = waitForSingleObject(pi.hProcess, INFINITE)
    if w == WAIT_FAILED:
      raise newException(OSError,
        "sandwall: WaitForSingleObject failed: " & $getLastError())
    var code: int32 = 0
    if getExitCodeProcess(pi.hProcess, code) == 0:
      raise newException(OSError,
        "sandwall: GetExitCodeProcess failed: " & $getLastError())
    result = ExitCode(int(code))
else:
  import std/[posix, strutils]

  proc forkNimbox*(): Pid =
    ## Fork a child that inherits nothing of the parent's sandbox state.
    ## In the child, call `restrict` then `exec`; the parent gets the pid to
    ## wait on. Raises on failure.
    result = posix.fork()
    if result < 0:
      raise newException(OSError, "sandwall: fork() failed: " & osLastError().`$`)

  proc exec*(cmd: openArray[string]) =
    ## Replace the current process image with `cmd` (first element is the
    ## program, the rest its args). Uses PATH lookup. Only returns on failure.
    if cmd.len == 0:
      raise newException(ValueError, "sandwall.exec: empty command")
    let prog0 = cmd[0]
    var argv = allocCStringArray(cmd)
    # execvp does not return on success
    discard execvp(prog0.cstring, argv)
    deallocCStringArray(argv)
    # reached only on error
    raise newException(OSError,
      "sandwall: exec(" & cmd.join(" ") & ") failed: " & osLastError().`$`)

  proc wait*(pid: Pid): ExitCode =
    ## Block until `pid` exits. Returns the process exit code (0-255 for normal
    ## exit, 128+signal for termination by signal).
    var status: cint = 0
    if posix.waitpid(pid, status, 0) < 0:
      raise newException(OSError,
        "sandwall: waitpid failed: " & osLastError().`$`)
    if WIFEXITED(status):
      result = ExitCode(WEXITSTATUS(status))
    elif WIFSIGNALED(status):
      result = ExitCode(128 + WTERMSIG(status))
    else:
      result = ExitCode(1)

template runSandboxed*(writable: openArray[string]; cmd: openArray[string];
                        read: openArray[string] = [];
                        denied: openArray[string] = []): ExitCode =
  ## One-shot helper. Restricts to `writable` (full access) plus `read`
  ## (read+execute only) and runs `cmd`, returning its exit code.
  ##
  ## On posix: fork, in the child `restrict` then `exec`, in the parent
  ## `wait`. The parent keeps running unrestricted.
  ##
  ## On windows: `restrict` (prepare AppContainer SID + stamp ACLs), then
  ## `spawnSandboxed` (CreateProcessW with the security-capabilities
  ## attribute, then ACL rollback in a defer). Windows cannot confine the
  ## current process, so the whole sandbox takes effect at spawn time in
  ## the child.
  block:
    when defined(windows):
      restrict(writable, read, denied)
      spawnSandboxed(cmd)
    else:
      let pid = forkNimbox()
      if pid == 0:
        try:
          restrict(writable, read, denied)
          exec(cmd)
        except CatchableError as e:
          stderr.writeLine("sandwall child: " & e.msg)
        exitnow(127)   # only reached on setup failure
      wait(pid)
