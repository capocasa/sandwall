## process: run a sandboxed command.
##
## Posix: `forkNimbox`/`exec`/`wait` fork a child, apply the sandbox in the
## child, and exec the target. The parent stays unrestricted so it can run
## privileged commands and clean up. Landlock/Seatbelt confine the calling
## thread and children inherit the restriction, so this fork-then-restrict-in-
## child model works: the parent never calls `restrict`.
##
## Windows has no fork, and a token cannot narrow the current process, only a
## spawned one. `spawnSandboxed` does it in one call: `CreateProcessAsUserW`
## with the token prepared by `restrict`, then rolls back the ACLs in a defer.
##
## `runSandboxed` is the portable entry that dispatches to the right path.

import std/os
import ./restrict

type
  ExitCode* = distinct int

proc `$`*(e: ExitCode): string = $(int(e))

when defined(windows):
  import std/winlean
  import ./acl  # currentRestrictedToken, rollbackAcls, currentRestrictingSid

  proc spawnSandboxed*(cmd: openArray[string]): ExitCode =
    ## Spawn `cmd` under the prepared restricted token (see `acl.restrictImpl`),
    ## wait for it, and roll back the stamped ACLs in a `defer` so cleanup
    ## runs whether CreateProcess succeeds or the child errors. Raises if no
    ## token was prepared (`restrict` not called) or CreateProcess fails.
    if currentRestrictedToken == 0:
      raise newException(OSError, "sandwall: restrict() must be called first")

    # Rollback runs unconditionally, including on the raise paths below. This
    # is the one mutation-bearing operation in the Windows backend and must
    # never be skipped: stray deny ACEs on volume roots break other processes.
    defer: rollbackAcls(currentRestrictingSid)

    # CreateProcessW wants a single mutable UTF-16 command line. Build it by
    # quoting each arg with the Windows rules (std/os.quoteShellWindows).
    var cmdLine = ""
    for i, a in cmd:
      if i > 0: cmdLine.add(' ')
      cmdLine.add(quoteShellWindows(a))
    if cmdLine.len == 0:
      raise newException(ValueError, "sandwall.spawnSandboxed: empty command")
    let cmdLineW = newWideCString(cmdLine)

    var si = default(STARTUPINFO)
    si.cb = DWORD(sizeof(si))
    var pi = default(PROCESS_INFORMATION)

    if createProcessAsUserW(currentRestrictedToken, nil,
        cmdLineW, nil, nil, 0, 0, nil, nil, addr si, addr pi) == 0:
      raise newException(OSError,
        "sandwall: CreateProcessAsUserW failed: " & $getLastError())
    defer:
      discard closeHandle(pi.hProcess)
      discard closeHandle(pi.hThread)

    # INFINITE wait; the child is sandboxed and we own its lifetime.
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
  ## On windows: `restrict` (prepare token + stamp ACLs), then
  ## `spawnSandboxed` (CreateProcessAsUser with the token, then ACL rollback
  ## in a defer). Windows cannot confine the current process, so the whole
  ## sandbox takes effect at spawn time in the child.
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
