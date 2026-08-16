## process: run a sandboxed command.
##
## Posix: `forkNimbox`/`exec`/`wait` fork a child, apply the sandbox in the
## child, and exec the target. The parent stays unrestricted so it can run
## privileged commands and clean up. Landlock/Seatbelt confine the calling
## thread and children inherit the restriction, so this fork-then-restrict-in-
## child model works: the parent never calls `restrict`.
##
## Windows has no fork, and a token cannot narrow the current process,
## only a spawned one. `spawnSandboxedAndWait` runs the command as the
## dedicated `sandwall` user via CreateProcessWithLogonW (lpDesktop
## NULL; see rtoken.nim), inside a KILL_ON_JOB_CLOSE Job.
## `restrict` stamped the sandbox user's ALLOW grants on the writable
## roots beforehand; per-run DENY narrowing is rolled back in a defer.
## See rtoken.nim for why the dedicated user (and not a restricted
## token or an AppContainer) is the only shape that holds.
##
## `runSandboxed` is the portable entry that dispatches to the right path.

import std/os
import ./restrict

type
  ExitCode* = distinct int

proc `$`*(e: ExitCode): string = $(int(e))

when defined(windows):
  import std/[winlean, widestrs, strutils]
  import ./rtoken  # spawnSandboxed

  proc findExeInPath*(name: string): string =
    ## Resolve a bare command name against PATH/PATHEXT like cmd does:
    ## cwd first, then each PATH entry, trying the name as-is plus each
    ## PATHEXT extension. Returns the input unchanged when the name
    ## already carries a directory or resolves nowhere (CreateProcessW
    ## then fails with its own error, as execvp would).
    if name.len == 0: return name
    for c in name:
      if c in {'\\', '/', ':'}: return name
    var exts: seq[string] = @[""]
    let pathext = getEnv("PATHEXT")
    if pathext.len > 0:
      for e in pathext.split(';'):
        let t = e.strip()
        if t.len > 0: exts.add(t.toLowerAscii())
    template matches(dir: string): string =
      block:
        var hit = ""
        for e in exts:
          let cand = dir / (name & e)
          if fileExists(cand): hit = cand; break
        hit
    let inCwd = matches(getCurrentDir())
    if inCwd.len > 0: return inCwd
    for dir in getEnv("PATH").split(';'):
      let d = dir.strip()
      if d.len == 0: continue
      let hit = matches(d)
      if hit.len > 0: return hit
    name

  proc spawnSandboxedAndWait*(cmd: openArray[string]): ExitCode =
    ## Spawn `cmd` as the sandbox user, wait for it, and unwind the
    ## per-run state (stdout pipe, DENY narrowing) inside the library
    ## (rtoken.runAsSandboxUser owns it). Raises if the spawn
    ## fails. The WFP fence installed by `3code wall setup-windows`
    ## confines the sandbox user to loopback either way; the caller
    ## routes traffic through the wall proxy via env when the policy
    ## has host rules.
    ExitCode(rtoken.runAsSandboxUser(cmd))
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
  ## On windows: `restrict` stamps the sandbox user's ALLOW grants on
  ## the writable roots, then `spawnSandboxedAndWait` runs the command
  ## as that user. Windows cannot confine the current process, so the
  ## whole sandbox takes effect at spawn time in the child.
  block:
    when defined(windows):
      restrict(writable, read, denied)
      spawnSandboxedAndWait(cmd)
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
