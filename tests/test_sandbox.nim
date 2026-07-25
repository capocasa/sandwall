## Tests for nimbox.
##
## Two layers:
##   1. CLI tests: invoke the `nimbox restrict ... -- CMD` binary, check the
##      command is confined.
##   2. Library tests: each scenario forks a child (since a Landlock domain
##      is permanent for the thread that applies it), so isolation is built in.
##
## Run via `nimble test`.

import std/[os, osproc, unittest, strutils]

# --------------------------------------------------------------------------
# helpers

proc nimboxExe(): string =
  ## The freshly built nimbox binary at the project root. The `nimble test`
  ## task builds it there before running the tests.
  let testDir = parentDir(currentSourcePath())
  result = parentDir(testDir) / "nimbox"
  when defined(windows): result.add(".exe")

proc tempDir(name: string): string =
  result = getTempDir() / ("nimbox-test-" & name)
  removeDir(result)
  createDir(result)

proc expectFile(path: string): bool = fileExists(path)

proc systemReadDirs(): seq[string] =
  ## Read-only system dirs used by library tests that call restrict()
  ## directly. The CLI path and the backends auto-add OS-specific baselines,
  ## but library callers pass their own lists. Kept minimal here since the
  ## backends also auto-add /usr, /bin, /dev/*, etc.
  when defined(windows): @[]
  elif defined(macosx): @[]
  else: @[]

proc redirectCmd(path: string): string =
  ## A shell command that writes "ok" to `path`, using the OS's native shell.
  ## posix uses `sh -c`; Windows uses `cmd /c` (no `sh` on a stock runner).
  when defined(windows):
    "cmd /c \"echo ok > " & path & "\""
  else:
    "sh -c 'echo ok > " & path & "'"

# --------------------------------------------------------------------------
# CLI tests (shell out to the binary)

suite "nimbox CLI (sandboxed exec)":
  test "write allowed, write denied":
    let a = tempDir("cli-a")
    let d = tempDir("cli-d")
    # the allowed write runs in one invocation, the denied in another,
    # because a failing redirect makes the shell exit nonzero.
    discard execCmd(nimboxExe().quoteShell & " restrict " & a.quoteShell &
                    " -- " & redirectCmd(a / "x.txt"))
    let rcDenied = execCmd(nimboxExe().quoteShell & " restrict " &
                           a.quoteShell &
                           " -- " & redirectCmd(d / "y.txt"))
    check: expectFile(a / "x.txt")
    check: rcDenied != 0
    check: not expectFile(d / "y.txt")

  # posix-only: targets /usr/bin, which has no Windows analogue.
  when not defined(windows):
    test "cannot modify system dir":
      let a = tempDir("sys-a")
      let target = "/usr/bin/nimbox_should_not_exist_" & $getCurrentProcessId()
      let rc = execCmd(nimboxExe().quoteShell & " restrict " & a.quoteShell &
                       " -- touch " & target)
      check: rc != 0
      check: not fileExists(target)

  test "--ro path is readable but not writable":
    let rw = tempDir("ro-rw")
    let ro = tempDir("ro-ro")
    writeFile(ro / "secret.txt", "topsecret")
    # read from the read-only path succeeds
    let rcRead = execCmd(nimboxExe().quoteShell & " restrict " & rw.quoteShell &
                         " --ro " & ro.quoteShell & " -- cat " &
                         (ro / "secret.txt").quoteShell)
    check: rcRead == 0
    # write to the read-only path fails
    let rcWrite = execCmd(nimboxExe().quoteShell & " restrict " & rw.quoteShell &
                          " --ro " & ro.quoteShell & " -- " &
                          redirectCmd(ro / "new.txt"))
    check: rcWrite != 0
    check: not fileExists(ro / "new.txt")

  test "--ro without writable paths errors":
    let ro = tempDir("ro-only")
    let rc = execCmd(nimboxExe().quoteShell & " restrict --ro " & ro.quoteShell &
                     " -- true")
    check: rc == 2

  test "no command given errors":
    let rc = execCmd(nimboxExe().quoteShell & " restrict /tmp")
    check: rc == 2

# --------------------------------------------------------------------------
# library tests (fork a child per scenario)

when defined(linux) or defined(macosx):
  import nimbox
  import std/posix

  proc runScenario(name: string; body: proc(): bool): bool =
    ## Fork a child to run `body` (which applies Landlock and tests an
    ## expectation), wait for it, return whether the child exited 0.
    ##
    ## Caveat: the child runs Nim code in a forked copy of this multithreaded
    ## test process. Strictly, only async-signal-safe calls are valid between
    ## fork and exec in a multithreaded program. These tests get away with it
    ## because the child does little before `_exit`; this is a test-only
    ## convenience, not the pattern to copy for real sandboxing. For real
    ## commands use `forkNimbox` + `exec` (which replaces the image) or the
    ## `nimbox restrict ... -- CMD` CLI.
    let pid = forkNimbox()
    if pid == 0:
      var ok = false
      try: ok = body()
      except CatchableError: ok = false
      exitnow(if ok: 0 else: 1)
    result = int(wait(pid)) == 0

  suite "nimbox library (fork + restrict + exec)":
    test "restrict blocks writes outside allowed path":
      let a = tempDir("lib-a")
      let d = tempDir("lib-d")
      let ok = runScenario("rw") do () -> bool:
        restrict([a], read = systemReadDirs())
        writeFile(a / "ok.txt", "ok")
        if not fileExists(a / "ok.txt"): return false
        var raised = false
        try: writeFile(d / "bad.txt", "bad")
        except CatchableError: raised = true
        raised and not fileExists(d / "bad.txt")
      check: ok

    test "child of restricted process inherits the domain":
      let a = tempDir("inh-a")
      let d = tempDir("inh-d")
      let ok = runScenario("inh") do () -> bool:
        restrict([a], read = systemReadDirs())
        # spawn a child (sh) that tries to write outside; must be blocked
        let rc = execShellCmd("echo bad > " & d / "child.txt")
        # sh returns nonzero when redirect fails
        not fileExists(d / "child.txt")
      check: ok

    test "successive restrict calls only tighten":
      let a = tempDir("tight-a")
      let b = tempDir("tight-b")
      let ok = runScenario("tight") do () -> bool:
        restrict([a, b], read = systemReadDirs())
        writeFile(a / "a1.txt", "a")
        writeFile(b / "b1.txt", "b")
        restrict([a], read = systemReadDirs())
        writeFile(a / "a2.txt", "a2")
        # b is now denied by the second domain
        var raised = false
        try: writeFile(b / "b2.txt", "b2")
        except CatchableError: raised = true
        raised and fileExists(a / "a2.txt")
      check: ok
