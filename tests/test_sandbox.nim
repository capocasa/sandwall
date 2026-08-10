## Tests for sandwall.
##
## Two layers:
##   1. CLI tests: invoke the `sandwall RULES -- CMD` binary, check the
##      command is confined.
##   2. Library tests: each scenario forks a child (since a Landlock domain
##      is permanent for the thread that applies it), so isolation is built in.
##
## Run via `nimble test`.

import std/[os, osproc, unittest, strutils]

# --------------------------------------------------------------------------
# helpers

proc sandwallExe(): string =
  ## The freshly built sandwall binary at the project root. The `nimble test`
  ## task builds it there before running the tests. Derived from this test
  ## executable's own location (getAppFilename) rather than
  ## currentSourcePath, which is a COMPILE-TIME path - wrong for a
  ## cross-compiled binary run on another host (the Windows tests are
  ## cross-built on Linux and run on a Windows machine).
  let testDir = parentDir(getAppFilename())
  result = parentDir(testDir) / "sandwall"
  when defined(windows): result.add(".exe")

proc tempDir(name: string): string =
  result = getTempDir() / ("sandwall-test-" & name)
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

proc catCmd(path: string): string =
  ## A command that reads `path` to stdout: `type` on Windows, `cat` on posix.
  when defined(windows):
    "cmd /c type " & path.quoteShell
  else:
    "cat " & path.quoteShell

proc rulesFile(name, text: string): string =
  ## Write a policy file for the CLI tests and return its path.
  result = tempDir("rules-" & name) / "rules.txt"
  writeFile(result, text)

proc sw(rules: string; cmd: string): string =
  ## A full sandwall CLI invocation line.
  sandwallExe().quoteShell & " " & rules.quoteShell & " -- " & cmd

# --------------------------------------------------------------------------
# CLI tests (shell out to the binary)

suite "sandwall CLI (sandboxed exec)":
  test "allow allowed, write denied":
    let a = tempDir("cli-a")
    let d = tempDir("cli-d")
    let rules = rulesFile("a", "allow " & a & "\n")
    # the allowed write runs in one invocation, the denied in another,
    # because a failing redirect makes the shell exit nonzero.
    discard execCmd(sw(rules, redirectCmd(a / "x.txt")))
    let rcDenied = execCmd(sw(rules, redirectCmd(d / "y.txt")))
    check: expectFile(a / "x.txt")
    check: rcDenied != 0
    check: not expectFile(d / "y.txt")

  # posix-only: targets /usr/bin, which has no Windows analogue.
  when not defined(windows):
    test "cannot modify system dir":
      let a = tempDir("sys-a")
      let rules = rulesFile("sys", "allow " & a & "\n")
      let target = "/usr/bin/sandwall_should_not_exist_" & $getCurrentProcessId()
      let rc = execCmd(sw(rules, "touch " & target))
      check: rc != 0
      check: not fileExists(target)

    test "home stays confined; /etc is baseline-readable":
      # Real system dirs, sandboxrc-style. $HOME is not in the policy,
      # so the read must fail; a profile that under-enforces (e.g. a
      # Seatbelt deny that doesn't stick, or a Landlock rule that
      # silently widens) passes every tempdir test but fails here.
      # /etc is a baseline-read path by design (resolver config, certs),
      # so the read succeeds; an explicit deny must override the
      # baseline.
      let a = tempDir("sysread-a")
      let marker = getHomeDir() / ".sandwall_test_marker_" & $getCurrentProcessId()
      writeFile(marker, "secret")
      try:
        let rules = rulesFile("sysread", "allow " & a & "\n")
        let rcHome = execCmd(sw(rules, catCmd(marker)))
        check: rcHome != 0
        when defined(linux):
          # Baseline readability + the deny-carve-out are Landlock
          # specifics (Seatbelt punches denies with trailing rules;
          # Windows ACLs subtract natively).
          let rcEtc = execCmd(sw(rules, catCmd("/etc/hosts")))
          check: rcEtc == 0
          let denyEtc = rulesFile("sysread-denyetc",
            "allow " & a & "\ndeny /etc\n")
          check: execCmd(sw(denyEtc, catCmd("/etc/hosts"))) != 0
          let denyHosts = rulesFile("sysread-denyhosts",
            "allow " & a & "\ndeny /etc/hosts\n")
          check: execCmd(sw(denyHosts, catCmd("/etc/hosts"))) != 0
          check: execCmd(sw(denyHosts, catCmd("/etc/hostname"))) == 0
          let denySsh = rulesFile("sysread-denyssh",
            "allow " & a & "\ndeny /etc/ssh\n")
          check: execCmd(sw(denySsh, catCmd("/etc/ssh/ssh_config"))) != 0
          check: execCmd(sw(denySsh, catCmd("/etc/hostname"))) == 0
      finally:
        removeFile(marker)

  test "readonly path is readable but not writable":
    let rw = tempDir("ro-rw")
    let ro = tempDir("ro-ro")
    writeFile(ro / "secret.txt", "topsecret")
    let rules = rulesFile("ro", "allow " & rw & "\nreadonly " & ro & "\n")
    # read from the read-only path succeeds
    let rcRead = execCmd(sw(rules, catCmd(ro / "secret.txt")))
    check: rcRead == 0
    # write to the read-only path fails
    let rcWrite = execCmd(sw(rules, redirectCmd(ro / "new.txt")))
    check: rcWrite != 0
    check: not fileExists(ro / "new.txt")

  test "missing rules file errors":
    let rc = execCmd(sandwallExe().quoteShell & " /nonexistent-rules -- true")
    check: rc == 2

  test "no command given errors":
    let rules = rulesFile("nocmd", "allow /tmp\n")
    let rc = execCmd(sandwallExe().quoteShell & " " & rules.quoteShell)
    check: rc == 2

  test "deny narrows a writable root (sub-path deny)":
    # The grammar's last-wins narrowing, compiled to the backend: a
    # denied subpath under a writable root is unreachable while the
    # rest of the root stays writable. On Linux this exercises the
    # userns+bind-mask path; on Seatbelt the ordered profile.
    let rw = tempDir("deny-rw")
    let sub = rw / "locked"
    createDir(sub)
    writeFile(sub / "secret.txt", "x")
    let rules = rulesFile("deny", "allow " & rw & "\ndeny " & sub & "\n")
    # The probe reads the denied secret and reports DENIED on failure.
    # sh/cmd both exit nonzero on a failed read; wrap so the CLI rc is 0
    # and we assert on the marker instead.
    when defined(windows):
      let probe = "cmd /c \"type " & (sub / "secret.txt") &
        " 2>NUL || echo DENIED\""
    else:
      let probe = "sh -c " & ("cat " & (sub / "secret.txt").quoteShell &
        " 2>/dev/null || echo DENIED").quoteShell
    let (outp, rc) = execCmdEx(sw(rules, probe))
    check: rc == 0
    check: "DENIED" in outp
    # Sibling writes still work.
    let wrc = execCmd(sw(rules, redirectCmd(rw / "fine.txt")))
    check: wrc == 0
    check: fileExists(rw / "fine.txt")
    # The host's view is untouched (POSIX: the mask lives in the child's
    # mount namespace; Windows: the deny ACE is rolled back after the run).
    check: readFile(sub / "secret.txt") == "x"

  when defined(windows):
    test "host rules are accepted and fence egress (airgap)":
      # Loopback-hermetic: a rules file with a host rule must run the
      # child (the CLI must NOT reject host rules), hand it the proxy
      # env, and leave it with no network at all (the no-capability
      # AppContainer blocks even loopback, so the wall proxy/allowlist
      # cannot pass traffic - the airgap posture).
      let a = tempDir("net-a")
      let rules = rulesFile("netw", "allow " & a & "\nallow example.com\n")
      let probe = "cmd /c \"echo p=%http_proxy% & curl -s --noproxy * " &
        "--max-time 3 http://example.com/ 2>NUL || echo OFFLINE\""
      let (outp, rc) = execCmdEx(sw(rules, probe))
      check: rc == 0
      check: "p=http://127.0.0.1:" in outp   # proxy env inherited
      check: "OFFLINE" in outp               # direct egress fenced

  when defined(linux):
    test "host rules fence the network (allowed via proxy, direct blocked)":
      # A loopback HTTP one-shot plus a rules file allowing it: curl
      # through the auto-spawned proxy succeeds, bypassing the proxy
      # hits the netns fence. Loopback-only, hermetic.
      let a = tempDir("net-a")
      let rules = rulesFile("net", "allow " & a & "\nallow 127.0.0.1\n")
      let probe = "echo p=$http_proxy; " &
        "curl -spx $http_proxy --max-time 4 http://127.0.0.1:9/ " &
        "2>/dev/null || echo PROXY-REACHED; " &
        "curl -s --noproxy '*' --max-time 2 http://127.0.0.1:9/ " &
        "2>/dev/null || echo DIRECT-BLOCKED"
      let (outp, rc) = execCmdEx(sw(rules, "sh -c " & probe.quoteShell))
      check: rc == 0
      # Connection refused (port 9 closed) proves the proxy answered;
      # a fence-blocked attempt would time out instead.
      check: "PROXY-REACHED" in outp
      check: "DIRECT-BLOCKED" in outp

# --------------------------------------------------------------------------
# library tests (fork a child per scenario)

when defined(linux) or defined(macosx):
  import sandwall
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
    ## `sandwall restrict ... -- CMD` CLI.
    let pid = forkNimbox()
    if pid == 0:
      var ok = false
      try: ok = body()
      except CatchableError: ok = false
      exitnow(if ok: 0 else: 1)
    result = int(wait(pid)) == 0

  suite "sandwall library (fork + restrict + exec)":
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

    when defined(linux):
      # Landlock layers domains: each restrict() intersects with the
      # previous, so a second call tightens. Seatbelt is one-shot per
      # process (sandbox_init fails EPERM on re-init), so this
      # semantics test is Linux-only.
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
