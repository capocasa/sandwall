## sandwall - a process sandbox backed by OS-native primitives.
##
## Linux uses Landlock plus a netns egress fence; macOS uses Seatbelt
## (sandbox_init_with_parameters) for both. The user-facing API is
## identical on both.
##
## As a library:
##   import sandwall
##   restrict(rules)          # parsed policy: fs rules, then net wall
##
## As a binary:
##   sandwall RULES [--] CMD [ARGS ...]
##   # confines itself per RULES (a policy file, - = stdin), then exec()s CMD
##
## See the `restrict` and `rules` modules. Low-level pieces: `landlock`,
## `seatbelt`, `acl` (filesystem backends), `wall/` (the network half).

import ./sandwall/restrict
export restrict

import ./sandwall/process
export process

import ./sandwall/rules
export rules

import ./sandwall/wall
export wall

# ----------------------------------------------------------------------- CLI

when isMainModule:
  import std/[os, syncio, strutils]
  when defined(posix):
    import std/posix except Time
  when defined(windows):
    import ./sandwall/wall/proxy
    import ./sandwall/wall/stdio
    import ./sandwall/wall/permit

  const usage = """
sandwall - a process sandbox backed by OS-native primitives

Usage:
  sandwall RULES [--] CMD [ARGS ...]
  sandwall connect HOST PORT

  RULES is a policy file; `-` reads it from stdin. The sandbox applies
  the file's path rules to the filesystem (allow = read+write, readonly
  = read+execute, deny = nothing; anything unmentioned is denied) and
  its host rules to the network, then exec()s CMD. CMD and its children
  are confined.

  With no host rules the network is left alone. With at least one host
  rule, egress is fenced to loopback and a per-run proxy enforces the
  hostname allowlist (edits to RULES take effect on the next
  connection). System dirs stay read-only so CMD's binaries and libs
  stay runnable.

  On Linux with nft available the run first tries the raw path: CMD
  gets no proxy env vars, its DNS resolves allowed names to fake-IPs
  and plain ssh/scp/telnet work. If the raw fence cannot go up the
  command is re-run with proxy env vars (the env path) instead.

  On Windows the run also tries the raw path first when every allow
  rule names an exact host (a wildcard goes to the proxy) and
  `sandwall setup --stamp-as ACCOUNT` granted the spawning account the
  per-run kernel permits; a refused stamp falls back to the env path
  with the reason printed. `sandwall wfp-stamp-probe`, run unelevated
  as that account, tells whether it can stamp.

  sandwall connect HOST PORT
      SOCKS5 stdio adapter for ssh ProxyCommand-style tools: pumps
      stdio through the wall proxy at 127.0.0.1:$WALL_PROXY_PORT
      (default 1080) to HOST:PORT. Blocks. Not needed for tools that
      honor http_proxy/ALL_PROXY, which is most of them.

Examples:
  sandwall rules.txt -- make test
  sandwall rules.txt curl https://api.example.com
  cat rules.txt | sandwall - -- ls -la

The restriction is monotonic: permanent for this process and all
descendants. There is no "unrestrict".

Note: the `setup` command exists only on Windows builds (the Windows
fence needs a one-time elevated install); on this build networking and
filesystem policy are enforced with no setup step.
  """

  proc dieUsage(msg: string): int =
    stderr.writeLine(usage)
    stderr.writeLine("\nError: " & msg)
    2

  proc connectMain(args: seq[string]): int =
    when defined(posix):
      if args.len != 2:
        return dieUsage("connect needs HOST PORT")
      let port = try: uint16(parseInt(args[1]))
                 except ValueError: return dieUsage("bad port")
      let proxyPort = try: uint16(parseInt(getEnv("WALL_PROXY_PORT", "1080")))
                      except ValueError: 1080'u16
      socksConnect(proxyPort, args[0], port)
    else:
      stderr.writeLine("sandwall: connect is POSIX-only"); 2

  when defined(linux):
    import ./sandwall/wall/netns

    proc runRaw(rules: seq[Rule]; projectDir, policyPath: string;
                cmd: seq[string]): int =
      ## The first attempt of a run when nft is around: fork, and let
      ## the child fence itself in raw mode and exec. Returns the
      ## child's exit code, or -1 when the child refused raw mode (exit
      ## 75 AND the marker over the pipe only the pre-exec fence code
      ## could write), in which case the caller runs env mode in-process.
      ## The marker on stderr alone is not enough: a command may exit
      ## 75 on its own, and running it twice is not an option.
      var marker: array[2, cint]
      if posix.pipe(marker) != 0: raiseOSError(osLastError())
      let pid = posix.fork()
      if pid == 0:
        discard posix.close(marker[0])
        discard fcntl(marker[1], F_SETFD, FD_CLOEXEC)
        discard setsid()
        try:
          restrict(rules, projectDir, policyPath, raw = true,
                   fallbackFd = marker[1])
          exec(cmd)
        except CatchableError as e:
          stderr.writeLine("sandwall: " & e.msg)
        exitnow(127)
      if pid < 0:
        discard posix.close(marker[0])
        discard posix.close(marker[1])
        raiseOSError(osLastError())
      discard posix.close(marker[1])
      var status: cint
      discard posix.waitpid(pid, status, 0)
      # The proxy the child forked may still hold the write end for a
      # moment; the marker, if any, is already in the pipe, so look
      # without waiting.
      var pfd = TPollfd(fd: marker[0], events: POLLIN, revents: 0)
      var got: array[RawMarker.len, char]
      let n = if poll(addr pfd, 1, 0) > 0:
                posix.read(marker[0], addr got[0], got.len)
              else: 0
      discard posix.close(marker[0])
      var gotMarker = newString(max(n, 0))
      for i in 0 ..< gotMarker.len: gotMarker[i] = got[i]
      var code = 1
      if WIFEXITED(status): code = int(WEXITSTATUS(status))
      elif WIFSIGNALED(status): code = 128 + int(WTERMSIG(status))
      if code == RawFallbackExit and gotMarker == RawMarker:
        stderr.writeLine("sandwall: retrying with proxy env")
        return -1
      code

  proc runMain(args: seq[string]): int =
    ## sandwall RULES [--] CMD [ARGS...]
    if args.len < 2:
      return dieUsage("expected RULES and a command")
    let rulesArg = args[0]
    var cmdStart = 1
    if args[1] == "--": cmdStart = 2
    if cmdStart >= args.len:
      return dieUsage("no command given")
    let cmd = args[cmdStart .. ^1]

    let projectDir = getCurrentDir()
    var text: string
    var policyPath = ""
    if rulesArg == "-":
      text = stdin.readAll()
    else:
      policyPath = absolutePath(rulesArg)
      if not fileExists(policyPath):
        return dieUsage("rules file not found: " & rulesArg)
      text = readFile(policyPath)
    let rules = parsePolicy(text, projectDir)

    # setsid() before restrict+exec so CMD lands in its own session and
    # process group: callers that wrap long-running commands signal the
    # whole group on cancel/timeout, and without setsid those signals
    # would miss CMD's children.
    when defined(posix):
      discard setsid()
      when defined(linux):
        # Raw mode is tried only when nft is there to load the redirect;
        # the child decides whether it holds (restrict, RawUnavailableError).
        if findNft().len > 0:
          let rc = runRaw(rules, projectDir, policyPath, cmd)
          if rc >= 0: return rc
      try:
        restrict(rules, projectDir, policyPath)
        exec(cmd)
      except CatchableError as e:
        stderr.writeLine("sandwall: " & e.msg)
        return 127
    else:
      # Windows cannot confine the current process; runSandboxed
      # restricts (sandbox user ACL stamps) and spawns the child as
      # that user.
      let r = resolve(rules)
      # Network: no host rules -> open (POSIX parity). Host rules ->
      # the WFP fence (installed via `sandwall setup`) confines the
      # child's egress to loopback; the wall proxy enforces the
      # hostname allowlist. If the fence is NOT installed, warn: the
      # child has open network in either mode (accepted degrade).
      let netAllowed = r.hosts.len == 0
      let hosts = toHostList(r.hosts)
      var wallProxy: WallProxy
      var permits: seq[PermitEntry]
      if not netAllowed:
        let fenceInstalled = try: fenceStatus().installed
                              except CatchableError: false
        if not fenceInstalled:
          stderr.writeLine("sandwall: WARNING: host rules are present but " &
            "the WFP fence is not installed. The child will have OPEN " &
            "network access. Run 'sandwall setup' (elevated) to install " &
            "the fence and enforce the host allowlist.")
        # Raw path first. When every allow rule is an exact name or an
        # IP literal, the policy's addresses are seeded here, within
        # 1.5 s, and the kernel permits them for this run
        # (wfp.stampPermits): CMD gets no proxy env and connects
        # straight out. A wildcard allow admits names no snapshot can
        # enumerate and a deny-only policy has nothing to stamp; both
        # go to the proxy (env mode), which decides by name.
        if hosts.canStamp:
          let ps = newPermitSet()
          let report = ps.seedFromPolicy(hosts, 1500)
          permits = ps.snapshot()
          ps.close()
          let unresolved = report.failed.len + report.pending.len
          if unresolved > 0:
            stderr.writeLine("sandwall: " & $unresolved &
              " allowed host(s) did not resolve in time; not permitted " &
              "this run")
          if permits.len == 0:
            stderr.writeLine("sandwall: no allowed host resolved; using " &
              "the proxy env path")
      if permits.len > 0:
        try:
          return int(runSandboxed(r.writable, cmd, read = r.readonly,
                                  denied = r.denied, permits = permits))
        except PermitStampError as e:
          stderr.writeLine("sandwall: " & e.msg &
            "; using the proxy env path")
      if not netAllowed:
        let polPath = if policyPath.len > 0: policyPath
                      else:
                        let p = getTempDir() / ("sandwall-" &
                          $getCurrentProcessId() & "-policy")
                        writeFile(p, renderPolicy(rules))
                        p
        wallProxy = startWallProxy(polPath, projectDir)
        setProxyEnv(wallProxy.port)
      # Env mode: loopback reaches the wall proxy, which enforces the
      # allowlist; everything else the fence blocks. Without the fence
      # the child has open network (accepted degrade).
      try:
        return int(runSandboxed(r.writable, cmd, read = r.readonly,
                                denied = r.denied))
      except CatchableError as e:
        stderr.writeLine("sandwall: " & e.msg)
        return 127
      finally:
        if not netAllowed: stopWallProxy(wallProxy)

  proc cliMain(): int =
    let args = commandLineParams()
    if args.len == 0 or args[0] == "-h" or args[0] == "--help":
      stdout.writeLine(usage)
      return 0
    case args[0]
    of "connect":
      connectMain(args[1 .. ^1])
    of "setup":
      when defined(windows):
        if "--status" in args:
          let st = fenceStatus()
          let ast = acFenceStatus()
          echo "user fence: installed=", st.installed, " filters=", st.filters
          echo "ac fence:   installed=", ast.installed, " filters=", ast.filters
          if st.hint.len > 0: echo "  ", st.hint
          if ast.hint.len > 0: echo "  ", ast.hint
          return 0
        if "--uninstall" in args:
          uninstallFence()
          uninstallAcFence()
          unexemptAcLoopback()
          echo "sandwall: wall filters removed"
          return 0
        # --stamp-as ACCOUNT: let the unelevated account that spawns
        # stamp per-run permits (the raw path). Without it every run
        # goes through the proxy env path. The account must not be the
        # sandbox user itself: it could then widen its own fence.
        var stampAs = ""
        for i, a in args:
          if a == "--stamp-as" and i + 1 < args.len: stampAs = args[i + 1]
        var stampSid = ""
        if stampAs.len > 0:
          stampSid = sidString(stampAs)
          if stampSid.len == 0:
            stderr.writeLine("sandwall: --stamp-as: no such account: '" &
              stampAs & "'")
            return 1
          if stampSid == sidString():
            stderr.writeLine("sandwall: --stamp-as must not be the " &
              "sandbox user")
            return 1
        try:
          let sid = setupSandwallUser()
          installFence(sid, FirstProxyPort, LastProxyPort)
          try:
            installAcFence()
            exemptAcLoopback()
            echo "sandwall: AC fence installed"
          except OSError as e:
            stderr.writeLine("sandwall: AC fence install failed: " & e.msg)
          if stampSid.len > 0:
            try:
              grantPermitStamping(stampSid)
              echo "sandwall: ", stampAs,
                " may stamp per-run permits (check with wfp-stamp-probe)"
            except OSError as e:
              stderr.writeLine("sandwall: permit stamping not granted: " &
                e.msg & "; runs use the proxy env path")
          echo "sandwall: setup complete; sandwall user SID ", sid
          return 0
        except OSError as e:
          stderr.writeLine("sandwall: " & e.msg)
          return 1
      else:
        stderr.writeLine("sandwall: setup is only available on Windows builds " &
          "(the Windows fence needs a one-time elevated install). On this " &
          "build no setup is needed."); 2
    of "wfp-probe":
      when defined(windows):
        wfpProbeMain()
      else:
        0  # internal: nothing to probe on POSIX
    of "wfp-stamp-probe":
      # The raw path's gate, run unelevated as the spawning account:
      # can this session stamp and remove one permit filter?
      when defined(windows):
        wfpStampProbeMain(sidString())
      else:
        0  # internal: nothing to probe on POSIX
    of "stdio-relay":
      # The CPLW child's stdio hop: spawnSandboxed prefixes the
      # sandboxed command with `<self> stdio-relay --`. 3code.exe has
      # its own copy of this dispatch under `wall stdio-relay`.
      when defined(windows):
        if args.len < 3 or args[1] != "--":
          stderr.writeLine("sandwall: stdio-relay needs -- CMD")
          return 2
        stdio.relayMain(args[2 .. ^1])
      else:
        stderr.writeLine("sandwall: stdio-relay is Windows-only")
        return 2
    else:
      runMain(args)

  quit(cliMain())
