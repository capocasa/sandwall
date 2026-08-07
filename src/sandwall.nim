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
      try:
        restrict(rules, projectDir, policyPath)
        exec(cmd)
      except CatchableError as e:
        stderr.writeLine("sandwall: " & e.msg)
        return 127
    else:
      # Windows cannot confine the current process; runSandboxed
      # restricts (AppContainer SID + ACL stamps) and spawns the child
      # in the container, rolling the ACLs back after.
      let r = resolve(rules)
      # Network parity with POSIX: no host rules -> the child gets the
      # internetClient capability (network left alone); host rules ->
      # the child gets no capability (full egress fence) and a wall
      # proxy enforces the allowlist (wired in the next chunk).
      # Host rules: the no-capability AppContainer is the fence (all
      # egress incl. loopback is denied - verified: loopback is blocked
      # under EVERY capability, the loopback-exemption API is MSIX-only,
      # and WFP ALE_APP_ID is unavailable without admin/BFE, so no
      # capability combination lets the child reach a loopback proxy).
      # The wall proxy still runs in THIS unrestricted process and its
      # env (set on ourselves pre-spawn; the AC child rejects a custom
      # env block, probe p119, but inherits ours) is handed to the child,
      # so tools see the standard allowlist interface - but the child
      # cannot actually reach the proxy, so the allowlist cannot pass
      # traffic. Windows + host rules = airgap, and we say so.
      let netAllowed = r.hosts.len == 0
      var wallProxy: WallProxy
      if not netAllowed:
        let polPath = if policyPath.len > 0: policyPath
                      else:
                        let p = getTempDir() / ("sandwall-" &
                          $getCurrentProcessId() & "-policy")
                        writeFile(p, renderPolicy(rules))
                        p
        stderr.writeLine("sandwall: host rules on Windows: the child is " &
          "fully offline (the AppContainer egress fence also blocks " &
          "loopback, so the wall proxy/allowlist cannot pass traffic)")
        wallProxy = startWallProxy(polPath, projectDir)
        let hp = "http://127.0.0.1:" & $wallProxy.port
        let sp = "socks5h://127.0.0.1:" & $wallProxy.port
        putEnv("http_proxy", hp)
        putEnv("https_proxy", hp)
        putEnv("HTTP_PROXY", hp)
        putEnv("HTTPS_PROXY", hp)
        putEnv("ALL_PROXY", sp)
        putEnv("all_proxy", sp)
        putEnv("NO_PROXY", "")
        putEnv("no_proxy", "")
        putEnv("WALL_PROXY_PORT", $wallProxy.port)
      try:
        return int(runSandboxed(r.writable, cmd, read = r.readonly,
                                denied = r.denied,
                                inetOk = netAllowed))
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
          echo "installed: ", st.installed, " filters: ", st.filters
          if st.hint.len > 0: echo st.hint
          else: echo "behavioral verify: ", verifyFenceBehavioral()
          return 0
        if "--uninstall" in args:
          uninstallFence()
          echo "sandwall: wall filters removed"
          return 0
        try:
          let sid = setupSandwallUser()
          installFence(sid, FirstProxyPort, LastProxyPort)
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
    else:
      runMain(args)

  quit(cliMain())
