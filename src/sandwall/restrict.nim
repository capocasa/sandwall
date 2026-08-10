## restrict: lock the current thread's filesystem access to a set of paths.
##
## Each call builds and applies a single OS-native restriction. Within the
## applied policy, writable paths get full access (read, write, create,
## delete, rename, execute) and read paths get read + execute only; everything
## else is denied.
##
## The enforcement is monotonic: the OS intersects every applied restriction,
## so successive calls only tighten. A path must be allowed by *every* applied
## domain to remain accessible.
##
## No state, no init. Each call is a self-contained restriction. On a platform
## without a backend, it raises.

import std/[syncio, strutils, os]
import ./paths
export paths.normalize

when defined(linux):
  import ./landlock
  import ./mask
  import ./baseline
  import ./wall/netns
  export landlock.backendSupported, landlock.backendName
elif defined(macosx):
  import ./seatbelt
  export seatbelt.backendSupported, seatbelt.backendName
elif defined(windows):
  import ./acl
  export acl.backendSupported, acl.backendName

proc restrict*(writable: openArray[string]; read: openArray[string] = [];
               denied: openArray[string] = [];
               fenceNet: bool = false; proxyPort: uint16 = 0;
               proxySockPath: string = "";
               bridgePort: ptr uint16 = nil) =
  ## Confine the calling thread (and all future children).
  ##
  ## `fenceNet` confines network egress to loopback: on Linux by
  ## unsharing a network namespace (CLONE_NEWNET alongside the mask.nim
  ## user+mount userns; the netns has only `lo`, which kills UDP and
  ## DNS too), on macOS by Seatbelt rules permitting localhost traffic
  ## only. The wall proxy is then the only way off the machine: on
  ## Linux the child reaches it via `proxySockPath` - the proxy's unix
  ## listener in a directory this policy leaves writable - through a
  ## bridge re-exposed on 127.0.0.1:proxyPort inside the netns (0 =
  ## ephemeral; only meaningful when proxySockPath is set); on macOS
  ## the sandbox reaches the host loopback directly and proxySockPath
  ## is unused. When the netns is unavailable (unprivileged userns
  ## disabled, old kernel) a warning is printed and the restriction
  ## continues WITHOUT network fencing, matching the backend posture.
  ## Windows ignores it here: the network fence on Windows is decided at
  ## spawn time in process.spawnSandboxed (internetClient capability when
  ## the policy has no host rules, airgap when it has), not in-process.
  ##
  ## `writable` paths get full access (read, write, create, delete, rename,
  ## execute). `read` paths get read + execute only; defaults to empty.
  ## `denied` paths are unreachable even when they sit under a writable or
  ## read root (the compiled output of the policy's last-wins narrowing).
  ## Everything else is denied. On Linux each call layers a new
  ## restriction; the effective access is the intersection of all
  ## applied restrictions, so later calls only narrow. Drop a path from
  ## `writable` and re-call to revoke it. On macOS Seatbelt is one-shot
  ## per process (sandbox_init fails EPERM on re-init), so restrict()
  ## may be called only once there.
  ##
  ## On Linux `denied` is enforced by bind-masking the paths in a
  ## user+mount namespace before Landlock is applied (see mask.nim);
  ## Seatbelt and Windows subtract natively. When the namespace setup is
  ## unavailable the restriction applies without the narrowing and a
  ## warning is printed, matching the general backend-unavailable posture.
  when defined(linux):
    # When fencing, the userns must be created WITH CLONE_NEWNET, so the
    # netns comes first and maskDenied's ensureUserns is a no-op after.
    if fenceNet:
      try:
        enterNetns()
      except OSError as e:
        stderr.writeLine("sandwall: " & e.msg &
          "; continuing WITHOUT network fencing")
    # Denies under a baseline root are re-scoped inside Landlock
    # itself (rules union there, a bind-mask would not help); the
    # mount-namespace mask is only needed for denies narrowing a
    # policy rule's own allow/readonly root.
    var masked: seq[string]
    for d in denied:
      var underBaseline = false
      for b in baselineRead:
        if d == b or (d.len > b.len and d.startsWith(b & DirSep)):
          underBaseline = true; break
      if not underBaseline: masked.add d
    if masked.len > 0:
      try:
        maskDenied(masked)
      except OSError as e:
        stderr.writeLine("sandwall: " & e.msg &
          "; continuing without sub-path deny enforcement")
    landlock.restrictImpl(writable, read, denied)
    if fenceNet and proxySockPath.len > 0:
      # Landlock must still permit connecting to the unix socket: the
      # consumer must place proxySockPath under a writable path.
      let bp = bridgeToUnix(proxyPort, proxySockPath)
      if bridgePort != nil: bridgePort[] = bp
  elif defined(macosx):
    seatbelt.restrictImpl(writable, read, denied, egress = not fenceNet)
  elif defined(windows):
    # fenceNet stays a no-op here: the Windows wall is keyed on the
    # sandwall user's SID (wfp.nim) and therefore lives on the spawn
    # path (wall.winuser.spawnAsSandwall), not in this in-process call.
    acl.restrictImpl(writable, read, denied)
  else:
    {.error: "sandwall restrict has no backend for this platform".}

# ------------------------------------------------------------------ rules

import std/os
import ./rules
when defined(posix):
  import ./wall/proxy

proc restrict*(rules: openArray[Rule]; projectDir: string;
               policyPath: string = ""; verbose = false) =
  ## Apply a parsed policy to the calling thread (and all future
  ## children): filesystem rules first, then the network wall.
  ##
  ## With no host rules this is the filesystem sandbox alone. With at
  ## least one host rule, egress is fenced to loopback and a per-run
  ## wall proxy is forked (spawnWallProxy: it dies with the command
  ## tree, one proxy per run); the proxy enforces the hostname
  ## allowlist. Proxy env vars (http_proxy et al, socks5h for remote
  ## DNS) are set on this process so an exec'd command inherits them.
  ##
  ## `policyPath` is the file the proxy watches for mtime reloads, so
  ## editing the rules file mid-run takes effect on the next
  ## connection. Empty (stdin, ephemeral rules): the rendered rules
  ## are written into the run dir and that copy is watched; rewriting
  ## it is the reload path.
  ##
  ## Raises on backend or proxy failure.
  let r = resolve(rules)
  if r.hosts.len == 0:
    restrict(r.writable, r.readonly, r.denied)
    return
  when defined(posix):
    # The proxy is forked BEFORE any restriction: after restrict it
    # would inherit the fence, after exec the forking image is gone.
    # No policyPath (stdin, ephemeral rules): render the rules into
    # the run dir and watch that copy.
    let runDir = getTempDir() / ("sandwall-" & $getCurrentProcessId())
    createDir(runDir)
    let polPath = if policyPath.len > 0: policyPath
                  else: runDir / "policy"
    if policyPath.len == 0:
      writeFile(polPath, renderPolicy(rules))
    let proxy = spawnWallProxy(polPath, projectDir, runDir = runDir,
                               verbose = verbose)
    # The bridge's unix socket must sit in a writable dir or Landlock
    # denies connect() on it (netns.nim header). Add the run dir.
    var writable = r.writable
    if proxy.sockPath.len > 0:
      writable.add proxy.runDir
    # On linux the fenced side reaches the proxy through the netns
    # bridge, which binds its own ephemeral port INSIDE the netns;
    # env must point at that port, not the host one. On macOS the
    # sandbox reaches host loopback directly, so the proxy's own port.
    var bp: uint16
    restrict(writable, r.readonly, r.denied, fenceNet = true,
             proxyPort = 0, proxySockPath = proxy.sockPath,
             bridgePort = addr bp)
    let fencePort = when defined(linux): bp else: proxy.port
    # Env for the exec'd command: most tools honor http_proxy/
    # ALL_PROXY; socks5h means DNS happens at the proxy (the fence
    # has no resolver). WALL_PROXY_PORT is for tools that speak to
    # the proxy directly (the connect adapter reads it).
    let hp = "http://127.0.0.1:" & $fencePort
    let sp = "socks5h://127.0.0.1:" & $fencePort
    putEnv("http_proxy", hp)
    putEnv("https_proxy", hp)
    putEnv("HTTP_PROXY", hp)
    putEnv("HTTPS_PROXY", hp)
    putEnv("ALL_PROXY", sp)
    putEnv("all_proxy", sp)
    # No NO_PROXY on purpose: loopback targets must go through the
    # proxy too - the fence permits only loopback, and the proxy is
    # where the hostname allowlist lives. Tools bypassing the proxy
    # for 127.0.0.1 would hit the fence (or, allowed, loopback
    # services inside the netns see nothing useful).
    putEnv("NO_PROXY", "")
    putEnv("no_proxy", "")
    putEnv("WALL_PROXY_PORT", $fencePort)
  else:
    # Windows: the net fence is keyed on the sandwall user and lives
    # on the spawn path (wall/winuser.nim), not in this in-process
    # call. Fail loudly rather than pretend.
    raise newException(IOError,
      "sandwall: host rules (network fence) are not supported in-process " &
      "on Windows; spawn via the sandwall user instead")

proc restrict*(rules: openArray[Rule]; verbose = false) =
  ## As restrict(rules, projectDir, policyPath) with the current dir
  ## as project root and no policy file (rules are fixed for the run;
  ## a reload copy is written to the run dir when fencing).
  restrict(rules, getCurrentDir(), "", verbose)
