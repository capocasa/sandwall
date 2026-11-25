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
  export netns.RawUnavailableError, netns.RawMarker, netns.RawFallbackExit
elif defined(macosx):
  import ./seatbelt
  export seatbelt.backendSupported, seatbelt.backendName
elif defined(windows):
  import ./rtoken
  export rtoken.backendSupported, rtoken.backendName,
         rtoken.interruptActiveRun

proc restrict*(writable: openArray[string]; read: openArray[string] = [];
               denied: openArray[string] = [];
               fenceNet: bool = false; proxyPort: uint16 = 0;
               proxySockPath: string = "";
               bridgePort: ptr uint16 = nil;
               raw: bool = false; dnsSockPath: string = "") =
  ## Confine the calling thread (and all future children).
  ##
  ## `raw` (Linux, with fenceNet and proxySockPath) adds the env-var-free
  ## egress path on top of the netns (wall/netns.nim): the fake pool
  ## routed, an nft redirect onto a raw bridge, `/etc/resolv.conf`
  ## pointing at a DNS relay to `dnsSockPath` (the forwarder's unix
  ## datagram listener), and the raw bridge itself; all of it before
  ## exec, and the two relays forked after Landlock so they inherit it.
  ## The proxy env vars are then the caller's to leave alone. When the
  ## raw half cannot go up it raises RawUnavailableError before Landlock
  ## with nothing half-applied, which `restrict(rules)` turns into exit
  ## 75 with `RawMarker` (the parent's cue to re-spawn in env mode).
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
    # NO_NEW_PRIVS before any namespace switch: the flag is inherited
    # across unshare(2), and some kernels reject the prctl once the
    # caller sits in a fresh user namespace (arm64 CI runners). Landlock's
    # apply() re-sets it, which is then a no-op.
    landlock.setNoNewPrivsEarly()
    # When fencing, the userns must be created WITH CLONE_NEWNET, so the
    # netns comes first and maskDenied's ensureUserns is a no-op after.
    if raw and (not fenceNet or proxySockPath.len == 0):
      raise newException(ValueError,
        "sandwall: the raw fence needs fenceNet and proxySockPath")
    if fenceNet:
      try:
        enterNetns()
      except OSError as e:
        if raw:
          # env mode is the better degrade: tools that honor proxy vars
          # still go through the policy. Let the parent switch to it.
          raise newException(RawUnavailableError, "network namespace: " & e.msg)
        stderr.writeLine("sandwall: " & e.msg &
          "; continuing WITHOUT network fencing")
    var rawFence: RawFence
    if raw:
      # nft needs exec and the resolv.conf bind mount needs the mount
      # namespace as it is: both before Landlock and the masks.
      rawFence = prepareRawFence(proxySockPath, dnsSockPath)
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
    try:
      landlock.restrictImpl(writable, read, denied)
    except OSError as e:
      # Same backend-unavailable posture as the unshare and mask
      # degrades above: report and continue without this layer. The
      # mount-namespace masks and the netns fence remain in force.
      stderr.writeLine("sandwall: " & e.msg &
        "; continuing WITHOUT landlock confinement")
    if fenceNet and proxySockPath.len > 0:
      # Landlock must still permit connecting to the unix socket: the
      # consumer must place proxySockPath under a writable path.
      let bp = bridgeToUnix(proxyPort, proxySockPath)
      if bridgePort != nil: bridgePort[] = bp
    if raw:
      startRawBridges(rawFence)
  elif defined(macosx):
    seatbelt.restrictImpl(writable, read, denied, egress = not fenceNet)
  elif defined(windows):
    # fenceNet stays a no-op here: the Windows wall is keyed on the
    # sandwall user's SID (wfp.nim) and therefore lives on the spawn
    # path (wall.winuser.spawnAsSandwall), not in this in-process call.
    rtoken.restrictImpl(writable, read, denied)
  else:
    {.error: "sandwall restrict has no backend for this platform".}

# ------------------------------------------------------------------ rules

import std/os
import ./rules
when defined(posix):
  import ./wall/proxy
when defined(linux):
  import std/posix

proc restrict*(rules: openArray[Rule]; projectDir: string;
               policyPath: string = ""; verbose = false;
               raw: bool = false; fallbackFd: cint = -1) =
  ## Apply a parsed policy to the calling thread (and all future
  ## children): filesystem rules first, then the network wall.
  ##
  ## `raw` (Linux) asks for the env-var-free path instead: fence DNS
  ## with fake-IPs, an nft redirect, and the proxy's raw forward path
  ## (wall/netns.nim). Then no proxy env var is set. The mode is the
  ## parent's call: when the raw half is refused this process prints
  ## the reason, `RawMarker`, writes the marker to `fallbackFd` when
  ## given (the caller's pipe to its parent, which it should make
  ## CLOEXEC so the exec'd command cannot fake the signal) and exits
  ## 75, before Landlock and exec. A caller that wants the fallback
  ## forks for the attempt.
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
    when defined(linux):
      try:
        restrict(writable, r.readonly, r.denied, fenceNet = true,
                 proxyPort = 0, proxySockPath = proxy.sockPath,
                 bridgePort = addr bp,
                 raw = raw, dnsSockPath = runDir / "dns.sock")
      except RawUnavailableError as e:
        stderr.writeLine("sandwall: " & e.msg)
        stderr.writeLine(RawMarker)
        if fallbackFd >= 0:
          var marker = RawMarker
          discard posix.write(fallbackFd, addr marker[0], marker.len)
        exitnow(RawFallbackExit)
      if raw: return   # the redirect and the fence DNS carry egress: no env
    else:
      restrict(writable, r.readonly, r.denied, fenceNet = true,
               proxyPort = 0, proxySockPath = proxy.sockPath,
               bridgePort = addr bp)
    let fencePort = when defined(linux): bp else: proxy.port
    # Point the exec'd command's proxy env at the wall proxy. On linux
    # the fenced side reaches it through the netns bridge's ephemeral
    # in-netns port; on macOS at the proxy's own host-loopback port.
    setProxyEnv(fencePort)
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
