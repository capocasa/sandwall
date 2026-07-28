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

import std/syncio
import ./paths
export paths.normalize

when defined(linux):
  import ./landlock
  import ./mask
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
               proxySockPath: string = "") =
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
  ## Windows accepts the parameter and ignores it for now (chunk 4).
  ##
  ## `writable` paths get full access (read, write, create, delete, rename,
  ## execute). `read` paths get read + execute only; defaults to empty.
  ## `denied` paths are unreachable even when they sit under a writable or
  ## read root (the compiled output of the policy's last-wins narrowing).
  ## Everything else is denied. Each call layers a new restriction; the
  ## effective access is the intersection of all applied restrictions, so
  ## later calls only narrow. Drop a path from `writable` and re-call to
  ## revoke it.
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
    if denied.len > 0:
      try:
        maskDenied(denied)
      except OSError as e:
        stderr.writeLine("sandwall: " & e.msg &
          "; continuing without sub-path deny enforcement")
    landlock.restrictImpl(writable, read)
    if fenceNet and proxySockPath.len > 0:
      # Landlock must still permit connecting to the unix socket: the
      # consumer must place proxySockPath under a writable path.
      discard bridgeToUnix(proxyPort, proxySockPath)
  elif defined(macosx):
    seatbelt.restrictImpl(writable, read, denied, egress = not fenceNet)
  elif defined(windows):
    # fenceNet stays a no-op here: the Windows wall is keyed on the
    # sandwall user's SID (wfp.nim) and therefore lives on the spawn
    # path (wall.winuser.spawnAsSandwall), not in this in-process call.
    acl.restrictImpl(writable, read, denied)
  else:
    {.error: "sandwall restrict has no backend for this platform".}
