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
  export landlock.backendSupported, landlock.backendName
elif defined(macosx):
  import ./seatbelt
  export seatbelt.backendSupported, seatbelt.backendName
elif defined(windows):
  import ./acl
  export acl.backendSupported, acl.backendName

proc restrict*(writable: openArray[string]; read: openArray[string] = [];
               denied: openArray[string] = []) =
  ## Confine the calling thread (and all future children).
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
    if denied.len > 0:
      try:
        maskDenied(denied)
      except OSError as e:
        stderr.writeLine("sandwall: " & e.msg &
          "; continuing without sub-path deny enforcement")
    landlock.restrictImpl(writable, read)
  elif defined(macosx):
    seatbelt.restrictImpl(writable, read, denied)
  elif defined(windows):
    acl.restrictImpl(writable, read, denied)
  else:
    {.error: "sandwall restrict has no backend for this platform".}
