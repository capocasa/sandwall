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

import ./paths
export paths.normalize

when defined(linux):
  import ./landlock
  export landlock.backendSupported, landlock.backendName
elif defined(macosx):
  import ./seatbelt
  export seatbelt.backendSupported, seatbelt.backendName
elif defined(windows):
  import ./acl
  export acl.backendSupported, acl.backendName

proc restrict*(writable: openArray[string]; read: openArray[string] = []) =
  ## Confine the calling thread (and all future children).
  ##
  ## `writable` paths get full access (read, write, create, delete, rename,
  ## execute). `read` paths get read + execute only; defaults to empty.
  ## Everything else is denied. Each call layers a new restriction; the
  ## effective access is the intersection of all applied restrictions, so
  ## later calls only narrow. Drop a path from `writable` and re-call to
  ## revoke it.
  when defined(linux):
    landlock.restrictImpl(writable, read)
  elif defined(macosx):
    seatbelt.restrictImpl(writable, read)
  elif defined(windows):
    acl.restrictImpl(writable, read)
  else:
    {.error: "procbox restrict has no backend for this platform".}
