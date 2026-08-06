## OS-specific baseline paths every sandboxed process needs.
##
## A sandboxed command still has to exec, load shared libraries, read random
## data, and redirect to /dev/null. These are read-only system directories
## and device nodes the OS itself provides, not user data. Each backend
## auto-adds them inside `restrictImpl`, so callers never pass them.
##
## Split into read-only (system dirs, libs, binaries, devices like
## /dev/urandom) and writable-devices (/dev/null, /dev/tty on systems where
## the shell needs it). The writable set is deliberately tiny: /dev/null must
## accept writes or every `2>/dev/null` fails.

# Read-only system paths: shared libraries, system binaries, fonts, device
# nodes that only need read access.
when defined(linux):
  const baselineRead* = [
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/etc",
    "/proc", "/sys",
    "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom",
    "/dev/dri", "/dev/shm"
  ]
  # /dev/null must accept writes (shells redirect stderr there constantly).
  const baselineWrite* = ["/dev/null"]
elif defined(macosx):
  const baselineRead* = [
    "/usr", "/bin", "/sbin", "/etc",
    "/System", "/Library", "/opt",
    "/private/var/db/timezone", "/private/var/db/dyld", "/private/etc",
    "/private/tmp", "/private/var/tmp",
    "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"
  ]
  const baselineWrite* = ["/dev/null"]
elif defined(windows):
  # The AppContainer child reads/executes system binaries via the standard
  # ALL APPLICATION PACKAGES grant already on C:\Windows, so no baseline
  # stamping is needed (and C:\Windows is protected against our DACL writes
  # anyway). Writable paths get explicit grants; everything else is denied.
  const baselineRead* = @[]
  const baselineWrite* = @[]
else:
  const baselineRead* = @[]
  const baselineWrite* = @[]
