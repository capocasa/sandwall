## mask: enforce denied subpaths on Linux by hiding them in a mount
## namespace.
##
## Landlock layers intersect and rules within a layer union, so there is
## no way to subtract a subpath from an allowed root with Landlock alone.
## The kernel-supported answer (the same technique bubblewrap uses) is a
## user+mount namespace: bind a denied directory over an empty directory,
## a denied file over /dev/null, and the path is unreachable regardless
## of what the Landlock domain allows. Mount namespaces are per-process
## and inherited by children, so the masks hold for the whole tree.
##
## Unprivileged user namespaces can be disabled by the distro or blocked
## by a container's seccomp profile; in that case `maskDenied` raises and
## the caller falls back to running without the narrowing (with a
## warning, matching the host's general "backend unavailable" posture).

when defined(linux):
  import std/[os, posix, strutils, hashes]
  import ./paths

  {.push header: "<sched.h>".}
  proc unshare(flags: cint): cint {.importc: "unshare".}
  {.pop.}

  {.push header: "<sys/mount.h>".}
  proc mount(source, target, fstype: cstring, flags: culong,
             data: pointer): cint {.importc: "mount".}
  {.pop.}

  const
    CLONE_NEWUSER_C* = 0x10000000.cint
    CLONE_NEWNS_C* = 0x00020000.cint
    CLONE_NEWNET_C* = 0x40000000.cint
    MS_BIND_C = 4096.culong
    MS_REC_C = 16384.culong
    MS_PRIVATE_C = 1.culong shl 18

  var inUserns = false
    ## Set once ensureUserns succeeded; later calls (e.g. maskDenied then
    ## enterNetns) skip the unshare entirely.

  proc writeProc(path, content: string) =
    ## The /proc id-mapping writes raise IOError on hosts where the
    ## files are missing or unwritable (Ubuntu's apparmor userns
    ## restriction fails HERE, after unshare already succeeded, rather
    ## than at unshare). Callers of ensureUserns catch OSError to
    ## degrade (restrict: "continuing without sub-path deny
    ## enforcement"), so anything else escapes as an unhandled
    ## exception and kills every sandboxed command. Translate.
    try:
      writeFile(path, content)
    except CatchableError as e:
      raise newException(OSError,
        "sandwall: writing " & path & " failed: " & e.msg)

  proc writeIdMap(path: string; outer: int) =
    writeProc(path, $outer & " " & $outer & " 1\n")

  proc prctl(option: cint): cint {.importc: "prctl", varargs, discardable.}

  proc setNoNewPrivsBestEffort*() =
    ## prctl(PR_SET_NO_NEW_PRIVS), ignoring failure: landlock's apply()
    ## sets the flag again and reports when it truly cannot be set. Set
    ## BEFORE any unshare(2): the flag is sticky and inherited across the
    ## namespace switch, so landlock's own set is a no-op re-set there.
    ## (The arm64 CI EPERM that motivated the early set was never prctl's:
    ## landlock.nim issued the x86_64 syscall number, which is setsid(2)
    ## on arm64.)

    const PR_SET_NO_NEW_PRIVS = 38
    discard prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

  proc ensureUserns*(extraFlags: cint = 0) =
    ## Enter our uid-mapped user+mount namespace (plus `extraFlags` such as
    ## CLONE_NEWNET), exactly once per process. No-op on repeat calls: the
    ## namespaces from the first call stay, and extra flags of later calls
    ## are moot - so the net fence must be requested before or with the
    ## first restriction. Raises OSError when unprivileged user namespaces
    ## are unavailable; callers decide whether that is fatal.
    if inUserns: return
    setNoNewPrivsBestEffort()
    # Read the ids BEFORE the unshare: inside the fresh namespace they
    # show as the unmapped overflow (65534) until a map exists, and a
    # mapping write naming 65534 is rejected for any other outer id -
    # the stranded-nobody bug.
    let outerUid = int(getuid())
    let outerGid = int(getgid())
    if unshare(CLONE_NEWUSER_C or CLONE_NEWNS_C or extraFlags) != 0:
      raise newException(OSError,
        "sandwall: unshare(user+mount ns) failed (errno " & $errno &
        "); unprivileged user namespaces may be disabled")
    # Self-map (not 0): the confined process keeps the launching user's
    # id, so `id`, listings and ownership checks show the truth. Caps
    # over the namespace come from the unshare itself, not from the
    # mapped value - mapping to 0 bought nothing except a lying `id`
    # and root-shaped tool behavior inside the fence.
    writeProc("/proc/self/setgroups", "deny\n")
    writeIdMap("/proc/self/uid_map", outerUid)
    writeIdMap("/proc/self/gid_map", outerGid)
    # Don't let the masks propagate back to the host's mount table.
    if mount(nil, "/", nil, MS_REC_C or MS_PRIVATE_C, nil) != 0:
      raise newException(OSError,
        "sandwall: making mounts private failed (errno " & $errno & ")")
    inUserns = true

  proc bindMount*(source, target: string) =
    ## Bind `source` over `target` (a file or a directory) in this
    ## process's mount namespace. Raises OSError; the caller decides
    ## whether that is fatal. Requires the user+mount namespace
    ## (`ensureUserns`) to be in place, and the mounts to be private so
    ## nothing propagates to the host.
    if mount(source.cstring, target.cstring, nil, MS_BIND_C, nil) != 0:
      raise newException(OSError,
        "sandwall: bind-mount " & source & " over " & target &
        " failed (errno " & $errno & ")")

  proc maskDenied*(denied: openArray[string]) =
    ## Hide each denied path from this process and its children. A
    ## denied directory is bind-masked over a fresh empty dir, a denied
    ## file over a fresh empty file. The scratch source is chmod'd
    ## unwritable up front: a bare bind is writable, so a command
    ## writing into a denied path would succeed into the mask copy and
    ## exit 0, losing the data while looking like success. With the mode
    ## stripped the attempt fails with EACCES instead. (A read-only
    ## bind REMOUNT is the other way, but remounting a bind requires
    ## repeating the source mount's full flag set or the kernel answers
    ## EINVAL; the mode works everywhere.) DAC rather than mount flags
    ## also means the check survives in user namespaces, where caps
    ## granted by the ns don't reach mounts owned by the parent ns.
    if denied.len == 0: return
    ensureUserns()
    for raw in denied:
      let d = paths.normalize(raw)
      if d.len == 0 or not (dirExists(d) or fileExists(d)): continue
      if dirExists(d):
        let empty = getTempDir() / ("sandwall-mask-" & $getpid() & "-" &
                                    $hash(d))
        if not dirExists(empty): createDir(empty)
        try: setFilePermissions(empty, {fpUserRead, fpUserExec})
        except OSError: discard
        if mount(empty.cstring, d.cstring, nil, MS_BIND_C, nil) != 0:
          raise newException(OSError,
            "sandwall: bind-mask " & d & " failed (errno " & $errno & ")")
      else:
        let empty = getTempDir() / ("sandwall-mask-file-" & $getpid() & "-" &
                                    $hash(d))
        var prepared = true
        if not fileExists(empty):
          try:
            writeFile(empty, "")
            setFilePermissions(empty, {fpUserRead})
          except CatchableError:
            prepared = false
        if not prepared:
          # No scratch file available (read-only temp): fall back to
          # /dev/null, which still hides the content.
          if mount("/dev/null".cstring, d.cstring, nil, MS_BIND_C, nil) != 0:
            raise newException(OSError,
              "sandwall: bind-mask " & d & " failed (errno " & $errno & ")")
        else:
          if mount(empty.cstring, d.cstring, nil, MS_BIND_C, nil) != 0:
            raise newException(OSError,
              "sandwall: bind-mask " & d & " failed (errno " & $errno & ")")
