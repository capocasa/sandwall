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
    CLONE_NEWUSER_C = 0x10000000.cint
    CLONE_NEWNS_C = 0x00020000.cint
    MS_BIND_C = 4096.culong
    MS_REC_C = 16384.culong
    MS_PRIVATE_C = 1.culong shl 18

  proc writeIdMap(path: string; inner: cint) =
    let outer = if "uid" in path: getuid() else: getgid()
    writeFile(path, $inner & " " & $outer & " 1\n")

  proc maskDenied*(denied: openArray[string]) =
    ## Hide each denied path from this process and its children. A denied
    ## directory is bind-masked over a fresh empty dir, a denied file over
    ## /dev/null. Raises OSError when unprivileged user namespaces are
    ## unavailable; callers decide whether that is fatal.
    if denied.len == 0: return
    if unshare(CLONE_NEWUSER_C or CLONE_NEWNS_C) != 0:
      raise newException(OSError,
        "procbox: unshare(user+mount ns) failed (errno " & $errno &
        "); unprivileged user namespaces may be disabled")
    # Map our own uid/gid to 0 inside the namespace so we keep ownership
    # of the bind mounts we make.
    writeFile("/proc/self/setgroups", "deny\n")
    writeIdMap("/proc/self/uid_map", 0)
    writeIdMap("/proc/self/gid_map", 0)
    # Don't let the masks propagate back to the host's mount table.
    if mount(nil, "/", nil, MS_REC_C or MS_PRIVATE_C, nil) != 0:
      raise newException(OSError,
        "procbox: making mounts private failed (errno " & $errno & ")")
    for raw in denied:
      let d = paths.normalize(raw)
      if d.len == 0 or not (dirExists(d) or fileExists(d)): continue
      if dirExists(d):
        let empty = getTempDir() / ("procbox-mask-" & $getpid() & "-" &
                                    $hash(d))
        if not dirExists(empty): createDir(empty)
        if mount(empty.cstring, d.cstring, nil, MS_BIND_C, nil) != 0:
          raise newException(OSError,
            "procbox: bind-mask " & d & " failed (errno " & $errno & ")")
      else:
        if mount("/dev/null".cstring, d.cstring, nil, MS_BIND_C, nil) != 0:
          raise newException(OSError,
            "procbox: bind-mask " & d & " failed (errno " & $errno & ")")
