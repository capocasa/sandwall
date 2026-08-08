## Low-level Linux Landlock backend for sandwall.
##
## Landlock is a Linux Security Module (kernel 5.13+) that lets any
## unprivileged process restrict its own filesystem access. Once applied to
## a thread, the restriction binds to that thread and all descendants forever:
## you can only ever add *more* rules, never loosen them.
##
## This module is Linux-specific. On other platforms it compiles to no-ops so
## the rest of sandwall stays portable, but the interesting work is here.

const landlockAvailable* = defined(linux)

when defined(linux):
  import std/[oserrors, sets]
  import std/posix except Time
  import ./paths
  import ./baseline
  type AccessFds = distinct uint64

  # Syscall numbers are stable on every Linux/Arch combination (UAPI).
  const
    sysLandlockCreateRuleset = 444
    sysLandlockAddRule = 445
    sysLandlockRestrictSelf = 446

    LANDLOCK_CREATE_RULESET_VERSION = 1.cuint

    # Filesystem access rights, in bit order from linux/landlock.h.
    LANDLOCK_ACCESS_FS_EXECUTE = (1'u64 shl 0)
    LANDLOCK_ACCESS_FS_WRITE_FILE = (1'u64 shl 1)
    LANDLOCK_ACCESS_FS_READ_FILE = (1'u64 shl 2)
    LANDLOCK_ACCESS_FS_READ_DIR = (1'u64 shl 3)
    LANDLOCK_ACCESS_FS_REMOVE_DIR = (1'u64 shl 4)
    LANDLOCK_ACCESS_FS_REMOVE_FILE = (1'u64 shl 5)
    LANDLOCK_ACCESS_FS_MAKE_CHAR = (1'u64 shl 6)
    LANDLOCK_ACCESS_FS_MAKE_DIR = (1'u64 shl 7)
    LANDLOCK_ACCESS_FS_MAKE_REG = (1'u64 shl 8)
    LANDLOCK_ACCESS_FS_MAKE_SOCK = (1'u64 shl 9)
    LANDLOCK_ACCESS_FS_MAKE_FIFO = (1'u64 shl 10)
    LANDLOCK_ACCESS_FS_MAKE_BLOCK = (1'u64 shl 11)
    LANDLOCK_ACCESS_FS_MAKE_SYM = (1'u64 shl 12)
    LANDLOCK_ACCESS_FS_REFER = (1'u64 shl 13)
    LANDLOCK_ACCESS_FS_TRUNCATE = (1'u64 shl 14)
    LANDLOCK_ACCESS_FS_IOCTL_DEV = (1'u64 shl 15)

  type
    RulesetAttr {.packed.} = object
      handledAccessFs: uint64
      handledAccessNet: uint64
      scoped: uint64

    PathBeneathAttr {.packed.} = object
      allowedAccess: uint64
      parentFd: cint

  proc syscall(n: clong): clong {.importc: "syscall", header: "<unistd.h>", varargs.}
  proc rawOpen(path: cstring, flags: cint): cint {.importc: "open", header: "<fcntl.h>".}
  proc rawClose(fd: cint): cint {.importc: "close", header: "<unistd.h>".}
  template checkErrno(ctx: string) =
    let e = osLastError()
    raise newException(OSError,
      "landlock: " & ctx & " failed (errno=" & $int(e) & ")")

  proc queryAbi(): int =
    ## The kernel's highest supported Landlock ABI version, or -1 when the
    ## kernel has no Landlock at all. Each version added access-rights bits:
    ##   v1 (5.13): execute, read, write, remove, make_*
    ##   v2 (5.19): REFER (rename across dirs)
    ##   v3 (6.2):  TRUNCATE
    ##   v4 (6.7):  IOCTL_DEV
    ## Passing a ruleset attr or a per-rule mask with bits the running kernel
    ## doesn't understand makes the syscall fail with EINVAL, so callers must
    ## mask to the bits their kernel reports.
    let r = syscall(clong sysLandlockCreateRuleset, nil, 0.culong,
                    LANDLOCK_CREATE_RULESET_VERSION.cuint)
    if r < 0: result = -1 else: result = int r

  # Full bitmask of every right sandwall knows, across all ABI versions. This
  # is the upper bound; the kernel-supported subset is computed at restrict()
  # time from queryAbi().
  const allFsRights =
    LANDLOCK_ACCESS_FS_EXECUTE or
    LANDLOCK_ACCESS_FS_WRITE_FILE or
    LANDLOCK_ACCESS_FS_READ_FILE or
    LANDLOCK_ACCESS_FS_READ_DIR or
    LANDLOCK_ACCESS_FS_REMOVE_DIR or
    LANDLOCK_ACCESS_FS_REMOVE_FILE or
    LANDLOCK_ACCESS_FS_MAKE_CHAR or
    LANDLOCK_ACCESS_FS_MAKE_DIR or
    LANDLOCK_ACCESS_FS_MAKE_REG or
    LANDLOCK_ACCESS_FS_MAKE_SOCK or
    LANDLOCK_ACCESS_FS_MAKE_FIFO or
    LANDLOCK_ACCESS_FS_MAKE_BLOCK or
    LANDLOCK_ACCESS_FS_MAKE_SYM or
    LANDLOCK_ACCESS_FS_REFER or
    LANDLOCK_ACCESS_FS_TRUNCATE or
    LANDLOCK_ACCESS_FS_IOCTL_DEV

  proc maskForAbi(abi: int): uint64 =
    ## The rights bits valid for the running kernel's ABI version. Drops the
    ## bits newer than the kernel supports so create_ruleset/add_rule don't
    ## fail with EINVAL on older kernels.
    result = allFsRights
    if abi < 2: result = result and not LANDLOCK_ACCESS_FS_REFER
    if abi < 3: result = result and not LANDLOCK_ACCESS_FS_TRUNCATE
    if abi < 4: result = result and not LANDLOCK_ACCESS_FS_IOCTL_DEV

  # Rights valid only for directories. Landlock rejects add_rule with
  # EINVAL when directory-only bits are set on a file path (device node,
  # regular file, symlink). addRule uses fileRights (the complement) for
  # non-directory paths.
  const dirOnlyRights =
    LANDLOCK_ACCESS_FS_READ_DIR or
    LANDLOCK_ACCESS_FS_REMOVE_DIR or
    LANDLOCK_ACCESS_FS_REMOVE_FILE or
    LANDLOCK_ACCESS_FS_MAKE_CHAR or
    LANDLOCK_ACCESS_FS_MAKE_DIR or
    LANDLOCK_ACCESS_FS_MAKE_REG or
    LANDLOCK_ACCESS_FS_MAKE_SOCK or
    LANDLOCK_ACCESS_FS_MAKE_FIFO or
    LANDLOCK_ACCESS_FS_MAKE_BLOCK or
    LANDLOCK_ACCESS_FS_MAKE_SYM or
    LANDLOCK_ACCESS_FS_REFER

  # Rights valid for a regular file or device node: execute, read, write,
  # truncate, ioctl. REFER is about cross-directory rename and is rejected
  # for files; TRUNCATE and IOCTL_DEV are file-level ops.
  const fileOnlyRights =
    LANDLOCK_ACCESS_FS_EXECUTE or
    LANDLOCK_ACCESS_FS_WRITE_FILE or
    LANDLOCK_ACCESS_FS_READ_FILE or
    LANDLOCK_ACCESS_FS_TRUNCATE or
    LANDLOCK_ACCESS_FS_IOCTL_DEV

  proc readRights(mask: uint64): AccessFds =
    ## The "read" rights bundle: execute + read file + read dir, masked to
    ## what the kernel supports.
    AccessFds(uint64(LANDLOCK_ACCESS_FS_EXECUTE or
                     LANDLOCK_ACCESS_FS_READ_FILE or
                     LANDLOCK_ACCESS_FS_READ_DIR) and mask)

  proc writeRights(mask: uint64): AccessFds =
    ## Everything: full read + all the mutating ops we handle, masked to what
    ## the kernel supports. Granting this to a path makes it fully usable.
    AccessFds(uint64(readRights(mask)) or
              ((allFsRights and not uint64(readRights(allFsRights))) and mask))

  proc openPath(path: string): cint =
    result = rawOpen(path, 0o2000000)  # O_PATH (010000000 octal)
    if result < 0: checkErrno("open('" & path & "') O_PATH")

  proc closeFd(fd: cint) =
    if fd >= 0:
      discard rawClose(fd)

  type
    Ruleset = object
      fd: cint
      abi: int

  proc attrSizeForAbi(abi: int): culong =
    # The kernel validates attr_size against its own compiled struct, so
    # passing more bytes than the running ABI knows returns EINVAL. ABI v1
    # has only handledAccessFs (8 bytes), v2 adds handledAccessNet (16),
    # v5 adds scoped (24).
    result = 8.culong
    if abi >= 2: result = 16.culong
    if abi >= 5: result = 24.culong

  proc createRuleset(): Ruleset =
    let abi = queryAbi()
    if abi < 0:
      raise newException(OSError,
        "landlock: kernel does not support landlock (create_ruleset " &
        "version probe failed)")
    let mask = maskForAbi(abi)
    # DEBUG: test which high bits the kernel accepts
    for testBit in [14'u64, 15'u64]:
      let ta = RulesetAttr(handledAccessFs: testBit,
                           handledAccessNet: 0, scoped: 0)
      let tf = syscall(clong sysLandlockCreateRuleset,
                       unsafeAddr ta, culong(sizeof(ta)), 0.cuint)
      stderr.writeLine "LANDLOCK DEBUG bit=", testBit, " fd=", tf,
        " errno=", (if tf < 0: int(osLastError()) else: 0)
    let attr = RulesetAttr(handledAccessFs: mask,
                           handledAccessNet: 0,
                           scoped: 0)
    let attrSize = attrSizeForAbi(abi)
    stderr.writeLine "LANDLOCK DEBUG abi=", abi, " mask=", mask,
      " attrSize=", attrSize, " sizeof=", sizeof(attr)
    # Try full struct size first; fall back to ABI-sized on EINVAL.
    var fd = syscall(clong sysLandlockCreateRuleset,
                     unsafeAddr attr, culong(sizeof(attr)), 0.cuint)
    if fd < 0 and osLastError() == OSErrorCode(22):
      stderr.writeLine "LANDLOCK DEBUG retry with attrSize=", attrSize
      fd = syscall(clong sysLandlockCreateRuleset,
                   unsafeAddr attr, attrSize, 0.cuint)
    if fd < 0:
      stderr.writeLine "LANDLOCK DEBUG create_ruleset errno=", int(osLastError())
      checkErrno("create_ruleset")
    result.fd = cint fd
    result.abi = abi

  proc addRule(rs: var Ruleset; path: string; allowed: AccessFds) =
    if rs.fd < 0:
      raise newException(ValueError, "sandwall: ruleset already consumed")
    let pfd = openPath(path)
    try:
      # Landlock rejects add_rule with EINVAL when directory-only rights
      # (READ_DIR, MAKE_*, REMOVE_*, REFER) are set on a non-directory path.
      # O_PATH gives an fd we can fstat to check the type.
      var st: Stat
      var effective = uint64(allowed)
      if fstat(pfd, st) == 0'i32 and not S_ISDIR(st.st_mode):
        effective = effective and fileOnlyRights
      let pb = PathBeneathAttr(allowedAccess: effective, parentFd: pfd)
      const LANDLOCK_RULE_PATH_BENEATH = 1
      let r = syscall(clong sysLandlockAddRule, rs.fd.clong,
                      LANDLOCK_RULE_PATH_BENEATH.clong,
                      unsafeAddr pb, 0.cuint)
      if r < 0: checkErrno("add_rule('" & path & "')")
    finally:
      closeFd(pfd)

  proc apply(rs: var Ruleset) =
    if rs.fd < 0:
      raise newException(ValueError, "sandwall: ruleset already consumed")
    const PR_SET_NO_NEW_PRIVS = 38
    let p = syscall(clong 157, PR_SET_NO_NEW_PRIVS.clong, 1.clong,
                    0.clong, 0.clong, 0.clong)
    if p < 0: checkErrno("prctl(NO_NEW_PRIVS)")
    let r = syscall(clong sysLandlockRestrictSelf, rs.fd.clong, 0.cuint)
    if r < 0: checkErrno("restrict_self")
    closeFd(rs.fd)
    rs.fd = -1

  proc close(rs: var Ruleset) =
    closeFd(rs.fd)
    rs.fd = -1

proc backendSupported*(): bool = landlockAvailable

proc backendName*(): string = "landlock"

when defined(linux):
  proc restrictImpl*(writable, read: openArray[string]) =
    ## Confine the calling thread via a single Landlock domain. Writable
    ## paths get full access, read paths get read + execute, everything else
    ## is denied.
    var rs = createRuleset()
    try:
      let mask = maskForAbi(rs.abi)
      let w = writeRights(mask)
      let r = readRights(mask)
      # Track paths added with write rights so we don't add a redundant
      # read-only rule for the same path (write already includes read). A
      # read-only path added first is still upgraded by a later write rule,
      # since Landlock unions multiple rules for the same path.
      var writeSeen = initHashSet[string]()
      var readSeen = initHashSet[string]()
      # Auto-add OS-specific baseline paths so sandboxed commands can exec,
      # load shared libraries, read /dev/urandom, and redirect to /dev/null
      # without callers listing them explicitly.
      for p in baselineRead:
        let n = normalize(p)
        if n.len == 0 or readSeen.containsOrIncl(n): continue
        try: rs.addRule(n, r)
        except OSError: discard
      for p in baselineWrite:
        let n = normalize(p)
        if n.len == 0 or writeSeen.containsOrIncl(n): continue
        try: rs.addRule(n, w)
        except OSError: discard
      for p in writable:
        let n = normalize(p)
        if n.len == 0 or writeSeen.containsOrIncl(n): continue
        try: rs.addRule(n, w)
        except OSError: discard
      for p in read:
        let n = normalize(p)
        if n.len == 0 or readSeen.containsOrIncl(n): continue
        try: rs.addRule(n, r)
        except OSError: discard
      rs.apply()
    except CatchableError:
      rs.close()
      raise
