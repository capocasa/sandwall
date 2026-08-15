## Windows AppContainer + ACL backend for sandwall.
##
## Windows has no single syscall-interception hook, and hand-rolled
## restricted tokens (CreateRestrictedToken + CreateProcessAsUserW) cannot
## spawn a child on Windows 11 - every variant fails with access denied
## (verified by probes; see cybernetic-plan.md step 1). The supported
## mechanism is an AppContainer: a process launched with
## PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES runs under a lowbox token
## that denies filesystem and network access by default; only DACL grants
## for the AppContainer SID let the child touch a path.
##
## So this backend: derives (or creates) the `sandwall.fs` AppContainer
## profile once, stamps ALLOW ACEs for its SID on the writable/read-only
## paths, and lets process.nim spawn the child with the security-capabilities
## attribute. No volume-root DENY stamps are needed (the AppContainer denies
## by default), which removes the dangerous system-wide mutation and its
## rollback risk. The ALLOW stamps on user paths are still rolled back
## after the child exits.

import ./paths

when defined(windows):
  import std/winlean except PSID
  import std/[widestrs, sets, syncio]
  import ./wall/winffi
  export winffi.PSID

  # AppContainer profile FFI lives in wall/winffi.nim (shared with
  # wfp.nim and winuser.nim). CreateAppContainerProfile returns
  # ERROR_ALREADY_EXISTS (0x800700b7) when the profile exists from a
  # previous run; the SID then comes from deriveAppContainerSidFromAppContainerName.

  # --- ACL stamping FFI (accctrl.h / aclapi.h / winnt.h) ---

  type
    # ACCESS_MODE (accctrl.h): GRANT_ACCESS for stamps, DENY_ACCESS for
    # policy narrowing. Sized to int32 to match the Win32 enum. The order
    # matters: DENY_ACCESS=3, REVOKE_ACCESS=4 (winnt.h); an earlier version
    # swapped them, so a "deny" stamp silently REVOKEd (a no-op strip) and
    # deny narrowing under a writable root never took (verified on Win11).
    ACCESS_MODE* {.size: sizeof(int32).} = enum
      notUsedAccess = 0
      grantAccess   ## allow
      setAccess
      denyAccess    ## deny (policy narrowing)
      revokeAccess  ## strip all existing ACEs for the trustee
      setAudit
      setAllAudit

    TRUSTEE_FORM {.size: sizeof(int32).} = enum
      trusteeIsSid = 0
      trusteeIsName
      trusteeBadForm
      trusteeIsObjectsAndSid
      trusteeIsObjectsAndName

    TRUSTEE_TYPE* {.size: sizeof(int32).} = enum
      trusteeIsUnknown = 0
      trusteeIsUser
      trusteeIsGroup
      trusteeIsDomain
      trusteeIsAlias
      trusteeIsWellKnownGroup
      trusteeIsDeleted
      trusteeIsInvalid
      trusteeIsComputer

    # {CONTAINER|OBJECT}_INHERIT_ACE (winnt.h).
    # SUB_CONTAINERS_AND_OBJECTS_INHERIT = both bits set.
    Inheritance = enum
      noInherit = 0x0
      subContainersAndObjectsInherit = 0x3  # CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE

    SE_OBJECT_TYPE {.size: sizeof(int32).} = enum
      seUnknownObjectType = 0
      seFileObject = 1  ## the only one we use

    # Win32 TRUSTEE_W (accctrl.h). Layout verified amd64: 32 bytes,
    # ptstrName at offset 24.
    TRUSTEE_W* {.bycopy.} = object
      pMultipleTrustee: pointer
      multipleTrusteeOperation: int32  # NO_MULTIPLE_TRUSTEE = 0
      trusteeForm: TRUSTEE_FORM
      trusteeType: TRUSTEE_TYPE
      ptstrName: pointer               # PSID when trusteeForm = TRUSTEE_IS_SID

    # Win32 EXPLICIT_ACCESS_W. Layout verified amd64: 48 bytes, trustee at 16.
    EXPLICIT_ACCESS_W* {.bycopy.} = object
      grfAccessPermissions: DWORD
      grfAccessMode: ACCESS_MODE
      grfInheritance: DWORD
      trustee: TRUSTEE_W

    PACL* = pointer

  const
    # SECURITY_INFORMATION flags (winnt.h)
    DACL_SECURITY_INFORMATION* = 0x00000004
    LABEL_SECURITY_INFORMATION = 0x00000010'i32

    # File access masks (winnt.h)
    FILE_GENERIC_READ*    = 0x00120089'i32
    FILE_GENERIC_EXECUTE* = 0x001200A0'i32
    FILE_ALL_ACCESS*      = 0x001F01FF'i32

    # Token rights needed to write an integrity label into an object's SACL
    # (SetNamedSecurityInfo with LABEL_SECURITY_INFORMATION).
    TOKEN_QUERY_PRIV       = 0x0008'i32
    TOKEN_ADJUST_PRIVILEGES = 0x0020'i32
    SE_PRIVILEGE_ENABLED   = 0x00000002'i32

  type
    LUID = object
      lowPart: DWORD
      highPart: LONG
    LUID_AND_ATTRIBUTES = object
      luid: LUID
      attributes: DWORD
    # TOKEN_PRIVILEGES with a one-element privilege array.
    TOKEN_PRIVILEGES_1 = object
      privilegeCount: DWORD
      privileges: array[1, LUID_AND_ATTRIBUTES]

  # SetEntriesInAcl merges one or more EXPLICIT_ACCESS into a new ACL. We pass
  # the old ACL as nil so it builds a fresh one from our entries.
  proc setEntriesInAcl*(cCountOfExplicitEntries: DWORD;
      pListOfExplicitEntries: ptr EXPLICIT_ACCESS_W;
      oldAcl: PACL; newAcl: ptr PACL): DWORD {.stdcall, dynlib: "advapi32",
      importc: "SetEntriesInAclW".}

  # SetNamedSecurityInfo takes an object by name (wide) and a SE_OBJECT_TYPE.
  proc setNamedSecurityInfoW*(pObjectName: pointer; objectType: SE_OBJECT_TYPE;
      securityInfo: DWORD; psidOwner: PSID; psidGroup: PSID;
      pDacl: PACL; pSacl: PACL): DWORD {.stdcall, dynlib: "advapi32",
      importc: "SetNamedSecurityInfoW".}

  # GetNamedSecurityInfo reads an existing security descriptor by name. Used by
  # rollbackAcls to fetch the live DACL before stripping our SID's ACEs.
  proc getNamedSecurityInfoW*(pObjectName: pointer;
      objectType: SE_OBJECT_TYPE; securityInfo: DWORD;
      psidOwner: ptr PSID; psidGroup: ptr PSID; pDacl: ptr PACL;
      pSacl: ptr PACL; psd: ptr pointer): DWORD {.stdcall, dynlib: "advapi32",
      importc: "GetNamedSecurityInfoW"}

  # --- integrity label FFI (advapi32) ---

  # SDDL <-> security descriptor conversion, and SACL extraction from a
  # descriptor. The integrity label is applied via an SDDL SACL because
  # building a SYSTEM_MANDATORY_LABEL ACE by hand (SetEntriesInAcl rewrites
  # the ACE type) does not survive SetNamedSecurityInfo - verified by probes.
  # convertStringSecurityDescriptorToSecurityDescriptorW comes from winffi.
  proc getSecurityDescriptorSacl(sd: pointer; present: ptr WINBOOL;
      sacl: ptr PACL; defaulted: ptr WINBOOL): WINBOOL {.stdcall,
      dynlib: "advapi32", importc: "GetSecurityDescriptorSacl".}

  proc getAce(acl: PACL; idx: DWORD; ace: ptr pointer): WINBOOL {.stdcall,
      dynlib: "advapi32", importc: "GetAce".}

  # IsEqualSid/EqualSid/RtlEqualMemory are all compiler intrinsics on Windows
  # (none exported from any dll - "could not import"), so compare SIDs in pure
  # Nim: equal length plus a raw byte compare via equalMem.
  # getLengthSid comes from winffi.
  proc sameSid(a, b: PSID): bool =
    let la = getLengthSid(a)
    if la != getLengthSid(b): return false
    return equalMem(a, b, int(la))

  proc addAce(acl: PACL; aceRevision, startingAceIndex: DWORD; aceList: pointer;
      aceListLength: DWORD): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "AddAce".}

  proc openProcessToken(processHandle: Handle; desiredAccess: DWORD;
      tokenHandle: ptr Handle): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "OpenProcessToken".}

  proc lookupPrivilegeValueW(systemName, name: WideCString;
      luid: ptr LUID): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "LookupPrivilegeValueW".}

  proc adjustTokenPrivileges(tokenHandle: Handle; disableAllPrivileges: WINBOOL;
      newState: ptr TOKEN_PRIVILEGES_1; bufferLength: DWORD;
      previousState: pointer; returnLength: ptr DWORD): WINBOOL {.stdcall,
      dynlib: "advapi32", importc: "AdjustTokenPrivileges".}

  # --- module state ---

  # AppContainer SID prepared by restrictImpl, applied at spawn time by
  # process.nim. nil = no sandbox set. The SID is allocated by userenv and
  # kept alive for the whole sandbox lifetime; the attribute-list buffer
  # process.nim builds references it.
  var currentAppContainerSid*: PSID = nil

  # Every filesystem path whose DACL we mutated. The spawn walks this in a
  # defer to remove our ACEs. Mutating security descriptors is the one
  # dangerous operation in this backend: a crash between stamp and rollback
  # leaves stray allow ACEs for the AppContainer SID on user paths (deny
  # stamps no longer exist - the AppContainer denies by default).
  var stampedPaths*: seq[string] = @[]

  # Writable paths we labelled Low integrity; rolled back in rollbackAcls.
  var labelledPaths*: seq[string] = @[]

  # --- helpers ---

  proc fail*(what: string) {.noinline.} =
    ## Raise OSError carrying the Win32 error code for the last failed call.
    raise newException(OSError,
      "sandwall windows-acl: " & what & " failed (error " & $getLastError() & ")")

  proc enablePrivilege(name: string) =
    ## Enable `name` (e.g. SeSecurityPrivilege) on the current process token.
    ## Needed to write integrity labels into an object's SACL. Best-effort:
    ## a caller already holding the privilege is unaffected, and a caller that
    ## cannot get it will simply fail the label write (handled by caller).
    var token: Handle
    if openProcessToken(getCurrentProcess(),
        DWORD(TOKEN_QUERY_PRIV or TOKEN_ADJUST_PRIVILEGES), addr token) == 0:
      return
    defer: discard closeHandle(token)
    var luid: LUID
    if lookupPrivilegeValueW(nil, newWideCString(name), addr luid) == 0:
      return
    var tp: TOKEN_PRIVILEGES_1
    tp.privilegeCount = 1
    tp.privileges[0].luid = luid
    tp.privileges[0].attributes = DWORD(SE_PRIVILEGE_ENABLED)
    discard adjustTokenPrivileges(token, 0, addr tp, 0, nil, nil)

  proc buildAppContainerSid*(): PSID =
    ## Return the SID of the `sandwall.fs` AppContainer profile, creating
    ## the profile on first use. The profile persists across runs, so after
    ## creation we take the derive path. Raises OSError if neither call
    ## succeeds. The returned SID stays valid until freed by userenv; we
    ## keep it for the process lifetime.
    if currentAppContainerSid != nil:
      return currentAppContainerSid
    let name = newWideCString("sandwall.fs")
    var sid: PSID = nil
    if createAppContainerProfile(name, newWideCString("sandwall fs"),
        newWideCString("sandwall filesystem sandbox"), nil, 0,
        addr sid) != 0:
      # Exists from a previous run (or any failure) - derive by name.
      if deriveAppContainerSidFromAppContainerName(name, addr sid) != 0:
        fail("CreateAppContainerProfile/DeriveAppContainerSidFromAppContainerName")
    currentAppContainerSid = sid
    return sid

  proc buildExplicitAccess*(sid: PSID; mode: ACCESS_MODE; rights: DWORD;
      inheritance: DWORD): EXPLICIT_ACCESS_W =
    ## Construct an EXPLICIT_ACCESS_W for `sid` (TRUSTEE_IS_SID) with the given
    ## access mode, rights, and inheritance flags.
    result = default(EXPLICIT_ACCESS_W)
    result.grfAccessPermissions = rights
    result.grfAccessMode = mode
    result.grfInheritance = inheritance
    result.trustee.pMultipleTrustee = nil
    result.trustee.multipleTrusteeOperation = 0  # NO_MULTIPLE_TRUSTEE
    result.trustee.trusteeForm = trusteeIsSid
    result.trustee.trusteeType = trusteeIsUser
    result.trustee.ptstrName = sid

  proc buildDefaultDaclEntry*(sid: PSID): EXPLICIT_ACCESS_W =
    ## EXPLICIT_ACCESS granting GENERIC_ALL (no inheritance) for a token
    ## default DACL, with TRUSTEE_IS_UNKNOWN (not TRUSTEE_IS_USER): the SIDs
    ## are a mix of well-known and session SIDs, and UNKNOWN avoids the name
    ## lookup a typed trustee can trigger. Matches Codex's token default DACL.
    result = buildExplicitAccess(sid, grantAccess, DWORD(0x10000000'i32), 0)
    result.trustee.trusteeType = trusteeIsUnknown

  proc writeDacl(path: string; acl: PACL) =
    ## Write `acl` as the new DACL for `path`. Raises OSError on failure.
    let wpathObj = newWideCString(path)
    let wpath: WideCString = wpathObj
    let rc = setNamedSecurityInfoW(cast[pointer](wpath), seFileObject,
      DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
    if rc != 0:
      raise newException(OSError,
        "sandwall windows-acl: SetNamedSecurityInfo failed on " & path &
        " (error " & $rc & ")")

  proc mergeDaclEntry(path: string; sid: PSID; mode: ACCESS_MODE;
      rights: DWORD; inheritance: DWORD) =
    ## Merge one EXPLICIT_ACCESS into `path`'s live DACL (grant or revoke).
    ## Reads the DACL, applies SetEntriesInAcl against it (preserving every
    ## other ACE), writes the result back. Raises OSError on any failed step.
    var oldDacl: PACL = nil
    var sd: pointer = nil
    let wpathObj = newWideCString(path)
    let wpath: WideCString = wpathObj
    let rc0 = getNamedSecurityInfoW(cast[pointer](wpath), seFileObject,
      DACL_SECURITY_INFORMATION, nil, nil, addr oldDacl, nil, addr sd)
    if rc0 != 0:
      raise newException(OSError,
        "sandwall windows-acl: GetNamedSecurityInfo failed on " & path &
        " (error " & $rc0 & ")")
    defer: localFree(sd)
    var ea = buildExplicitAccess(sid, mode, rights, inheritance)
    var newAcl: PACL = nil
    let rc = setEntriesInAcl(1, addr ea, oldDacl, addr newAcl)
    if rc != 0:
      raise newException(OSError,
        "sandwall windows-acl: SetEntriesInAcl failed on " & path &
        " (error " & $rc & ")")
    # SetEntriesInAcl allocates with LocalAlloc; LocalFree releases it.
    defer: localFree(newAcl)
    writeDacl(path, newAcl)

  proc stampAce*(path: string; sid: PSID; mode: ACCESS_MODE;
      rights: DWORD; inheritance = DWORD(subContainersAndObjectsInherit)) =
    ## Add an ACE for `sid` to `path`'s DACL, MERGING into the existing DACL
    ## (preserving the inherited SYSTEM/Administrators grants). Records `path`
    ## in stampedPaths for rollback. Raises OSError on any failed step.
    mergeDaclEntry(path, sid, mode, rights, inheritance)
    stampedPaths.add(path)

  # SDDL for the Low-integrity mandatory label. `ML` =
  # SYSTEM_MANDATORY_LABEL_ACE_TYPE (a SetEntriesInAcl-built ACE gets its type
  # rewritten and is silently dropped by SetNamedSecurityInfo, so the label
  # must come from an SDDL-parsed descriptor - verified by probes). OICI makes
  # the label inherit to children, NW is the No-Write-Up policy, LW = the Low
  # integrity SID (S-1-16-4096). AI keeps the SACL auto-inherit flag, matching
  # what `icacls /setintegritylevel (OI)(CI)L` produces.
  const lowLabelSddl = "S:AI(ML;OICI;NW;;;LW)"

  proc stampIntegrityLabel(path: string) =
    ## Mark `path` Low integrity via a mandatory-label ACE in the SACL. An
    ## AppContainer child runs at Low integrity, and Windows Mandatory
    ## Integrity Control denies a Low process write access to any object not
    ## itself labelled Low (the default No-Write-Up policy) - regardless of
    ## the DACL. So every writable path needs this label in addition to the
    ## DACL grant, or the child sees "Access is denied" on writes even though
    ## the DACL ACE is present. Requires SeSecurityPrivilege (SACL write),
    ## enabled in stampAcls.
    var sd: pointer = nil
    if convertStringSecurityDescriptorToSecurityDescriptorW(
        newWideCString(lowLabelSddl), 1, addr sd, nil) == 0:
      raise newException(OSError,
        "sandwall windows-acl: SDDL parse of label failed (error " &
        $getLastError() & ")")
    defer: localFree(sd)
    var present: WINBOOL = 0
    var sacl: PACL = nil
    var defaulted: WINBOOL = 0
    if getSecurityDescriptorSacl(sd, addr present, addr sacl, addr defaulted) == 0 or
        present == 0 or sacl == nil:
      raise newException(OSError,
        "sandwall windows-acl: no SACL in parsed label descriptor")
    let wpathObj = newWideCString(path)
    let wpath: WideCString = wpathObj
    let rc = setNamedSecurityInfoW(cast[pointer](wpath), seFileObject,
      DWORD(LABEL_SECURITY_INFORMATION), nil, nil, nil, sacl)
    if rc != 0:
      raise newException(OSError,
        "sandwall windows-acl: SetNamedSecurityInfo(label) failed on " & path &
        " (error " & $rc & ")")
    labelledPaths.add(path)

  proc removeIntegrityLabel(path: string) =
    ## Clear the integrity label from `path` (rollback of stampIntegrityLabel).
    ## Writes a NULL SACL for the LABEL portion, which removes the mandatory
    ## label ACE. Requires SeSecurityPrivilege.
    let wpathObj = newWideCString(path)
    let wpath: WideCString = wpathObj
    let rc = setNamedSecurityInfoW(cast[pointer](wpath), seFileObject,
      DWORD(LABEL_SECURITY_INFORMATION), nil, nil, nil, nil)
    if rc != 0:
      raise newException(OSError,
        "sandwall windows-acl: SetNamedSecurityInfo(label-clear) failed on " & path &
        " (error " & $rc & ")")


  proc hasSidAce*(path: string; sid: PSID; rights: DWORD;
      inheritance: DWORD): bool =
    ## True when `path`'s DACL already carries an ALLOW ACE for `sid`
    ## covering `rights` with matching `inheritance`. Lets callers skip
    ## a redundant SetNamedSecurityInfoW, which on profile directories
    ## costs seconds (NTFS walks the subtree reconciling inheritable
    ## ACEs even when nothing changes).
    var oldDacl: PACL = nil
    var sd: pointer = nil
    let wpathObj = newWideCString(path)
    let wpath: WideCString = wpathObj
    let rc0 = getNamedSecurityInfoW(cast[pointer](wpath), seFileObject,
      DACL_SECURITY_INFORMATION, nil, nil, addr oldDacl, nil, addr sd)
    if rc0 != 0:
      raise newException(OSError,
        "sandwall windows-acl: GetNamedSecurityInfo failed on " & path &
        " (error " & $rc0 & ")")
    defer: localFree(sd)
    if oldDacl.isNil: return false
    let aceCount = int(cast[ptr uint16](cast[uint](oldDacl) + 2)[])
    for i in 0 ..< aceCount:
      var ace: pointer = nil
      if getAce(oldDacl, DWORD(i), addr ace) == 0: continue
      # AceType at +1: 0 = ACCESS_ALLOWED_ACE_TYPE
      if cast[ptr uint8](cast[uint](ace) + 1)[] != 0: continue
      let aceMask = cast[ptr DWORD](cast[uint](ace) + 4)[]
      let aceFlags = cast[ptr uint8](cast[uint](ace) + 3)[]
      let aceSid = cast[PSID](cast[pointer](cast[uint](ace) + 8))
      if not sameSid(aceSid, sid): continue
      if (aceMask and rights) != rights: continue
      if (DWORD(aceFlags) and DWORD(0x0F)) != inheritance: continue
      return true
    false

  proc removeSidAces*(path: string; sid: PSID) =
    ## Strip every ACE whose trustee SID equals `sid` from `path`'s DACL.
    ## SetEntriesInAcl/REVOKE_ACCESS is NOT usable here: on this Windows 11
    ## build it leaves behind a ghost ACCESS_DENIED (mask 0) ACE for the
    ## trustee instead of deleting it (verified by probe p80). So we rebuild
    ## the DACL manually: copy every ACE whose trustee is NOT our SID into a
    ## fresh ACL with AddAce, preserving order (deny-before-allow semantics)
    ## and every other trustee. Raises OSError on failure.
    var oldDacl: PACL = nil
    var sd: pointer = nil
    let wpathObj = newWideCString(path)
    let wpath: WideCString = wpathObj
    let rc0 = getNamedSecurityInfoW(cast[pointer](wpath), seFileObject,
      DACL_SECURITY_INFORMATION, nil, nil, addr oldDacl, nil, addr sd)
    if rc0 != 0:
      raise newException(OSError,
        "sandwall windows-acl: GetNamedSecurityInfo failed on " & path &
        " (error " & $rc0 & ")")
    defer: localFree(sd)

    # Compute the surviving size and count, skipping our SID's ACEs.
    let aceCount = cast[ptr uint16](cast[uint](oldDacl) + 2)[]
    var keepSize = 0
    var keepCount = 0
    for i in 0 ..< int(aceCount):
      var ace: pointer = nil
      if getAce(oldDacl, DWORD(i), addr ace) == 0: continue
      let aceSize = int(cast[ptr uint16](cast[uint](ace) + 2)[])
      let aceSid = cast[PSID](cast[pointer](cast[uint](ace) + 8))
      if sameSid(aceSid, sid):
        continue  # ours - drop it
      keepSize += aceSize
      keepCount += 1

    # New ACL header (8 bytes) + the kept ACE bodies, built by AddAce so the
    # header fields (revision, size, count) stay consistent.
    let newSize = 8 + keepSize
    let newAcl = cast[PACL](alloc0(newSize))
    defer: dealloc(newAcl)
    # ACL_REVISION = 2 (a plain discretionary ACL).
    cast[ptr uint8](newAcl)[] = 2
    cast[ptr uint16](cast[uint](newAcl) + 2)[] = uint16(newSize)
    cast[ptr uint16](cast[uint](newAcl) + 4)[] = 0  # AddAce maintains AceCount
    for i in 0 ..< int(aceCount):
      var ace: pointer = nil
      if getAce(oldDacl, DWORD(i), addr ace) == 0: continue
      let aceSize = DWORD(cast[ptr uint16](cast[uint](ace) + 2)[])
      let aceSid = cast[PSID](cast[pointer](cast[uint](ace) + 8))
      if sameSid(aceSid, sid):
        continue
      # MAXDWORD start index = append, preserving order.
      if addAce(newAcl, DWORD(2), DWORD(-1), ace, aceSize) == 0:
        raise newException(OSError,
          "sandwall windows-acl: AddAce(rebuild) failed on " & path &
          " (error " & $getLastError() & ")")
    writeDacl(path, newAcl)

proc backendSupported*(): bool =
  when defined(windows): true else: false

proc backendName*(): string = "windows-appcontainer"

when defined(windows):
  proc stampAcls*(writable, read: seq[string]; sid: PSID) =
    ## Stamp the full ACL policy for the AppContainer SID:
    ##   1. ALLOW FILE_ALL_ACCESS + a Low integrity label on each writable
    ##      path (the label is required: the Low-integrity child is blocked
    ##      from writing Medium/High objects by MIC even when the DACL allows).
    ##   2. ALLOW FILE_GENERIC_READ | FILE_GENERIC_EXECUTE on each read path
    ##      (read is allowed across integrity levels, so no label needed).
    ## No DENY stamps: the AppContainer denies everything it is not granted,
    ## so volume roots need no touching. Each mutated path is recorded in
    ## stampedPaths for rollback.
    enablePrivilege("SeSecurityPrivilege")
    for p in writable:
      stampAce(p, sid, grantAccess, FILE_ALL_ACCESS)
      stampIntegrityLabel(p)

    for p in read:
      stampAce(p, sid, grantAccess,
        FILE_GENERIC_READ or FILE_GENERIC_EXECUTE)

  proc rollbackAcls*(sid: PSID) =
    ## Best-effort removal of our SID's ACEs from every stamped path, and the
    ## Low integrity label from every labelled path. Called in a defer by the
    ## spawn. Errors are logged to stderr and skipped: a missing path (deleted
    ## during the run) must not abort cleanup of the rest.
    let paths = stampedPaths
    stampedPaths = @[]
    for path in paths:
      try:
        removeSidAces(path, sid)
      except CatchableError as e:
        stderr.writeLine("sandwall windows-acl: rollback failed on " & path &
          ": " & e.msg)
    let labelled = labelledPaths
    labelledPaths = @[]
    for path in labelled:
      try:
        removeIntegrityLabel(path)
      except CatchableError as e:
        stderr.writeLine("sandwall windows-acl: label rollback failed on " & path &
          ": " & e.msg)

  proc restrictImpl*(writable, read: openArray[string];
                     denied: openArray[string] = []) =
    ## Prepare the AppContainer SID and stamp the filesystem ACLs in one
    ## pass. Stores the SID for the spawn path (process.nim) and records
    ## every mutated path so the spawn can roll back via rollbackAcls.
    let sid = buildAppContainerSid()

    var seen = initHashSet[string]()
    var writablePaths: seq[string] = @[]
    var readOnlyPaths: seq[string] = @[]
    for p in writable:
      let n = normalize(p)
      if n.len == 0 or seen.containsOrIncl(n): continue
      writablePaths.add(n)
    for p in read:
      let n = normalize(p)
      if n.len == 0 or seen.containsOrIncl(n): continue
      readOnlyPaths.add(n)

    stampAcls(writablePaths, readOnlyPaths, sid)
