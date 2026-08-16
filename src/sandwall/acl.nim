## Windows ACL primitives for the dedicated-user sandbox backend.
##
## The retired AppContainer backend used to live here (create the
## `sandwall.fs` profile, stamp its SID, roll back after the run); it
## was replaced by rtoken.nim's dedicated-user model in 0.4.0. What
## remains is the shared low-level layer both it and winuser.nim build
## on: the ACCESS_MODE/TRUSTEE/EXPLICIT_ACCESS Win32 types, the
## SetEntriesInAcl/SetNamedSecurityInfo/GetNamedSecurityInfo FFI, and
## the three DACL operations the backends need - stamp an ACE, test
## for an existing ACE, strip a SID's ACEs.
##
## The ACCESS_MODE order matters: DENY_ACCESS=3, REVOKE_ACCESS=4
## (winnt.h); an earlier version swapped them, so a "deny" stamp
## silently REVOKEd (a no-op strip) and deny narrowing under a
## writable root never took (verified on Win11).

when defined(windows):
  import std/winlean except PSID
  import std/[widestrs, syncio]
  import ./wall/winffi
  export winffi.PSID

  # --- ACL stamping FFI (accctrl.h / aclapi.h / winnt.h) ---

  type
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
    Inheritance* = enum
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
      grfAccessPermissions*: DWORD
      grfAccessMode*: ACCESS_MODE
      grfInheritance*: DWORD
      trustee*: TRUSTEE_W

    PACL* = pointer

  const
    # SECURITY_INFORMATION flags (winnt.h)
    DACL_SECURITY_INFORMATION* = 0x00000004

    # File access masks (winnt.h)
    FILE_GENERIC_READ*    = 0x00120089'i32
    FILE_GENERIC_EXECUTE* = 0x001200A0'i32
    FILE_ALL_ACCESS*      = 0x001F01FF'i32
    FILE_TRAVERSE*        = 0x20'i32

    # ACL inheritance flags (winnt.h), shared by the stamping callers
    # that do not use the Inheritance enum.
    OBJECT_INHERIT_ACE* = 0x1'i32
    CONTAINER_INHERIT_ACE* = 0x2'i32
    SUB_CONTAINERS_AND_OBJECTS_INHERIT* = 0x3'i32

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

  # GetNamedSecurityInfo reads an existing security descriptor by name. Used
  # to fetch the live DACL before merging into or stripping from it.
  proc getNamedSecurityInfoW*(pObjectName: pointer;
      objectType: SE_OBJECT_TYPE; securityInfo: DWORD;
      psidOwner: ptr PSID; psidGroup: ptr PSID; pDacl: ptr PACL;
      pSacl: ptr PACL; psd: ptr pointer): DWORD {.stdcall, dynlib: "advapi32",
      importc: "GetNamedSecurityInfoW"}

  proc getAce(acl: PACL; idx: DWORD; ace: ptr pointer): WINBOOL {.stdcall,
      dynlib: "advapi32", importc: "GetAce".}

  proc addAce(acl: PACL; aceRevision, startingAceIndex: DWORD; aceList: pointer;
      aceListLength: DWORD): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "AddAce".}

  # IsEqualSid/EqualSid/RtlEqualMemory are all compiler intrinsics on Windows
  # (none exported from any dll - "could not import"), so compare SIDs in pure
  # Nim: equal length plus a raw byte compare via equalMem.
  # getLengthSid comes from winffi.
  proc sameSid(a, b: PSID): bool =
    let la = getLengthSid(a)
    if la != getLengthSid(b): return false
    return equalMem(a, b, int(la))

  # --- helpers ---

  proc fail*(what: string) {.noinline.} =
    ## Raise OSError carrying the Win32 error code for the last failed call.
    raise newException(OSError,
      "sandwall windows-acl: " & what & " failed (error " & $getLastError() & ")")

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

  proc readDacl(path: string; oldDacl: ptr PACL): pointer =
    ## Fetch `path`'s live DACL and security descriptor. The returned
    ## descriptor is LocalAlloc'd by the API; the caller LocalFrees it.
    ## Raises OSError on failure.
    var sd: pointer = nil
    oldDacl[] = nil
    let wpathObj = newWideCString(path)
    let wpath: WideCString = wpathObj
    let rc = getNamedSecurityInfoW(cast[pointer](wpath), seFileObject,
      DACL_SECURITY_INFORMATION, nil, nil, oldDacl, nil, addr sd)
    if rc != 0:
      raise newException(OSError,
        "sandwall windows-acl: GetNamedSecurityInfo failed on " & path &
        " (error " & $rc & ")")
    sd

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
    let sd = readDacl(path, addr oldDacl)
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
    ## (preserving the inherited SYSTEM/Administrators grants). Idempotent:
    ## re-stamping the same grant is safe (SetEntriesInAcl merges).
    ## Raises OSError on any failed step.
    mergeDaclEntry(path, sid, mode, rights, inheritance)

  proc hasSidAce*(path: string; sid: PSID; rights: DWORD;
      inheritance: DWORD): bool =
    ## True when `path`'s DACL already carries an ALLOW ACE for `sid`
    ## covering `rights` with matching `inheritance`. Lets callers skip
    ## a redundant SetNamedSecurityInfoW, which on profile directories
    ## costs seconds (NTFS walks the subtree reconciling inheritable
    ## ACEs even when nothing changes).
    var oldDacl: PACL = nil
    let sd = readDacl(path, addr oldDacl)
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
      # Inheritance bits on a just-written ACE can differ from the
      # requested flags (container inherit vs object inherit after
      # SetNamedSecurityInfo). Any covering ALLOW ACE is enough to
      # skip a multi-minute subtree walk.
      discard inheritance
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
    let sd = readDacl(path, addr oldDacl)
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

proc backendName*(): string = "windows-acl"
