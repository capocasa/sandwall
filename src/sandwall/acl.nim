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
  import std/[winlean, widestrs, sets, syncio]

  # --- AppContainer profile FFI (userenv.dll) ---

  type
    PSID* = pointer
    # winlean has no HRESULT alias.
    HRESULT = int32

  # The profile APIs live in userenv.dll, not kernel32/advapi32.
  # CreateAppContainerProfile returns ERROR_ALREADY_EXISTS (0x800700b7)
  # when the profile exists from a previous run; the SID is then obtained
  # via DeriveAppContainerSidFromAppContainerName.
  proc createAppContainerProfile(name, display, desc: WideCString;
      caps: pointer; capCount: DWORD; sid: ptr PSID): HRESULT {.stdcall,
      dynlib: "userenv", importc: "CreateAppContainerProfile".}

  proc deriveAppContainerSidFromAppContainerName(name: WideCString;
      sid: ptr PSID): HRESULT {.stdcall, dynlib: "userenv",
      importc: "DeriveAppContainerSidFromAppContainerName".}

  proc localFree(hMem: pointer): pointer {.stdcall, dynlib: "kernel32",
      importc: "LocalFree".}

  # --- ACL stamping FFI (accctrl.h / aclapi.h / winnt.h) ---

  type
    # ACCESS_MODE (accctrl.h): GRANT_ACCESS for stamps, REVOKE_ACCESS for
    # rollback. Sized to int32 to match the Win32 enum.
    ACCESS_MODE {.size: sizeof(int32).} = enum
      notUsedAccess = 0
      grantAccess   ## allow
      setAccess
      revokeAccess  ## strip all existing ACEs for the trustee
      denyAccess    ## deny (unused: AppContainer denies by default)
      setAudit
      setAllAudit

    TRUSTEE_FORM {.size: sizeof(int32).} = enum
      trusteeIsSid = 0
      trusteeIsName
      trusteeBadForm
      trusteeIsObjectsAndSid
      trusteeIsObjectsAndName

    TRUSTEE_TYPE {.size: sizeof(int32).} = enum
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
    TRUSTEE_W {.bycopy.} = object
      pMultipleTrustee: pointer
      multipleTrusteeOperation: int32  # NO_MULTIPLE_TRUSTEE = 0
      trusteeForm: TRUSTEE_FORM
      trusteeType: TRUSTEE_TYPE
      ptstrName: pointer               # PSID when trusteeForm = TRUSTEE_IS_SID

    # Win32 EXPLICIT_ACCESS_W. Layout verified amd64: 48 bytes, trustee at 16.
    EXPLICIT_ACCESS_W {.bycopy.} = object
      grfAccessPermissions: DWORD
      grfAccessMode: ACCESS_MODE
      grfInheritance: DWORD
      trustee: TRUSTEE_W

    PACL = pointer

  const
    # SECURITY_INFORMATION flags (winnt.h)
    DACL_SECURITY_INFORMATION* = 0x00000004

    # File access masks (winnt.h)
    FILE_GENERIC_READ*    = 0x00120089'i32
    FILE_GENERIC_EXECUTE* = 0x001200A0'i32
    FILE_ALL_ACCESS*      = 0x001F01FF'i32

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

  # --- helpers ---

  proc fail*(what: string) {.noinline.} =
    ## Raise OSError carrying the Win32 error code for the last failed call.
    raise newException(OSError,
      "sandwall windows-acl: " & what & " failed (error " & $getLastError() & ")")

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

  proc buildExplicitAccess(sid: PSID; mode: ACCESS_MODE; rights: DWORD;
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

  proc stampAce*(path: string; sid: PSID; mode: ACCESS_MODE;
      rights: DWORD; inheritance = DWORD(subContainersAndObjectsInherit)) =
    ## Add an ACE for `sid` to `path`'s DACL. Merges a single EXPLICIT_ACCESS
    ## via SetEntriesInAcl (oldAcl=nil builds a fresh one containing just our
    ## entry), then writes the resulting DACL back with SetNamedSecurityInfo.
    ## Records `path` in stampedPaths. Raises OSError on any failed step.
    var ea = buildExplicitAccess(sid, mode, rights, inheritance)
    var newAcl: PACL = nil
    let rc = setEntriesInAcl(1, addr ea, nil, addr newAcl)
    if rc != 0:
      raise newException(OSError,
        "sandwall windows-acl: SetEntriesInAcl failed on " & path &
        " (error " & $rc & ")")
    # SetEntriesInAcl allocates with LocalAlloc; LocalFree releases it.
    defer: discard localFree(newAcl)
    writeDacl(path, newAcl)
    stampedPaths.add(path)

  proc removeSidAces(path: string; sid: PSID) =
    ## Strip every ACE whose trustee SID equals `sid` from `path`'s DACL.
    ## Reads the live DACL via GetNamedSecurityInfo, removes matching ACEs
    ## with SetEntriesInAcl (REVOKE_ACCESS removes all existing ACEs for the
    ## trustee before the merge), and writes the result back. This is the
    ## only safe rollback primitive: it preserves every ACE that is not ours.
    var dacl: PACL = nil
    var sd: pointer = nil
    let wpathObj = newWideCString(path)
    let wpath: WideCString = wpathObj
    let rc = getNamedSecurityInfoW(cast[pointer](wpath), seFileObject,
      DACL_SECURITY_INFORMATION, nil, nil, addr dacl, nil, addr sd)
    if rc != 0:
      raise newException(OSError,
        "sandwall windows-acl: GetNamedSecurityInfo failed on " & path &
        " (error " & $rc & ")")
    defer: discard localFree(sd)

    var ea = buildExplicitAccess(sid, revokeAccess, 0, 0)
    var newAcl: PACL = nil
    let rc2 = setEntriesInAcl(1, addr ea, dacl, addr newAcl)
    if rc2 != 0:
      raise newException(OSError,
        "sandwall windows-acl: SetEntriesInAcl(REVOKE) failed on " & path &
        " (error " & $rc2 & ")")
    defer: discard localFree(newAcl)
    writeDacl(path, newAcl)

proc backendSupported*(): bool =
  when defined(windows): true else: false

proc backendName*(): string = "windows-appcontainer"

when defined(windows):
  proc stampAcls*(writable, read: seq[string]; sid: PSID) =
    ## Stamp the full ACL policy for the AppContainer SID:
    ##   1. ALLOW FILE_ALL_ACCESS on each writable path.
    ##   2. ALLOW FILE_GENERIC_READ | FILE_GENERIC_EXECUTE on each read path.
    ## No DENY stamps: the AppContainer denies everything it is not granted,
    ## so volume roots need no touching. Each mutated path is recorded in
    ## stampedPaths for rollback.
    for p in writable:
      stampAce(p, sid, grantAccess, FILE_ALL_ACCESS)

    for p in read:
      stampAce(p, sid, grantAccess,
        FILE_GENERIC_READ or FILE_GENERIC_EXECUTE)

  proc rollbackAcls*(sid: PSID) =
    ## Best-effort removal of our SID's ACEs from every stamped path. Called
    ## in a defer by the spawn. Errors are logged to stderr and skipped: a
    ## missing path (deleted during the run) must not abort cleanup of the
    ## rest. Snapshots the path list first because removeSidAces must NOT
    ## append to it (we are undoing, not stamping).
    let paths = stampedPaths
    stampedPaths = @[]
    for path in paths:
      try:
        removeSidAces(path, sid)
      except CatchableError as e:
        stderr.writeLine("sandwall windows-acl: rollback failed on " & path &
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
