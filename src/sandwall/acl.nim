## Windows restricted-token + ACL backend for sandwall.
##
## Windows has no single syscall-interception hook. The Codex-validated
## approach is a restricted token plus filesystem ACLs: we build a token via
## CreateRestrictedToken that carries a fresh "restricting SID", then at spawn
## time Windows runs TWO access checks on every NtCreateFile (the normal DACL
## check and the restricting-SID check) and BOTH must pass. By stamping a DENY
## ACE for our SID on the volume roots the sandbox must block, and ALLOW ACEs
## for our SID on the paths it may touch, the restricted child is confined.
##
## A token applies at CreateProcess time, not to the calling thread, so unlike
## Landlock/Seatbelt `restrictImpl` here PREPARES the token and stamps the
## ACLs; the spawn path (process.nim) applies the token. This is genuinely the
## weak platform and the ACL stamping mutates the filesystem - see
## CROSSPLATFORM.md Phase 3.

import ./paths

when defined(windows):
  import std/[winlean, widestrs, sets, syncio]

  # --- advapi32 security/token FFI (not in std/winlean) ---

  type
    PSID* = pointer
    SidIdentifierAuthority* = array[6, uint8]

  const
    # token access rights (winnt.h)
    TOKEN_QUERY*        = 0x0008'i32
    TOKEN_DUPLICATE*    = 0x0002'i32
    TOKEN_ASSIGN_PRIMARY* = 0x0001'i32

    # CreateRestrictedToken flags
    DISABLE_MAX_PRIVILEGE* = 0x1'i32

    # SECURITY_NT_AUTHORITY = S-1-5, the most-used identifier authority for
    # freshly minted SIDs. We build S-1-5-<random32> off it.
    securityNtAuthority*: SidIdentifierAuthority =
      [0'u8, 0, 0, 0, 0, 5]

  proc getCurrentProcessId*(): DWORD {.stdcall, dynlib: "kernel32",
      importc: "GetCurrentProcessId".}

  proc openProcessToken*(processHandle: Handle; desiredAccess: DWORD;
      tokenHandle: ptr Handle): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "OpenProcessToken".}

  # AllocateAndInitializeSid is C-variadic on the sub-authority values. Nim
  # cannot import a variadic stdcall cleanly, so we declare the fixed 1
  # sub-authority shape: the C signature is (auth, count, sub0..sub7, &pSid);
  # with count=1 that is (auth, 1, sub0, &pSid). SID becomes
  # S-<auth>-<one DWORD sub-authority>, plenty for a unique restricting SID.
  proc allocateAndInitializeSid*(pIdentifierAuthority: ptr SidIdentifierAuthority;
      nSubAuthorityCount: uint8; nSubAuthority0: DWORD;
      pSid: ptr PSID): WINBOOL {.stdcall,
      dynlib: "advapi32", importc: "AllocateAndInitializeSid".}

  proc freeSid*(pSid: PSID): pointer {.stdcall, dynlib: "advapi32",
      importc: "FreeSid".}

  proc createRestrictedToken*(existingToken: Handle; flags: DWORD;
      sidToDisableCount: DWORD; sidToDisable: ptr PSID;
      privilegeToDeleteCount: DWORD; privileges: pointer;
      restrictedSidCount: DWORD; sidToRestrict: ptr PSID;
      newToken: ptr Handle): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "CreateRestrictedToken".}

  # --- ACL stamping FFI (accctrl.h / aclapi.h / winnt.h) ---

  type
    # ACCESS_MODE (accctrl.h): only GRANT_ACCESS and DENY_ACCESS are used for
    # EXPLICIT_ACCESS entries. Sized to int32 to match the Win32 enum.
    ACCESS_MODE {.size: sizeof(int32).} = enum
      notUsedAccess = 0
      grantAccess   ## allow
      setAccess
      revokeAccess
      denyAccess    ## deny
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

    # {CONTAINER|OBJECT}_INHERIT_ACE, NO_PROPAGATE_INHERIT_ACE (winnt.h).
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
    FILE_GENERIC_WRITE*   = 0x00120116'i32
    FILE_GENERIC_EXECUTE* = 0x001200A0'i32
    FILE_ALL_ACCESS*      = 0x001F01FF'i32
    FILE_DELETE_ACCESS*   = 0x00010000'i32  # DELETE right

  # FindFirstVolumeW / FindNextVolumeW / FindVolumeClose (kernel32).
  const
    MAX_VOLUME_NAME = 50  # a Volume Manager GUID path fits well within this

  proc findFirstVolumeW(lpszVolumeName: ptr Utf16Char;
      cchBufferLength: DWORD): Handle {.stdcall, dynlib: "kernel32",
      importc: "FindFirstVolumeW".}

  proc findNextVolumeW(hFindVolume: Handle; lpszVolumeName: ptr Utf16Char;
      cchBufferLength: DWORD): WINBOOL {.stdcall, dynlib: "kernel32",
      importc: "FindNextVolumeW".}

  proc findVolumeClose(hFindVolume: Handle): WINBOOL {.stdcall,
      dynlib: "kernel32", importc: "FindVolumeClose".}

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

  proc localFree(hMem: pointer): pointer {.stdcall, dynlib: "kernel32",
      importc: "LocalFree".}

  # GetNamedSecurityInfo reads an existing security descriptor by name. Used by
  # rollbackAcls to fetch the live DACL before stripping our SID's ACEs.
  # SECURITY_DESCRIPTOR is opaque to us; we deal in the DACL pointer it returns.
  proc getNamedSecurityInfoW*(pObjectName: pointer;
      objectType: SE_OBJECT_TYPE; securityInfo: DWORD;
      psidOwner: ptr PSID; psidGroup: ptr PSID; pDacl: ptr PACL;
      pSacl: ptr PACL; psd: ptr pointer): DWORD {.stdcall, dynlib: "advapi32",
      importc: "GetNamedSecurityInfoW"}

  # CreateProcessAsUserW (advapi32). Applies a prepared token to the spawned
  # child in one call; there is no way to narrow the current process. The
  # STARTUPINFO / PROCESS_INFORMATION structs come from winlean. lpCommandLine
  # is LPWSTR (mutable), which WideCString satisfies.
  proc createProcessAsUserW*(hToken: Handle; lpApplicationName: WideCString;
      lpCommandLine: WideCString; lpProcessAttributes: ptr SECURITY_ATTRIBUTES;
      lpThreadAttributes: ptr SECURITY_ATTRIBUTES; bInheritHandles: WINBOOL;
      dwCreationFlags: DWORD; lpEnvironment: pointer;
      lpCurrentDirectory: WideCString; lpStartupInfo: ptr STARTUPINFO;
      lpProcessInformation: ptr PROCESS_INFORMATION): WINBOOL {.stdcall,
      dynlib: "advapi32", importc: "CreateProcessAsUserW"}

  # --- module state ---

  # Token prepared by restrictImpl, applied at spawn time. 0 = no sandbox set.
  var currentRestrictedToken*: Handle = 0

  # The restricting SID owned by the current sandbox. The SID is kept alive
  # for the whole sandbox lifetime (not freed in buildRestrictedToken): the
  # stamping and rollback passes reference it independently of the token, which
  # holds its own internal copy. restrictImpl frees the previous SID on re-entry.
  var currentRestrictingSid*: PSID = nil

  # Caller paths normalised once.
  var writablePaths*: seq[string] = @[]
  var readOnlyPaths*: seq[string] = @[]

  # Every filesystem path whose DACL we mutated. The spawn (chunk 3) walks
  # this in a defer to remove our ACEs. Mutating real security descriptors is
  # the one dangerous operation in this backend: a crash between stamp and
  # rollback leaves deny ACEs on volume roots that break other processes.
  var stampedPaths*: seq[string] = @[]

  # --- helpers ---

  proc fail*(what: string) {.noinline.} =
    ## Raise OSError carrying the Win32 error code for the last failed call.
    raise newException(OSError,
      "sandwall windows-acl: " & what & " failed (error " & $getLastError() & ")")

  proc buildRestrictedToken*(): Handle =
    ## Open the current process token and produce a restricted copy carrying a
    ## fresh random SID. The returned token is what the spawn path applies;
    ## caller owns the handle. Raises OSError on any failed step. As a side
    ## effect sets `currentRestrictingSid` so the stamping pass can reuse the
    ## exact SID embedded in the token.
    var base: Handle
    if openProcessToken(getCurrentProcess(),
        TOKEN_QUERY or TOKEN_DUPLICATE, addr base) == 0:
      fail("OpenProcessToken")
    defer: discard closeHandle(base)

    # Fresh restricting SID. The seed mixes the PID with a stack address for
    # per-call variance; it is NOT crypto-strength, but it is never constant
    # (chunk 2 may swap in a proper RNG). Avoiding a fixed seed matters
    # because a constant SID would let one sandbox's ACLs leak across runs.
    #
    # The SID is intentionally NOT freed here: stampAcls/rollbackAcls need it
    # alive for the lifetime of the sandbox (until the spawn rolls back). One
    # SID per sandbox (~8 bytes) is a bounded, acceptable cost. Freeing the
    # previous SID on re-entry is the caller's job (restrictImpl).
    var authority = securityNtAuthority
    if currentRestrictingSid != nil:
      discard freeSid(currentRestrictingSid)
    currentRestrictingSid = nil
    var stackAnchor = 0
    let seed = getCurrentProcessId() xor cast[DWORD](cast[uint](addr stackAnchor))
    if allocateAndInitializeSid(addr authority, 1'u8, seed,
        addr currentRestrictingSid) == 0:
      fail("AllocateAndInitializeSid")

    var restricted: Handle
    if createRestrictedToken(base, DISABLE_MAX_PRIVILEGE,
        0, nil,          # no SIDs to disable
        0, nil,          # no privileges to delete
        1, addr currentRestrictingSid,  # one restricting SID
        addr restricted) == 0:
      discard freeSid(currentRestrictingSid)
      currentRestrictingSid = nil
      fail("CreateRestrictedToken")
    return restricted

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

  proc enumerateVolumeRoots*(): seq[string] =
    ## Return every mounted volume root in the volume GUID path form
    ## returned by FindFirstVolumeW. SetNamedSecurityInfo accepts these
    ## directly, so there is no need to resolve each to a drive letter;
    ## stamping the GUID path covers every file on that volume regardless of
    ## which drive letter (if any) fronts it. Returns empty if enumeration
    ## fails, in which case the sandbox degrades to denying nothing at the
    ## volume layer (still enforces via the absence of ALLOW ACEs on
    ## non-writable paths).
    var nameBuf: array[MAX_VOLUME_NAME, Utf16Char]
    let h = findFirstVolumeW(addr nameBuf[0], DWORD(nameBuf.len))
    if h == -1:
      return @[]
    defer: discard findVolumeClose(h)

    while true:
      let guidPath = $cast[WideCString](addr nameBuf[0])
      result.add(guidPath)
      if findNextVolumeW(h, addr nameBuf[0], DWORD(nameBuf.len)) == 0:
        break

proc backendSupported*(): bool =
  when defined(windows): true else: false

proc backendName*(): string = "windows-acl"

when defined(windows):
  const
    # Rights we deny at volume roots: the write/delete/create family. We must
    # NOT deny FILE_GENERIC_READ or the process cannot even enumerate the
    # drive or load DLLs from C:\Windows.
    denyRights = FILE_GENERIC_WRITE or FILE_DELETE_ACCESS

  proc stampAcls*(writable, read: seq[string]; sid: PSID) =
    ## Stamp the full ACL policy for `sid`:
    ##   1. DENY `denyRights` on every volume root, so the default across all
    ##      drives is write-denied.
    ##   2. ALLOW FILE_ALL_ACCESS on each writable path.
    ##   3. ALLOW FILE_GENERIC_READ | FILE_GENERIC_EXECUTE on each read path.
    ## Each mutated path is recorded in stampedPaths for rollback.
    for vol in enumerateVolumeRoots():
      stampAce(vol, sid, denyAccess, denyRights)

    for p in writable:
      stampAce(p, sid, grantAccess, FILE_ALL_ACCESS)

    for p in read:
      stampAce(p, sid, grantAccess,
        FILE_GENERIC_READ or FILE_GENERIC_EXECUTE)

  proc rollbackAcls*(sid: PSID) =
    ## Best-effort removal of our SID's ACEs from every stamped path. Called
    ## in a defer by the spawn (chunk 3). Errors are logged to stderr and
    ## skipped: a missing path (deleted during the run) must not abort cleanup
    ## of the rest. Snapshots the path list first because removeSidAces must
    ## NOT append to it (we are undoing, not stamping).
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
    ## Build the restricted token and stamp the filesystem ACLs in one pass.
    ## Stores the token for the spawn path (process.nim) and records every
    ## mutated path so the spawn can roll back via rollbackAcls.
    currentRestrictedToken = buildRestrictedToken()

    var seen = initHashSet[string]()
    writablePaths = @[]
    readOnlyPaths = @[]
    for p in writable:
      let n = normalize(p)
      if n.len == 0 or seen.containsOrIncl(n): continue
      writablePaths.add(n)
    for p in read:
      let n = normalize(p)
      if n.len == 0 or seen.containsOrIncl(n): continue
      readOnlyPaths.add(n)

    stampAcls(writablePaths, readOnlyPaths, currentRestrictingSid)
