## Windows write-restricted-token + Job backend for sandwall.
##
## This replaces the AppContainer backend. AppContainer confines the
## process to a private object namespace, which kills the cygwin/msys2
## DLL at init (NtCreateDirectoryObject on \BaseNamedObjects\msys-2.0
## returns ACCESS_DENIED), so msys2 bash cannot run inside an AC. A
## write-restricted token is a NORMAL token (full object-namespace
## access), so cygwin survives; only file WRITES get the extra
## restricted-SID check. This is the Codex/Kilo/Anthropic mechanism.
##
## Enforcement model (unelevated, same-user):
##   1. CreateRestrictedToken(WRITE_RESTRICTED) with a restricted SID
##      list of [Everyone, Logon SID, synthetic-write SID]. A write then
##      succeeds only if the normal user AND at least one restricted SID
##      are granted. We ACL-grant the synthetic SID only on writable
##      roots, so everywhere else the second check fails even though the
##      user could normally write there.
##   2. The synthetic SID is a stable, well-known SID derived once and
##      reused across runs so ACL grants persist (no per-run stamping +
##      rollback of DACLs like the AC backend). We grant it broad write
##      on each writable root and leave it denied (absent) elsewhere.
##   3. Medium integrity is left intact (NOT Low): Schannel/LSA and the
##      cygwin object namespace misbehave at Low.
##   4. An unnamed Job Object with KILL_ON_JOB_CLOSE contains the whole
##      process tree; the child is assigned before it resumes.
##
## No ACL rollback is needed for the DACL grants: the synthetic SID only
## confers access to a token that carries it in the restricted list, so a
## grant on a writable root is inert for every normal process. We keep a
## module record of granted roots only to re-assert idempotently.
##
## Deny narrowing (policy `deny` under a writable root) is stamped as an
## explicit DENY ACE for the synthetic SID and rolled back after the run,
## because a lingering DENY would also block nothing else (the SID is
## ours) but is kept clean to avoid surprising the user.

import std/os

when defined(windows):
  import std/[winlean, widestrs, strutils, syncio]
  import ./acl  # reuse trustee/EXPLICIT_ACCESS/SetEntriesInAcl + rollback helpers
  import ./paths  # normalize

  # --- token FFI ---

  type
    SID_AND_ATTRIBUTES = object
      sid: winlean.PSID
      attributes: DWORD

    TOKEN_MANDATORY_LABEL = object
      label: SID_AND_ATTRIBUTES

    JOBOBJECT_BASIC_LIMIT_INFORMATION = object
      perProcessUserTimeLimit: int64
      perJobUserTimeLimit: int64
      limitFlags: DWORD
      minimumWorkingSetSize: uint
      maximumWorkingSetSize: uint
      activeProcessLimit: DWORD
      affinity: uint
      priorityClass: DWORD
      schedulingClass: DWORD

    IO_COUNTERS = object
      readOperationCount, writeOperationCount, otherOperationCount: uint64
      readTransferCount, writeTransferCount, otherTransferCount: uint64

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION = object
      basicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION
      ioInfo: IO_COUNTERS
      processMemoryLimit: uint
      jobMemoryLimit: uint
      peakProcessMemoryUsed: uint
      peakJobMemoryUsed: uint

  const
    # CreateRestrictedToken flags (winnt.h)
    DISABLE_MAX_PRIVILEGE = 0x1'i32
    WRITE_RESTRICTED      = 0x8'i32

    # Token access rights
    TOKEN_DUPLICATE        = 0x0002'i32
    TOKEN_QUERY            = 0x0008'i32
    TOKEN_ADJUST_DEFAULT   = 0x0080'i32
    TOKEN_ASSIGN_PRIMARY   = 0x0001'i32
    TOKEN_ADJUST_PRIVILEGES = 0x0020'i32
    TOKEN_ALL_ACCESS_RW    = 0x000F01FF'i32

    # Token information classes
    tokenIntegrityLevel = 25'i32
    tokenDefaultDacl     = 6'i32
    SE_GROUP_INTEGRITY   = 0x00000020'i32

    # ACL header size (ACL struct, winnt.h)
    ACL_REVISION = 2'i32

    # Job objects
    jobObjectExtendedLimitInformation = 9'i32
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000'i32

    # Process creation flags
    CREATE_SUSPENDED = 0x00000004'i32

    # Well-known SID strings
    sidEveryone = "S-1-1-0"
    # Stable synthetic SID for sandwall writable roots. Must be in the
    # NT-authority domain range (S-1-5-21-...): app-package (S-1-15-2-*) and
    # capability (S-1-15-3-*) SIDs are rejected by CreateRestrictedToken with
    # ERROR_INVALID_PARAMETER on Win11 (verified by probe rtprobe2), while
    # S-1-5-21-* is accepted and valid in ACLs. The high subauthorities make
    # collision with a real domain SID vanishingly unlikely. We use it as a
    # plain restricted SID in a NORMAL token (not an AC), keeping cygwin alive.
    sidSandwallWrite = "S-1-5-21-3738981842-2241542906-1872314022-4093"

  proc convertStringSidToSidW(s: WideCString; sid: ptr winlean.PSID): WINBOOL
      {.stdcall, dynlib: "advapi32", importc: "ConvertStringSidToSidW".}

  proc createRestrictedToken(existingToken: Handle; flags: DWORD;
      disableSidCount: DWORD; sidsToDisable: ptr SID_AND_ATTRIBUTES;
      deletePrivilegeCount: DWORD; privilegesToDelete: pointer;
      restrictedSidCount: DWORD; sidsToRestrict: ptr SID_AND_ATTRIBUTES;
      newToken: ptr Handle): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "CreateRestrictedToken".}

  proc createProcessAsUserW(token: Handle; appName, cmdLine: WideCString;
      procAttr, threadAttr: ptr SECURITY_ATTRIBUTES; inheritHandles: WINBOOL;
      flags: DWORD; env: pointer; cwd: WideCString; si: ptr STARTUPINFO;
      pi: ptr PROCESS_INFORMATION): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "CreateProcessAsUserW", sideEffect.}

  proc openProcessToken(processHandle: Handle; desiredAccess: DWORD;
      tokenHandle: ptr Handle): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "OpenProcessToken".}

  proc setTokenInformation(token: Handle; infoClass: int32;
      info: pointer; infoLen: DWORD): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "SetTokenInformation".}

  proc createJobObjectW(attr: pointer; name: WideCString): Handle {.stdcall,
      dynlib: "kernel32", importc: "CreateJobObjectW".}

  proc setInformationJobObject(job: Handle; infoClass: int32; info: pointer;
      infoLen: DWORD): WINBOOL {.stdcall, dynlib: "kernel32",
      importc: "SetInformationJobObject".}

  proc assignProcessToJobObject(job, process: Handle): WINBOOL {.stdcall,
      dynlib: "kernel32", importc: "AssignProcessToJobObject".}

  proc getTokenInformation(token: Handle; infoClass: int32; info: pointer;
      infoLen: DWORD; retLen: ptr DWORD): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "GetTokenInformation".}

  proc resumeThread(thread: Handle): DWORD {.stdcall, dynlib: "kernel32",
      importc: "ResumeThread".}

  proc initializeAcl(acl: pointer; aclLength: DWORD; revision: DWORD): WINBOOL
      {.stdcall, dynlib: "advapi32", importc: "InitializeAcl".}

  proc addAccessAllowedAce(acl: pointer; revision, accessMask: DWORD;
      sid: winlean.PSID): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "AddAccessAllowedAce".}

  proc getLengthSid(sid: winlean.PSID): DWORD {.stdcall, dynlib: "advapi32",
      importc: "GetLengthSid".}

  proc copySid(destLen: DWORD; dest, src: winlean.PSID): WINBOOL {.stdcall,
      dynlib: "advapi32", importc: "CopySid".}

  proc localFree(mem: pointer): pointer {.stdcall, dynlib: "kernel32",
      importc: "LocalFree".}

  proc fail(what: string) {.noinline.} =
    raise newException(OSError,
      "sandwall windows-rtoken: " & what & " failed (error " & $getLastError() & ")")

  # --- module state ---

  # The synthetic write SID, derived once. Kept for the process lifetime.
  var writeSid: winlean.PSID = nil

  # Writable roots we granted the synthetic SID on (for potential cleanup).
  var grantedRoots: seq[string] = @[]

  # Deny paths we stamped (policy `deny` narrowing); rolled back post-run.
  var denyStamped: seq[string] = @[]

  proc sandwallWriteSid*(): winlean.PSID =
    ## Return the stable synthetic SID used to mark writable roots.
    if writeSid == nil:
      if convertStringSidToSidW(newWideCString(sidSandwallWrite),
          addr writeSid) == 0:
        fail("ConvertStringSidToSidW(write SID)")
    writeSid

  proc grantWriteRoot(path: string) =
    ## Grant the synthetic write SID full access on `path` (recursive).
    ## Idempotent; the grant is inert for non-restricted processes so we do
    ## NOT roll it back (unlike the AC backend's DACL stamps).
    acl.stampAce(path, sandwallWriteSid(), acl.grantAccess, acl.FILE_ALL_ACCESS)
    grantedRoots.add(path)

  proc stampDeny(path: string) =
    ## Stamp an explicit DENY-all ACE for the synthetic SID on `path`
    ## (policy `deny` under a writable root). Rolled back after the run.
    acl.stampAce(path, sandwallWriteSid(), acl.denyAccess, acl.FILE_ALL_ACCESS)
    denyStamped.add(path)

  proc rollbackDenies*() =
    ## Remove the DENY ACEs stamped for this run. Best-effort.
    let sid = sandwallWriteSid()
    let paths = denyStamped
    denyStamped = @[]
    for p in paths:
      try:
        acl.removeSidAces(p, sid)
      except CatchableError as e:
        stderr.writeLine("sandwall windows-rtoken: deny rollback failed on " &
          p & ": " & e.msg)

  proc restrictImpl*(writable, read: openArray[string];
                     denied: openArray[string] = []) =
    ## Stamp ACL grants for the synthetic write SID on each writable root
    ## and DENY stamps for the policy's denied narrowing. The actual token
    ## is built at spawn time in process.spawnSandboxed. `read` paths need
    ## no stamp: a restricted token only gates WRITES, and reads ride the
    ## normal user DACL (the child keeps the user's identity).
    let norm = paths.normalize
    var seen: seq[string] = @[]
    for p in writable:
      let n = norm(p)
      if n.len == 0 or n in seen: continue
      seen.add(n)
      grantWriteRoot(n)
    for d in denied:
      let n = norm(d)
      if n.len == 0: continue
      stampDeny(n)

  proc buildWriteRestrictedToken(): Handle =
    ## Build the write-restricted token from the current process token:
    ## WRITE_RESTRICTED with restricted SIDs [synthetic, Logon, Everyone].
    ## Strips privileges (DISABLE_MAX_PRIVILEGE) but keeps the token
    ## Medium IL with normal groups so cygwin init works. NO LUA_TOKEN:
    ## it broke schannel inside the sandbox (SEC_E_NO_CREDENTIALS on
    ## AcquireCredentialsHandle, every https site, verified on Win11).
    var token: Handle
    if openProcessToken(getCurrentProcess(),
        DWORD(TOKEN_DUPLICATE or TOKEN_QUERY or TOKEN_ASSIGN_PRIMARY or
              TOKEN_ADJUST_DEFAULT), addr token) == 0:
      fail("OpenProcessToken")
    defer: discard closeHandle(token)

    # Recipe mirrors Codex windows-sandbox-rs/src/token.rs.
    var everyoneSid, sandSid: winlean.PSID
    if convertStringSidToSidW(newWideCString(sidEveryone), addr everyoneSid) == 0:
      fail("ConvertStringSidToSidW(Everyone)")
    sandSid = sandwallWriteSid()

    # The logon-session SID must come from TokenGroups (scanning for a group
    # with SE_GROUP_LOGON_ID = 0xC0000000), NOT TokenLogonSid: the latter
    # returns a SID CreateRestrictedToken rejects with ERROR_NOACCESS on
    # Win11 (verified by probe rt3). TokenGroups layout is a DWORD count
    # followed by the SID_AND_ATTRIBUTES array ALIGNED to pointer size (8 on
    # amd64) - reading the SID at +4 picks up garbage (the other 998 cause).
    const tokenGroups = 2'i32
    const SE_GROUP_LOGON_ID = 0xC0000000'i32
    var logonSidVal: winlean.PSID = nil
    var logonBuf: pointer = nil
    var needed: DWORD = 0
    discard getTokenInformation(token, tokenGroups, nil, 0, addr needed)
    if needed > 0:
      logonBuf = alloc0(int(needed))
      if getTokenInformation(token, tokenGroups, logonBuf, needed, addr needed) != 0:
        let count = cast[ptr DWORD](logonBuf)[]
        # align(sizeof(DWORD)=4 up to sizeof(pointer)=8) = 8 on amd64
        var gptr = cast[uint](logonBuf) + cast[uint](sizeof(pointer))
        for i in 0 ..< int(count):
          let grp = cast[ptr SID_AND_ATTRIBUTES](gptr)
          if (grp.attributes and SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID:
            logonSidVal = grp.sid
            break
          gptr += cast[uint](sizeof(SID_AND_ATTRIBUTES))

    # The token user SID (TokenUser = 1), copied out so it stays valid after
    # the source token closes. It goes into the token's DEFAULT DACL only,
    # NEVER into the restricted-SID list: a write-restricted token grants a
    # write only when the normal SIDs AND some restricted SID both allow
    # it, so a user SID in the restricted list makes every user-writable
    # path writable and the whole sandbox a no-op (verified on Win11:
    # home-dir writes leaked; probe rt5's "with-user works" fixed cygwin
    # by accident and reintroduced the hole). Cygwin's named objects are
    # covered by the default-DACL entries below, not by the restricted list.
    const tokenUser = 1'i32
    var userSidVal: winlean.PSID = nil
    var uneeded: DWORD = 0
    discard getTokenInformation(token, tokenUser, nil, 0, addr uneeded)
    if uneeded > 0:
      let ubuf = alloc0(int(uneeded))
      if getTokenInformation(token, tokenUser, ubuf, uneeded, addr uneeded) != 0:
        let usid = cast[ptr SID_AND_ATTRIBUTES](ubuf).sid
        let ulen = getLengthSid(usid)
        userSidVal = cast[winlean.PSID](alloc0(int(ulen)))
        discard copySid(ulen, userSidVal, usid)
      dealloc(ubuf)

    # Restricted SID list order: [synthetic-write, Logon, Everyone].
    var restrictSids: seq[SID_AND_ATTRIBUTES]
    restrictSids.add SID_AND_ATTRIBUTES(sid: sandSid, attributes: 0)
    if logonSidVal != nil:
      restrictSids.add SID_AND_ATTRIBUTES(sid: logonSidVal, attributes: 0)
    restrictSids.add SID_AND_ATTRIBUTES(sid: everyoneSid, attributes: 0)

    var newToken: Handle
    let rc = createRestrictedToken(token,
        DWORD(DISABLE_MAX_PRIVILEGE or WRITE_RESTRICTED),
        0, nil, 0, nil, DWORD(restrictSids.len), addr restrictSids[0], addr newToken)
    if rc == 0:
      if logonBuf != nil: dealloc(logonBuf)
      fail("CreateRestrictedToken")

    # Default DACL = GENERIC_ALL for [Logon, Everyone, synthetic-write] (the
    # logon SID first, matching Codex). Cygwin's signal pipe and other named
    # objects are created with the token's default DACL; without these grants
    # the restricted access check fails and cygwin dies "couldn't create
    # signal pipe, Win32 error 5". Build it with SetEntriesInAcl (a fresh
    # ACL), like Codex, rather than hand-rolled InitializeAcl+AddAce.
    var daclSids: seq[winlean.PSID]
    if logonSidVal != nil: daclSids.add logonSidVal
    daclSids.add everyoneSid
    daclSids.add sandSid
    if userSidVal != nil: daclSids.add userSidVal
    var entries: seq[acl.EXPLICIT_ACCESS_W]
    for s in daclSids:
      entries.add acl.buildDefaultDaclEntry(s)
    var newDacl: acl.PACL = nil
    if acl.setEntriesInAcl(DWORD(entries.len), addr entries[0], nil,
        addr newDacl) != 0:
      if logonBuf != nil: dealloc(logonBuf)
      discard closeHandle(newToken)
      fail("SetEntriesInAcl(default DACL)")
    # TokenDefaultDacl takes a TOKEN_DEFAULT_DACL struct = a single PACL field.
    var tdd: pointer = newDacl
    if setTokenInformation(newToken, tokenDefaultDacl, addr tdd,
        DWORD(sizeof(pointer))) == 0:
      if logonBuf != nil: dealloc(logonBuf)
      discard closeHandle(newToken)
      fail("SetTokenInformation(TokenDefaultDacl)")
    discard localFree(newDacl)
    if logonBuf != nil: dealloc(logonBuf)
    newToken

  proc ensureJob(): Handle =
    ## Create an unnamed Job Object with KILL_ON_JOB_CLOSE so the whole
    ## child tree dies with the parent handle.
    let job = createJobObjectW(nil, nil)
    if job == 0: fail("CreateJobObjectW")
    var info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    zeroMem(addr info, sizeof(info))
    info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if setInformationJobObject(job, jobObjectExtendedLimitInformation,
        addr info, DWORD(sizeof(info))) == 0:
      discard closeHandle(job)
      fail("SetInformationJobObject")
    job

  proc spawnSandboxed*(cmd: openArray[string]): Handle =
    ## Spawn `cmd` under a write-restricted token inside a KILL_ON_JOB_CLOSE
    ## Job. Returns the process handle (caller waits/reads exit code and
    ## closes both it and, implicitly via Job, the tree). Cygwin survives
    ## because the token is a normal-namespace Medium-IL token.
    if cmd.len == 0:
      raise newException(ValueError, "sandwall.spawnSandboxed: empty command")
    let token = buildWriteRestrictedToken()
    defer: discard closeHandle(token)
    let job = ensureJob()
    # The Job handle must outlive the child for KILL_ON_JOB_CLOSE to mean
    # anything; we leak it into the process (never closed) so the tree is
    # killed only when THIS process exits. Acceptable: one Job per run.

    var cmdLine = ""
    for i, a in cmd:
      if i > 0: cmdLine.add(' ')
      cmdLine.add(quoteShellWindows(a))
    let cmdLineW = newWideCString(cmdLine)

    var si: STARTUPINFO
    zeroMem(addr si, sizeof(si))
    si.cb = DWORD(sizeof(si))
    si.dwFlags = DWORD(STARTF_USESTDHANDLES)
    si.hStdInput = getStdHandle(STD_INPUT_HANDLE)
    si.hStdOutput = getStdHandle(STD_OUTPUT_HANDLE)
    si.hStdError = getStdHandle(STD_ERROR_HANDLE)
    var pi: PROCESS_INFORMATION
    let cwdW = newWideCString(getCurrentDir())
    # CREATE_SUSPENDED so we can assign to the Job before any user code runs.
    if createProcessAsUserW(token, nil, cmdLineW, nil, nil, 1,
        DWORD(CREATE_SUSPENDED), nil, cwdW, addr si, addr pi) == 0:
      fail("CreateProcessAsUserW")
    if assignProcessToJobObject(job, pi.hProcess) == 0:
      discard closeHandle(pi.hProcess)
      discard closeHandle(pi.hThread)
      fail("AssignProcessToJobObject")
    discard resumeThread(pi.hThread)
    discard closeHandle(pi.hThread)
    pi.hProcess

proc backendSupported*(): bool =
  when defined(windows): true else: false

proc backendName*(): string = "windows-writerestricted"
