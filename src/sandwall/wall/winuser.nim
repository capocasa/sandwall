## winuser: the dedicated local user the Windows wall fences.
##
## The WFP fence (wfp.nim) keys its block filters on a user SID, so
## network-fenced children must run as a dedicated local user named
## `sandwall`. Setup is a one-time elevated, idempotent operation:
## create the user (or reset its password), mint a 32-char CSPRNG
## password, store it DPAPI-protected (CurrentUser scope) at
## %LOCALAPPDATA%\sandwall\credentials.dat, and hand the SID to
## wfp.installFence.
##
## Launch: `spawnAsSandwall` logs the user on with
## LOGON32_LOGON_NETWORK_CLEARTEXT / LOGON32_PROVIDER_WINNT50 and
## spawns via CreateProcessAsUserW. Cleartext network logon is chosen
## deliberately: no profile load is needed for a fenced batch-style
## child (INTERACTIVE would load one, BATCH denies the token some
## loopback paths), and the password never leaves the machine - it is
## the same shape srt-win uses.
##
## UNPLANNED: combining the fs sandbox (restricted token, acl.nim)
## with the net fence in ONE child - i.e. spawning a restricted-token
## process AS the sandwall user - is not designed yet. Today a caller
## picks one backend. See impl-plan.md locked decisions.

when defined(windows):
  import std/[winlean, widestrs, os, syncio, strutils]
  import ../acl
  import ./winffi
  import ./quotecmd

  {.passL: "-lnetapi32 -lbcrypt -lcrypt32".}

  const
    sandwallUserName* = "sandwall"
    passwordLen = 32
    # URL-safe base64-ish alphabet, 64 chars so password bytes map
    # uniformly (256 = 4 * 64) and nothing needs shell quoting.
    passwordAlphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    # NetUserAdd / NetUserSetInfo (lmaccess.h)
    UF_SCRIPT = 0x0001'u32
    UF_NORMAL_ACCOUNT = 0x0002'u32
    UF_DONT_EXPIRE_PASSWD = 0x10000'u32
    USER_PRIV_USER = 1'u32
    NERR_USER_EXISTS = 2224'u32

    # LogonUserW
    LOGON32_LOGON_NETWORK_CLEARTEXT = 3'u32
    LOGON32_PROVIDER_WINNT50 = 2'u32

    # DPAPI (dpapi.h)
    CRYPTPROTECT_UI_FORBIDDEN = 0x01'u32

    CREATE_NO_WINDOW = 0x08000000'u32
    INFINITE_MS = 0xFFFFFFFF'u32

    # OpenDesktopW access for rewriting the DACL (winnt.h)
    READ_CONTROL = 0x00020000'u32
    WRITE_DAC = 0x00040000'u32

  type
    USER_INFO_1 {.bycopy.} = object
      name: WideCString
      password: WideCString
      passwordAge: DWORD
      priv: DWORD
      homeDir: WideCString
      comment: WideCString
      flags: DWORD
      scriptPath: WideCString

    USER_INFO_1003 {.bycopy.} = object
      password: WideCString

    SID_NAME_USE {.size: sizeof(int32).} = enum
      sidTypeUser = 1
      sidTypeGroup
      sidTypeDomain
      sidTypeAlias
      sidTypeWellKnownGroup
      sidTypeDeletedAccount
      sidTypeInvalid
      sidTypeUnknown
      sidTypeComputer
      sidTypeLabel

    DATA_BLOB {.bycopy.} = object
      cbData: DWORD
      pbData: ptr byte

    LOCALGROUP_MEMBERS_INFO_3 {.bycopy.} = object
      lgrpi3DomainAndName: WideCString

  # --- FFI ---

  # Window station / desktop DACLs (user32 + advapi32). The enum value
  # SE_WINDOW_OBJECT = 7 in accctrl.h's SE_OBJECT_TYPE (acl.nim defines
  # the enum but only uses seFileObject, so the constant is local).
  const SE_WINDOW_OBJECT = 7'i32

  proc getProcessWindowStation(): Handle {.stdcall, dynlib: "user32",
      importc: "GetProcessWindowStation".}
  proc getThreadDesktop(threadId: DWORD): Handle {.stdcall, dynlib: "user32",
      importc: "GetThreadDesktop".}
  proc getCurrentThreadId(): DWORD {.stdcall, dynlib: "kernel32",
      importc: "GetCurrentThreadId".}
  proc openWindowStationW(name: WideCString; inherit: WINBOOL;
      desiredAccess: DWORD): Handle {.stdcall, dynlib: "user32",
      importc: "OpenWindowStationW".}
  proc closeWindowStation(h: Handle): WINBOOL {.stdcall, dynlib: "user32",
      importc: "CloseWindowStation".}
  proc openDesktopW(name: WideCString; flags: DWORD; inherit: WINBOOL;
      desiredAccess: DWORD): Handle {.stdcall, dynlib: "user32",
      importc: "OpenDesktopW".}
  proc closeDesktop(h: Handle): WINBOOL {.stdcall, dynlib: "user32",
      importc: "CloseDesktop".}
  proc getSecurityInfo(handle: Handle; objType: int32;
      secInfo: DWORD; sidOwner, sidGroup: ptr winffi.PSID; dacl, sacl: ptr acl.PACL;
      sd: ptr pointer): DWORD {.stdcall, dynlib: "advapi32",
      importc: "GetSecurityInfo".}
  proc setSecurityInfo(handle: Handle; objType: int32;
      secInfo: DWORD; sidOwner, sidGroup: winffi.PSID; dacl, sacl: acl.PACL): DWORD
      {.stdcall, dynlib: "advapi32", importc: "SetSecurityInfo".}

  proc netLocalGroupAddMembers(serverName: WideCString;
      groupName: WideCString; level: DWORD; buf: pointer;
      totalEntries: DWORD): DWORD {.stdcall, dynlib: "netapi32",
      importc: "NetLocalGroupAddMembers".}

  proc netUserAdd(serverName: WideCString; level: DWORD;
      buf: pointer; parmErr: ptr DWORD): DWORD {.stdcall,
      dynlib: "netapi32", importc: "NetUserAdd".}
  proc netUserSetInfo(serverName: WideCString; userName: WideCString;
      level: DWORD; buf: pointer; parmErr: ptr DWORD): DWORD {.stdcall,
      dynlib: "netapi32", importc: "NetUserSetInfo".}

  proc lookupAccountNameW(systemName: WideCString;
      accountName: WideCString; sid: pointer; cbSid: ptr DWORD;
      referencedDomainName: WideCString; cchReferencedDomainName: ptr DWORD;
      peUse: ptr SID_NAME_USE): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "LookupAccountNameW".}
  # convertSidToStringSidW is shared in winffi; localFree comes from winlean.

  proc bcryptGenRandom(hAlgorithm: pointer; pbBuffer: ptr byte;
      cbBuffer: uint32; dwFlags: uint32): int32 {.stdcall,
      dynlib: "bcrypt", importc: "BCryptGenRandom".}

  proc cryptProtectData(pDataIn: ptr DATA_BLOB;
      szDataDescr: WideCString; pOptionalEntropy: pointer;
      pvReserved: pointer; pPromptStruct: pointer; dwFlags: DWORD;
      pDataOut: ptr DATA_BLOB): WINBOOL {.stdcall, dynlib: "crypt32",
      importc: "CryptProtectData".}
  proc cryptUnprotectData(pDataIn: ptr DATA_BLOB;
      ppszDataDescr: pointer; pOptionalEntropy: pointer;
      pvReserved: pointer; pPromptStruct: pointer; dwFlags: DWORD;
      pDataOut: ptr DATA_BLOB): WINBOOL {.stdcall, dynlib: "crypt32",
      importc: "CryptUnprotectData".}

  proc logonUserW*(lpszUsername: WideCString; lpszDomain: WideCString;
      lpszPassword: WideCString; dwLogonType: DWORD;
      dwLogonProvider: DWORD; phToken: ptr Handle): WINBOOL {.stdcall,
      dynlib: "advapi32", importc: "LogonUserW".}
  proc createProcessAsUserW*(hToken: Handle;
      lpApplicationName: WideCString; lpCommandLine: WideCString;
      lpProcessAttributes: ptr SECURITY_ATTRIBUTES;
      lpThreadAttributes: ptr SECURITY_ATTRIBUTES;
      bInheritHandles: WINBOOL; dwCreationFlags: DWORD;
      lpEnvironment: pointer; lpCurrentDirectory: WideCString;
      lpStartupInfo: ptr STARTUPINFO;
      lpProcessInformation: ptr PROCESS_INFORMATION): WINBOOL {.stdcall,
      dynlib: "advapi32", importc: "CreateProcessAsUserW".}
  proc waitForSingleObject(hHandle: Handle;
      dwMilliseconds: DWORD): DWORD {.stdcall, dynlib: "kernel32",
      importc: "WaitForSingleObject".}
  proc getExitCodeProcess(hProcess: Handle;
      lpExitCode: ptr DWORD): WINBOOL {.stdcall, dynlib: "kernel32",
      importc: "GetExitCodeProcess".}

  proc fail*(what: string) {.noinline.} =
    raise newException(OSError, "sandwall winuser: " & what &
      " failed (win32 error " & $getLastError() & ")")

  proc randomPassword(): string =
    ## 32 chars from a 64-char alphabet via BCryptGenRandom with the
    ## system-preferred RNG (flag 0x2, no algorithm handle).
    var bytes: array[passwordLen, byte]
    if bcryptGenRandom(nil, addr bytes[0], passwordLen.uint32, 2'u32) != 0:
      fail("BCryptGenRandom")
    result = newString(passwordLen)
    for i in 0 ..< passwordLen:
      result[i] = passwordAlphabet[bytes[i].int and 63]

  proc credPath(): string =
    let base = getEnv("LOCALAPPDATA",
      getEnv("USERPROFILE") / "AppData" / "Local")
    base / "sandwall"

  proc storePassword(password: string) =
    ## DPAPI-protect (CurrentUser scope, UI forbidden) and write the
    ## blob to %LOCALAPPDATA%\sandwall\credentials.dat.
    var input = DATA_BLOB(cbData: DWORD(password.len),
      pbData: cast[ptr byte](password[0].unsafeAddr))
    var output: DATA_BLOB
    if cryptProtectData(addr input, nil, nil, nil, nil,
        DWORD(CRYPTPROTECT_UI_FORBIDDEN), addr output) == 0:
      fail("CryptProtectData")
    defer: localFree(output.pbData)
    let dir = credPath()
    createDir(dir)
    var blob = newString(output.cbData.int)
    if blob.len > 0:
      copyMem(addr blob[0], output.pbData, blob.len)
    writeFile(dir / "credentials.dat", blob)

  var credCacheOk = false
  var credCachePw = ""

  proc loadSandwallCred*(): tuple[ok: bool; password: string] =
    ## Read + CryptUnprotectData the stored password. ok=false when
    ## the file is missing, corrupt, or protected for another user.
    ## Cached after the first success: DPAPI every command is waste
    ## once the parent stays alive across tool launches.
    if credCacheOk: return (true, credCachePw)
    let path = credPath() / "credentials.dat"
    try:
      let raw = readFile(path)
      if raw.len == 0: return (false, "")
      var input = DATA_BLOB(cbData: DWORD(raw.len),
        pbData: cast[ptr byte](raw[0].unsafeAddr))
      var output: DATA_BLOB
      if cryptUnprotectData(addr input, nil, nil, nil, nil,
          DWORD(CRYPTPROTECT_UI_FORBIDDEN), addr output) == 0:
        return (false, "")
      defer: localFree(output.pbData)
      var pw = newString(output.cbData.int)
      if pw.len > 0:
        copyMem(addr pw[0], output.pbData, pw.len)
      credCacheOk = true
      credCachePw = pw
      (true, pw)
    except IOError:
      (false, "")

  proc userSid(user = sandwallUserName): winffi.PSID =
    ## Resolve `user`'s account SID (LookupAccountNameW two-call
    ## sizing dance) into a fresh heap buffer the caller deallocs.
    ## nil when the account does not exist.
    let name = newWideCString(user)
    var cbSid, cchDomain: DWORD
    var use: SID_NAME_USE
    discard lookupAccountNameW(nil, name, nil, addr cbSid, nil,
      addr cchDomain, addr use)
    if cbSid == 0: return nil
    let sid = alloc0(cbSid.int)
    # +1: the second LookupAccountNameW call writes cchDomain chars
    # plus a terminator (the sizing call reports chars incl. null).
    var domain = newWideCString("", cchDomain.int + 1)
    if lookupAccountNameW(nil, name, sid, addr cbSid, domain,
        addr cchDomain, addr use) == 0:
      dealloc(sid)
      return nil
    cast[winffi.PSID](sid)

  proc sidString*(): string =
    ## SID string of the sandwall user, "" when the user does not
    ## exist.
    let sid = userSid()
    if sid == nil: return ""
    defer: dealloc(sid)
    var str: WideCString
    if convertSidToStringSidW(sid, addr str) == 0:
      fail("ConvertSidToStringSidW")
    defer: localFree(str)
    $str

  proc grantDesktopAccess*(user: string): DWORD =
    ## Grant `user` access to the interactive window station (winsta0)
    ## and its default desktop so a cross-session
    ## CreateProcessWithLogonW child can initialize there. Without
    ## this, console-subsystem children die with 0xC0000142 (verified
    ## on Win11). Returns 0 on success, else the Win32 error. Pure Nim:
    ## the same Get/SetSecurityInfo + SetEntriesInAclW calls the C shim
    ## made, via acl.nim's EXPLICIT_ACCESS machinery.
    let sid = userSid(user)
    if sid == nil: return DWORD(getLastError())
    defer: dealloc(sid)

    # One grant ACE for the user SID, inherited by sub-objects (the
    # winsta0 case; the desktop pass below clears the inherit flag).
    # GENERIC_ALL on a window object does not expand to WINSTA_ALL /
    # DESKTOP_ALL the way it does for files. user32/imm32 need the
    # documented masks or DllMain dies 0xC0000142.
    const WINSTA_ALL = 0x000F037F'i32
    var ea = acl.buildExplicitAccess(sid, acl.grantAccess,
      DWORD(WINSTA_ALL),
      DWORD(acl.SUB_CONTAINERS_AND_OBJECTS_INHERIT))

    proc mergeInto(obj: Handle; inherit: DWORD): DWORD =
      var oldDacl: acl.PACL
      var sd: pointer
      result = getSecurityInfo(obj, SE_WINDOW_OBJECT,
        acl.DACL_SECURITY_INFORMATION, nil, nil, addr oldDacl, nil, addr sd)
      if result != 0: return result
      # The old DACL from GetSecurityInfo is deliberately NOT freed:
      # LocalFree on it heap-corrupted in session-0 callers on Win11
      # 26100 (setup died 0xC0000374 before reaching the fence
      # install). It is ~200 bytes, once per setup.
      ea.grfInheritance = inherit
      var newDacl: acl.PACL
      result = acl.setEntriesInAcl(1, addr ea, oldDacl, addr newDacl)
      if result != 0: return result
      defer: localFree(newDacl)
      result = setSecurityInfo(obj, SE_WINDOW_OBJECT,
        acl.DACL_SECURITY_INFORMATION, nil, nil, newDacl, nil)

    # Prefer the interactive WinSta0 so a later CreateProcessWithLogonW
    # child on the console session can init. Fall back to this process's
    # station/desktop: OpenWindowStationW("WinSta0") from session-0 sshd
    # returns 0 immediately; OpenDesktopW("default") from session 0 hangs,
    # so never call that unless we already opened WinSta0.
    var ws = openWindowStationW(newWideCString("WinSta0"), 0,
      DWORD(READ_CONTROL or WRITE_DAC))
    var openedWs = ws != 0
    if not openedWs:
      ws = getProcessWindowStation()
    if ws == 0: return DWORD(getLastError())
    result = mergeInto(ws, DWORD(acl.SUB_CONTAINERS_AND_OBJECTS_INHERIT))
    if result != 0:
      if openedWs: discard closeWindowStation(ws)
      return result
    var desk: Handle
    var openedDesk = false
    if openedWs:
      desk = openDesktopW(newWideCString("default"), 0, 0,
        DWORD(READ_CONTROL or WRITE_DAC))
      openedDesk = desk != 0
    if desk == 0:
      desk = getThreadDesktop(getCurrentThreadId())
    if desk == 0:
      result = DWORD(getLastError())
      if openedWs: discard closeWindowStation(ws)
      return result
    result = mergeInto(desk, 0)
    if openedDesk: discard closeDesktop(desk)
    if openedWs: discard closeWindowStation(ws)

  var currentDesktopGranted = false

  proc grantCurrentDesktop*(user: string): DWORD =
    ## Grant `user` the documented WINSTA_ALL / DESKTOP_ALL masks on
    ## THIS process's window station and desktop. Setup-time
    ## grantDesktopAccess prefers WinSta0 and may stamp a different
    ## session (sshd is session 0). user32/imm32 children of a later
    ## CPLW then die 0xC0000142 (whoami, bash, powershell) while
    ## console-only images (cmd, hostname) survive. Call this from the
    ## spawn path so the grant matches the station the child inherits.
    ## Cached after the first success: the objects do not change for
    ## the life of this process, and SetSecurityInfo every run is
    ## hundreds of ms.
    if currentDesktopGranted: return 0
    const
      WINSTA_ALL = 0x000F037F'i32
      DESKTOP_ALL = 0x000F01FF'i32
    let sid = userSid(user)
    if sid == nil: return DWORD(getLastError())
    defer: dealloc(sid)
    const SE_WINDOW_OBJECT = 7'i32
    proc hasSid(oldDacl: acl.PACL; rights: DWORD): bool =
      if oldDacl.isNil: return false
      let aceCount = int(cast[ptr uint16](cast[uint](oldDacl) + 2)[])
      for i in 0 ..< aceCount:
        var ace: pointer = nil
        if acl.getAce(oldDacl, DWORD(i), addr ace) == 0: continue
        if cast[ptr uint8](cast[uint](ace) + 1)[] != 0: continue
        let aceMask = cast[ptr DWORD](cast[uint](ace) + 4)[]
        let aceSid = cast[winffi.PSID](cast[pointer](cast[uint](ace) + 8))
        if not acl.sameSid(aceSid, sid): continue
        if (aceMask and rights) == rights: return true
      false
    proc merge(obj: Handle; rights: DWORD): DWORD =
      var ea = acl.buildExplicitAccess(sid, acl.grantAccess, rights, DWORD(0))
      var oldDacl: acl.PACL
      var sd: pointer
      result = getSecurityInfo(obj, SE_WINDOW_OBJECT,
        acl.DACL_SECURITY_INFORMATION, nil, nil, addr oldDacl, nil, addr sd)
      if result != 0: return result
      if hasSid(oldDacl, rights): return 0
      var newDacl: acl.PACL
      result = acl.setEntriesInAcl(1, addr ea, oldDacl, addr newDacl)
      if result != 0: return result
      defer: localFree(newDacl)
      result = setSecurityInfo(obj, SE_WINDOW_OBJECT,
        acl.DACL_SECURITY_INFORMATION, nil, nil, newDacl, nil)
    let ws = getProcessWindowStation()
    if ws == 0: return DWORD(getLastError())
    result = merge(ws, DWORD(WINSTA_ALL))
    if result != 0: return result
    let desk = getThreadDesktop(getCurrentThreadId())
    if desk == 0: return DWORD(getLastError())
    result = merge(desk, DWORD(DESKTOP_ALL))
    if result == 0: currentDesktopGranted = true

  proc netLocalGroupAddMems(group, user: string) =
    ## Add `user` to local `group` (level 3 = names). Best-effort: a
    ## missing group or an existing membership is not a setup failure.
    var entries: array[1, LOCALGROUP_MEMBERS_INFO_3]
    entries[0] = LOCALGROUP_MEMBERS_INFO_3(lgrpi3DomainAndName:
      newWideCString(user))
    discard netLocalGroupAddMembers(nil, newWideCString(group), 3,
      addr entries[0], 1)

  proc grantExecute*(path: string): bool =
    ## Grant the sandbox user read+execute on `path` (a file: this ACE
    ## only; a dir: inherited by the tree) plus traverse-only ACEs on
    ## the profile ancestors, so sandboxed children can run the tools
    ## that live under the invoking user's private profile. False when
    ## the path does not exist; raises on ACL failure.
    if not fileExists(path) and not dirExists(path): return false
    let sidP = userSid()
    if sidP == nil: return false
    defer: dealloc(sidP)
    # SetNamedSecurityInfo with an inheritable ACE walks the whole
    # subtree. The bundled MSYS2 tree is ~30k files; a second setup
    # over SSH looks hung for minutes. Skip when the ACE is already
    # there (hasSidAce is a DACL read, no walk).
    let rights = acl.FILE_GENERIC_READ or acl.FILE_GENERIC_EXECUTE
    if dirExists(path):
      if not acl.hasSidAce(path, sidP, rights, DWORD(3)):
        acl.stampAce(path, sidP, acl.grantAccess, rights,
          inheritance = DWORD(3))  # OI|CI
    else:
      if not acl.hasSidAce(path, sidP, rights, DWORD(0)):
        acl.stampAce(path, sidP, acl.grantAccess, rights,
          inheritance = DWORD(0))
    # ancestors of a private profile need traverse for the child to
    # even reach the file
    var dir = splitFile(path).dir
    while dir.len > 3 and dir.contains(r"\Users\"):
      if not acl.hasSidAce(dir, sidP, DWORD(0x20), DWORD(0)):
        acl.stampAce(dir, sidP, acl.grantAccess, DWORD(0x20),
          inheritance = DWORD(0))  # FILE_TRAVERSE, this dir only
      dir = splitFile(dir).dir
    true

  proc setupSandwallUser*(): string =
    ## Elevated, idempotent: create the sandwall user (or reset its
    ## password), store the password DPAPI-protected, return the SID
    ## string for wfp.installFence.
    let name = newWideCString(sandwallUserName)
    # Re-runs must not rotate the password: NetUserSetInfo(1003) from a
    # session-0 sshd child hangs on this Win11 (lsass waits on a UI/GPO
    # path that never completes). Keep the stored password when it still
    # unlocks the account; only mint+set when the user is new or the
    # stored blob is missing/stale.
    let existing = loadSandwallCred()
    var password = existing.password
    var needSet = not existing.ok
    if not needSet:
      result = sidString()
      if result.len == 0: needSet = true
    if needSet:
      password = randomPassword()
      let pw = newWideCString(password)
      var info: USER_INFO_1
      zeroMem(addr info, sizeof(info))
      info.name = name
      info.password = pw
      info.priv = DWORD(USER_PRIV_USER)
      info.flags = DWORD(UF_SCRIPT or UF_NORMAL_ACCOUNT or UF_DONT_EXPIRE_PASSWD)
      var parmErr: DWORD
      var rc = netUserAdd(nil, 1'i32, addr info, addr parmErr)
      if rc == DWORD(NERR_USER_EXISTS):
        var pwInfo = USER_INFO_1003(password: pw)
        rc = netUserSetInfo(nil, name, 1003'i32, addr pwInfo, addr parmErr)
      if rc != 0:
        raise newException(OSError, "sandwall winuser: user setup failed " &
          "(netapi error " & $rc & ")")
      storePassword(password)
    result = sidString()
    if result.len == 0:
      raise newException(OSError,
        "sandwall winuser: user created but SID lookup failed")
    # NetUserAdd alone leaves the account in NO groups (verified on
    # Win11: a groupless account's console-subsystem children die at
    # loader init). "Users" is the standard non-admin membership; the
    # ACL sandbox still denies everything not explicitly granted.
    netLocalGroupAddMems("Users", sandwallUserName)
    # Window station + desktop access: without it a cross-session CPLW
    # child of a console-subsystem exe hangs at loader init or dies
    # 0xC0000142 (verified on Win11; see grantDesktopAccess).
    let drc = grantDesktopAccess(sandwallUserName)
    if drc != 0:
      raise newException(OSError,
        "sandwall winuser: desktop grant failed (error " & $drc & ")")
    # The sandbox user must be able to execute the tools the sandboxed
    # children run: the calling binary (it re-execs as the stdio relay)
    # and, when present, the bundled MSYS2 tree 3code's bash tool uses.
    # These live under the invoking user's private profile, whose ACLs
    # deny every other account; grant read+execute (and traverse on the
    # ancestors) once here instead of on every run.
    let self = getAppFilename()
    discard grantExecute(self)
    # Sibling OpenSSL DLLs + cacert.pem sit next to 3code.exe. A file
    # ACE on the exe does not cover them; without RX the sandwall-user
    # re-exec dies at loader init ("could not load libssl") and the
    # parent waits forever on the relay.
    discard grantExecute(parentDir(self))
    let msys = getEnv("LOCALAPPDATA", "") & r"\3code\msys64"
    if dirExists(msys):
      discard grantExecute(msys)

  proc spawnAsSandwall*(cmd: openArray[string]): Handle =
    ## Log on as the sandwall user and spawn `cmd` via
    ## CreateProcessAsUserW. Returns the process handle; the caller
    ## owns it. The fs sandbox (restricted token) is a separate,
    ## mutually exclusive path today - see the module header.
    let (ok, password) = loadSandwallCred()
    if not ok:
      raise newException(OSError,
        "sandwall winuser: no stored credentials; run setup first")
    var token: Handle
    if logonUserW(newWideCString(sandwallUserName), newWideCString("."),
        newWideCString(password), DWORD(LOGON32_LOGON_NETWORK_CLEARTEXT),
        DWORD(LOGON32_PROVIDER_WINNT50), addr token) == 0:
      fail("LogonUserW")
    defer: discard closeHandle(token)
    let cmdline = newWideCString(quoteCmdLine(cmd))
    var si: STARTUPINFO
    zeroMem(addr si, sizeof(si))
    si.cb = DWORD(sizeof(si))
    var pi: PROCESS_INFORMATION
    if createProcessAsUserW(token, nil, cmdline, nil, nil, 0,
        DWORD(CREATE_NO_WINDOW), nil, nil, addr si, addr pi) == 0:
      fail("CreateProcessAsUserW")
    discard closeHandle(pi.hThread)
    pi.hProcess

  proc verifyFenceBehavioral*(): bool =
    ## Non-elevated fence check: spawn `<self> wall wfp-probe` as the
    ## sandwall user and trust its exit code (0 = egress blocked).
    ## False when setup never ran, the spawn fails, or the probe
    ## connects. The `wall wfp-probe` subcommand is one line in the
    ## consumer's CLI (wfp.wfpProbeMain).
    let ph = try:
      spawnAsSandwall([getAppFilename(), "wall", "wfp-probe"])
    except OSError:
      return false
    defer: discard closeHandle(ph)
    if waitForSingleObject(ph, 20000) != 0:
      return false
    var code: DWORD
    if getExitCodeProcess(ph, addr code) == 0:
      return false
    code == 0
