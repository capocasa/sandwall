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
  import ./winffi

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

  # --- FFI ---

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

  proc logonUserW(lpszUsername: WideCString; lpszDomain: WideCString;
      lpszPassword: WideCString; dwLogonType: DWORD;
      dwLogonProvider: DWORD; phToken: ptr Handle): WINBOOL {.stdcall,
      dynlib: "advapi32", importc: "LogonUserW".}
  proc createProcessAsUserW(hToken: Handle;
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

  proc fail(what: string) {.noinline.} =
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

  proc loadSandwallCred*(): tuple[ok: bool; password: string] =
    ## Read + CryptUnprotectData the stored password. ok=false when
    ## the file is missing, corrupt, or protected for another user.
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
      (true, pw)
    except IOError:
      (false, "")

  proc sidString*(): string =
    ## SID string of the sandwall user, "" when the user does not
    ## exist (LookupAccountName two-call sizing dance).
    let name = newWideCString(sandwallUserName)
    var cbSid, cchDomain: DWORD
    var use: SID_NAME_USE
    discard lookupAccountNameW(nil, name, nil, addr cbSid, nil,
      addr cchDomain, addr use)
    if cbSid == 0:
      return ""
    var sid = alloc0(cbSid.int)
    defer: dealloc(sid)
    var domain = newWideCString("", cchDomain.int)
    if lookupAccountNameW(nil, name, sid, addr cbSid, domain,
        addr cchDomain, addr use) == 0:
      return ""
    var str: WideCString
    if convertSidToStringSidW(cast[winffi.PSID](sid), addr str) == 0:
      fail("ConvertSidToStringSidW")
    defer: localFree(str)
    $str

  proc setupSandwallUser*(): string =
    ## Elevated, idempotent: create the sandwall user (or reset its
    ## password), store the password DPAPI-protected, return the SID
    ## string for wfp.installFence.
    let password = randomPassword()
    let name = newWideCString(sandwallUserName)
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
      # Idempotent re-run: rotate the password on the existing user.
      var pwInfo = USER_INFO_1003(password: pw)
      rc = netUserSetInfo(nil, name, 1003'i32, addr pwInfo, addr parmErr)
    if rc != 0:
      raise newException(OSError, "sandwall winuser: user setup failed " &
        "(netapi error " & $rc & ")")
    result = sidString()
    if result.len == 0:
      raise newException(OSError,
        "sandwall winuser: user created but SID lookup failed")
    storePassword(password)

  proc buildCommandLine(cmd: openArray[string]): WideCString =
    ## Minimal quoting: wrap args containing whitespace in quotes.
    var parts: seq[string]
    for a in cmd:
      if a.find(Whitespace) >= 0 and not a.startsWith('"'):
        parts.add '"' & a & '"'
      else:
        parts.add a
    newWideCString(parts.join(" "))

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
    let cmdline = buildCommandLine(cmd)
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
