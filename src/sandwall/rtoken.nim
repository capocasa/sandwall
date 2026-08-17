## Windows dedicated-user backend for sandwall.
##
## This replaces both the AppContainer backend and the same-user
## write-restricted-token backend. Neither could hold: the
## AppContainer confines the process to a private object namespace,
## which kills the msys2/cygwin DLL at init, and a same-user
## write-restricted token needs the token user SID in the restricted
## list for msys2's owner-ACL'd signal pipe - which makes every
## user-writable path writable and the sandbox a no-op (verified on
## Windows 11; the same wall Codex hit, openai/codex#17459).
##
## Enforcement model (the Codex "elevated sandbox" shape):
##   1. A one-time elevated setup (`3code wall setup-windows`) creates
##      a dedicated local user `sandwall` with a random password
##      stored DPAPI-protected at %LOCALAPPDATA%\sandwall\
##      credentials.dat (wall/winuser.nim).
##   2. `restrictImpl` stamps an ALLOW ACE for the sandbox USER SID on
##      each writable root (full access) and traverse-only ACEs on the
##      ancestors of every root (private profile dirs deny traverse by
##      default). DENY ACEs for deny-narrowing are stamped on the
##      denied path and rolled back after the run.
##   3. `spawnSandboxed` runs the child as that user via
##      CreateProcessWithLogonW with lpDesktop NULL: with the winsta0
##      + default-desktop ACL grants from setup in place, NULL lets
##      the child init in the caller's desktop; an explicit
##      "winsta0\default" string instead kills console-subsystem
##      children at loader init with 0xC0000142 (verified on Win11
##      26100). The user boundary IS the confinement:
##      the sandbox user can write nowhere except the stamped roots.
##      msys2 survives because the child is a normal user process with
##      a normal namespace and its own logon session.
##   4. An unnamed Job Object with KILL_ON_JOB_CLOSE contains the whole
##      process tree; the child is assigned right after spawn.
##   5. Network: the WFP fence (wfp.nim) blocks non-loopback egress for
##      the sandbox user; the wall proxy enforces the hostname
##      allowlist on loopback. With host rules the proxy env vars are
##      set on the child; without them the fence is left alone.
##
## The ALLOW grants for the user SID are NOT inert (unlike the
## synthetic-SID model): any process running as the sandbox user could
## write the stamped roots. That is exactly the boundary we want - only
## sandboxed children run as that user - so the grants persist across
## runs and idempotent re-stamping is enough. DENY narrowing must roll
## back: a lingering DENY for the sandbox user would break the next
## run's writable root.

import std/[os, times]

when defined(windows):
  import std/[winlean, widestrs, strutils, syncio, algorithm]
  import ./acl
  import ./paths
  import ./wall/winuser
  import ./wall/quotecmd
  import ./wall/stdio

  # --- FFI ---

  type
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
    # Job objects
    jobObjectExtendedLimitInformation = 9'i32
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000'i32
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000'i32
    LOGON_WITH_PROFILE = 0x00000001'i32

    # CreateProcessWithLogonW flags (winbase.h)
    CREATE_UNICODE_ENVIRONMENT = 0x00000400'i32
    CREATE_NO_WINDOW = 0x08000000'i32
    STARTF_USESHOWWINDOW = 0x00000001'i32
    SW_HIDE = 0'i32

  proc createJobObjectW(attr: pointer; name: WideCString): Handle {.stdcall,
      dynlib: "kernel32", importc: "CreateJobObjectW".}
  proc setInformationJobObject(job: Handle; infoClass: int32; info: pointer;
      infoLen: DWORD): WINBOOL {.stdcall, dynlib: "kernel32",
      importc: "SetInformationJobObject".}
  proc assignProcessToJobObject(job, process: Handle): WINBOOL {.stdcall,
      dynlib: "kernel32", importc: "AssignProcessToJobObject".}
  proc fail(what: string) {.noinline.} =
    raise newException(OSError,
      "sandwall windows-user: " & what & " failed (error " & $getLastError() & ")")

  # The real 11-argument prototype (no process/thread attribute
  # params, no inherit flag - a hand-written import with
  # CreateProcessAsUserW's shape misaligns the stack and SIGSEGVs, so
  # the signature below matches winbase.h exactly).
  proc createProcessWithLogonW(user, domain, password: WideCString;
      logonFlags: DWORD; appName: WideCString; cmdline: WideCString;
      creationFlags: DWORD; env: pointer; cwd: WideCString;
      si: ptr STARTUPINFO; pi: ptr PROCESS_INFORMATION): WINBOOL {.
      stdcall, dynlib: "advapi32", importc: "CreateProcessWithLogonW".}

  proc getEnvironmentStringsW(): WideCString {.stdcall,
      dynlib: "kernel32", importc: "GetEnvironmentStringsW".}
  proc freeEnvironmentStringsW(env: WideCString): WINBOOL {.stdcall,
      dynlib: "kernel32", importc: "FreeEnvironmentStringsW".}

  proc buildEnvBlockW(): WideCString =
    ## The LIVE process environment (so NIMBOX_OUT_PIPE and the
    ## wall-proxy vars putenv'd by the caller arrive). CPLW with a NULL
    ## env gives the child a fresh block instead: the relay would see
    ## no pipe name and TEMP/TMP would point into the sandwall user's
    ## absent profile. Leaked (a few KB per run; freed at exit).
    getEnvironmentStringsW()

  proc convertStringSidToSidW(str: WideCString; sid: ptr winlean.PSID): WINBOOL
      {.stdcall, dynlib: "advapi32", importc: "ConvertStringSidToSidW".}

  proc setHandleInformation(hObject: winlean.Handle; dwMask,
      dwFlags: DWORD): WINBOOL {.stdcall, dynlib: "kernel32",
      importc: "SetHandleInformation".}

  proc localFree(mem: pointer): pointer {.stdcall, dynlib: "kernel32",
      importc: "LocalFree".}

  # --- module state ---

  var userSidCache: winlean.PSID = nil
    ## The sandbox user's SID, resolved once per process.

  var denyStamped: seq[string] = @[]
    ## Deny paths stamped this run; rolled back after the child exits.

  var relayPipe: stdio.RelayPipe
    ## The current run's stdout pipe for the CPLW child; closed by
    ## endRun after the child exits.

  proc sandboxUserSid*(): winlean.PSID =
    ## Resolve (and cache) the sandbox user's SID from its name.
    if userSidCache == nil:
      let sid = winuser.sidString()
      if sid.len == 0:
        raise newException(OSError,
          "sandwall windows-user: the sandbox user does not exist; " &
          "run `3code wall setup-windows` once (elevated)")
      if convertStringSidToSidW(newWideCString(sid),
          addr userSidCache) == 0:
        fail("ConvertStringSidToSidW(sandbox user)")
    userSidCache

  proc ancestorsNeedGrant(path: string): seq[string] =
    ## Ancestors of `path` up to (excluding) the drive root that may
    ## deny the sandbox user traverse. Private profile dirs (C:\Users\
    ## <name>\...) are the practical case; system dirs already grant
    ## Users traverse, and stamping them anyway is harmless but noisy,
    ## so only ancestors under a user profile are stamped.
    result = @[]
    var dir = splitFile(path).dir
    const userProfileRoot = "\\Users\\"
    while dir.len > 3 and dir.contains(userProfileRoot):
      let parent = splitFile(dir).dir
      if parent.len <= 3: break
      result.add dir
      dir = parent
    # closest-first is irrelevant for grants; keep outermost-first
    result = reversed(result)

  proc restrictImpl*(writable, read: openArray[string];
                     denied: openArray[string] = []) =
    ## Stamp ALLOW ACEs for the sandbox user SID on each writable root
    ## (full access, inherited) and traverse-only ACEs on profile
    ## ancestors so the child can reach the root. `read` paths get an
    ## explicit read+execute stamp: system dirs already grant Users
    ## read, but a readonly path inside a private profile (Temp, home)
    ## is closed to the sandbox user without one. DENY ACEs for
    ## deny-narrowing are stamped for rollback after the run.
    let norm = paths.normalize
    var seen: seq[string] = @[]
    let sid = sandboxUserSid()
    for p in writable:
      let n = norm(p)
      if n.len == 0 or n in seen: continue
      seen.add(n)
      for anc in ancestorsNeedGrant(n):
        # Skip the stamp when the traverse ACE is already there: a
        # redundant SetNamedSecurityInfoW on a profile dir costs
        # seconds (NTFS walks the subtree reconciling inheritable
        # ACEs), and after the first run the ACE is always there.
        if acl.hasSidAce(anc, sid, DWORD(FILE_TRAVERSE), DWORD(0)):
          continue
        acl.stampAce(anc, sid, acl.grantAccess, DWORD(FILE_TRAVERSE),
          inheritance = DWORD(0))
      # Same skip as the ancestor / readonly loops: a redundant
      # inherited FILE_ALL_ACCESS stamp walks the subtree and can
      # take minutes under Defender. After the first run the ACE is
      # already there.
      if not acl.hasSidAce(n, sid, acl.FILE_ALL_ACCESS,
          DWORD(acl.SUB_CONTAINERS_AND_OBJECTS_INHERIT)):
        acl.stampAce(n, sid, acl.grantAccess, acl.FILE_ALL_ACCESS)
    for p in read:
      let n = norm(p)
      # A readonly rule for a path that does not exist (a policy guard
      # on a repo .sandbox that was never created) must be a no-op:
      # readDacl on a missing file raises error 2 and kills the run.
      if n.len == 0 or n in seen: continue
      if not dirExists(n) and not fileExists(n): continue
      seen.add(n)
      for anc in ancestorsNeedGrant(n):
        if acl.hasSidAce(anc, sid, DWORD(FILE_TRAVERSE), DWORD(0)):
          continue
        acl.stampAce(anc, sid, acl.grantAccess, DWORD(FILE_TRAVERSE),
          inheritance = DWORD(0))
      # Skip the stamp when the read+execute ACE is already there (the
      # same seconds-long NTFS walk as the ancestor check above).
      if acl.hasSidAce(n, sid,
          DWORD(acl.FILE_GENERIC_READ or acl.FILE_GENERIC_EXECUTE),
          DWORD(acl.SUB_CONTAINERS_AND_OBJECTS_INHERIT)):
        continue
      acl.stampAce(n, sid, acl.grantAccess,
        DWORD(acl.FILE_GENERIC_READ or acl.FILE_GENERIC_EXECUTE))
    for d in denied:
      let n = norm(d)
      if n.len == 0: continue
      # A deny on a not-yet-existing path cannot be stamped; the write
      # to it would fail the parent-dir allow anyway when the parent is
      # not writable, and when the parent IS writable the child could
      # create it - accepted gap, same as the token backend had.
      if not dirExists(n) and not fileExists(n): continue
      acl.stampAce(n, sid, acl.denyAccess, acl.FILE_ALL_ACCESS)
      denyStamped.add(n)

  proc endRun() =
    ## Unwind one run's side effects: close the stdout pipe (the pump
    ## thread sees EOF and exits, the env var pointed at a dead pipe)
    ## and remove the DENY ACEs stamped for this run. Both best-effort
    ## - cleanup of the rest must not abort on one failure.
    stdio.closeRelay(relayPipe)
    putenv("NIMBOX_OUT_PIPE", "")
    if denyStamped.len == 0: return
    let sid = sandboxUserSid()
    let paths = denyStamped
    denyStamped = @[]
    for p in paths:
      try:
        acl.removeSidAces(p, sid)
      except CatchableError as e:
        stderr.writeLine("sandwall windows-user: deny rollback failed on " &
          p & ": " & e.msg)

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
    ## Run `cmd` as the sandbox user via CreateProcessWithLogonW inside
    ## a KILL_ON_JOB_CLOSE Job. Returns the process handle.
    ## CreateProcessWithLogonW cannot inherit pipe handles across the
    ## logon boundary (and CreateProcessAsUserW needs privileges the
    ## non-elevated caller lacks, error 1314), so the command line is
    ## prefixed with `<self> stdio-relay`: a named pipe
    ## (everyone DACL) is handed over via the environment, the relay
    ## opens it by name, installs it as its stdio, and spawns the
    ## real CMD with ordinary handle inheritance. The parent pumps the
    ## pipe into its own stdio from a background thread.
    ## The WFP fence (keyed on the sandbox user) confines the child to
    ## loopback; the caller points the child at the wall proxy via env
    ## when the policy has host rules. On any failure after the relay
    ## pipe exists, endRun() unwinds it.
    if cmd.len == 0:
      raise newException(ValueError, "sandwall.spawnSandboxed: empty command")
    let (ok, password) = winuser.loadSandwallCred()
    if not ok:
      raise newException(OSError,
        "sandwall windows-user: no stored credentials; " &
        "run `3code setup` once (elevated)")
    discard sandboxUserSid()  # fail fast when setup never ran
    let job = ensureJob()
    # The Job handle must outlive the child for KILL_ON_JOB_CLOSE; we
    # leak it into this process (one Job per run, freed at exit).
    discard job
    let tag = $epochTime() & "-" & $getCurrentProcessId()
    relayPipe = stdio.createRelayPipe(tag)
    try:
      putenv("NIMBOX_OUT_PIPE", relayPipe.childName)
      # Do not re-exec 3code.exe as the relay: Nim -d:ssl loads libssl
      # at process init, before main, and the sandwall user cannot
      # LoadLibrary the sibling DLLs (verified: child exits 1, parent
      # waits forever). cmd.exe as the CPLW image works (exit 0, writes
      # as sandwall). Attach the named pipe by path so cmd opens it
      # itself; handle inheritance does not cross the logon boundary.
      # Start the pump after CPLW so a client will connect (a pump with
      # no client hangs endRun: ConnectNamedPipe + closeHandle).
      let inner = quoteCmdLine(cmd)
      let wrapped = "cmd.exe /c " & inner & " >" &
        relayPipe.childName & " 2>&1"
      let cmdW = newWideCString(wrapped)
      let userW = newWideCString(winuser.sandwallUserName)
      let domW = newWideCString(".")
      let pwW = newWideCString(password)
      let cwdW = newWideCString(getCurrentDir())
      var si: STARTUPINFO
      zeroMem(addr si, sizeof(si))
      si.cb = DWORD(sizeof(si))
      # Belt and suspenders with CREATE_NO_WINDOW below: wShowWindow is
      # what the console host reads when it does create a window. CPLW
      # is documented to default to CREATE_NEW_CONSOLE and older builds
      # ignore CREATE_NO_WINDOW there.
      si.dwFlags = STARTF_USESHOWWINDOW
      si.wShowWindow = int16(SW_HIDE)
      # lpDesktop stays NULL: with the winsta0 + default-desktop ACL
      # grants from setup in place, NULL lets the child init in the
      # caller's desktop. An explicit "winsta0\default" instead made
      # console-subsystem children die at loader init with 0xC0000142
      # (verified on Win11 26100).
      var pi: PROCESS_INFORMATION
      zeroMem(addr pi, sizeof(pi))
      let envW = buildEnvBlockW()
      # A NULL env would hand the child a fresh (nearly empty) block;
      # the live block needs CREATE_UNICODE_ENVIRONMENT or CPLW
      # rejects it with 87. CPLW also defaults to CREATE_NEW_CONSOLE and
      # a cross-logon child cannot inherit ours: without CREATE_NO_WINDOW
      # every sandboxed command flashes its own console window on the
      # desktop. The invisible console is inherited by descendants.
      # BREAKAWAY: sshd/cmd on this host already put us in a Job that
      # forbids nested AssignProcessToJobObject. Without breakaway the
      # child is born into that Job, our assign fails or the child is
      # killed when the parent Job accounts for it. Isolated CPLW
      # probes (no Job) spawn fine.
      let flags = (if not envW.isNil:
        DWORD(CREATE_UNICODE_ENVIRONMENT) else: 0'i32) or
        DWORD(CREATE_NO_WINDOW) or DWORD(CREATE_BREAKAWAY_FROM_JOB)
      if createProcessWithLogonW(userW, domW, pwW, DWORD(LOGON_WITH_PROFILE), nil, cmdW, flags,
          cast[pointer](envW), cwdW, addr si, addr pi) == 0:
        raise newException(OSError,
          "sandwall windows-user: CreateProcessWithLogonW failed (error " &
          $getLastError() & ")")
      discard closeHandle(pi.hThread)
      if assignProcessToJobObject(job, pi.hProcess) == 0:
        discard closeHandle(pi.hProcess)
        fail("AssignProcessToJobObject")
      stdio.pumpRelay(relayPipe)
      pi.hProcess
    except CatchableError:
      endRun()
      raise

  proc waitForExit*(ph: Handle): int =
    ## Block until `ph` exits and return its exit code. Raises on
    ## WaitForSingleObject/GetExitCodeProcess failure. The caller owns
    ## unwinding via endRun (runAsSandboxUser does).
    let w = waitForSingleObject(ph, INFINITE)
    if w == WAIT_FAILED:
      raise newException(OSError,
        "sandwall: WaitForSingleObject failed: " & $getLastError())
    var code: int32 = 0
    if getExitCodeProcess(ph, code) == 0:
      raise newException(OSError,
        "sandwall: GetExitCodeProcess failed: " & $getLastError())
    int(code)

  proc runAsSandboxUser*(cmd: openArray[string]): int =
    ## The whole run in one block: spawn as the sandbox user, wait,
    ## then unwind (pipe close + deny rollback) even when the wait
    ## raises. The ALLOW grants persist (only sandboxed children run as
    ## that user); a lingering DENY would break the next run, so the
    ## rollback is the one thing that must not be skipped.
    let ph = spawnSandboxed(cmd)
    defer: discard closeHandle(ph)
    try:
      waitForExit(ph)
    finally:
      endRun()


proc backendSupported*(): bool =
  ## True when the sandbox user exists and credentials are readable.
  when defined(windows):
    try:
      let (ok, _) = winuser.loadSandwallCred()
      ok and winuser.sidString().len > 0
    except CatchableError:
      false
  else:
    false

proc backendName*(): string = "windows-dedicated-user"
