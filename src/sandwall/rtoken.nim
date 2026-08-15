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
##      CreateProcessWithLogonW with lpDesktop="winsta0\default" (the
##      desktop string is REQUIRED: without it the child fails DLL
##      init with 0xC0000142). The user boundary IS the confinement:
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

    # ACL/ACL inheritance (winnt.h)
    CONTAINER_INHERIT_ACE = 0x2'i32
    OBJECT_INHERIT_ACE = 0x1'i32
    SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3'i32

    # Traverse-only rights for ancestor ACEs
    FILE_TRAVERSE = 0x20'i32

  proc createJobObjectW(attr: pointer; name: WideCString): Handle {.stdcall,
      dynlib: "kernel32", importc: "CreateJobObjectW".}
  proc setInformationJobObject(job: Handle; infoClass: int32; info: pointer;
      infoLen: DWORD): WINBOOL {.stdcall, dynlib: "kernel32",
      importc: "SetInformationJobObject".}
  proc assignProcessToJobObject(job, process: Handle): WINBOOL {.stdcall,
      dynlib: "kernel32", importc: "AssignProcessToJobObject".}
  proc resumeThread(thread: Handle): DWORD {.stdcall, dynlib: "kernel32",
      importc: "ResumeThread".}
  proc suspendThread(thread: Handle): DWORD {.stdcall, dynlib: "kernel32",
      importc: "SuspendThread".}
  proc fail(what: string) {.noinline.} =
    raise newException(OSError,
      "sandwall windows-user: " & what & " failed (error " & $getLastError() & ")")

  {.compile: "csrc/spawn_shim.c".}
  proc swSpawnWithLogon(user, domain, password, cmdline, cwd: WideCString;
      outProcess: ptr Handle): DWORD {.stdcall, importc: "sw_spawn_with_logon",
      sideEffect.}

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
    ## spawnSandboxedAndWait after the child exits.

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
    ## ancestors so the child can reach the root. `read` paths need no
    ## stamp: the sandbox user already reads system dirs, and readable
    ## user files live under ancestors we just stamped. DENY ACEs for
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
      acl.stampAce(n, sid, acl.grantAccess, acl.FILE_ALL_ACCESS)
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

  proc closeRunRelay*() =
    ## Close the current run's stdout pipe; the pump thread hits EOF
    ## and exits. The env var is cleared too (it pointed at the now
    ## dead pipe). Best-effort.
    stdio.closeRelay(relayPipe)
    putenv("NIMBOX_OUT_PIPE", "")

  proc rollbackDenies*() =
    ## Remove the DENY ACEs stamped for this run. Best-effort.
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

  proc quoteCmdLine(cmd: openArray[string]): string =
    ## cmd.exe-compatible quoting for the child command line.
    result = ""
    for i, a in cmd:
      if i > 0: result.add(' ')
      if a.find(Whitespace) >= 0 and not a.startsWith('"'):
        result.add('"' & a & '"')
      else:
        result.add(a)

  proc spawnSandboxed*(cmd: openArray[string];
                       internetAccess = false): Handle =
    ## Run `cmd` as the sandbox user via CreateProcessWithLogonW inside
    ## a KILL_ON_JOB_CLOSE Job. Returns the process handle. The desktop
    ## string is mandatory (children fail 0xC0000142 without it).
    ## CreateProcessWithLogonW cannot inherit pipe handles across the
    ## logon boundary (and CreateProcessAsUserW needs privileges the
    ## non-elevated caller lacks, error 1314), so the command line is
    ## prefixed with `<self> wall stdio-relay`: two named pipes
    ## (everyone DACL) are handed over via the environment, the relay
    ## opens them by name, installs them as its stdio, and spawns the
    ## real CMD with ordinary handle inheritance. The parent pumps the
    ## pipes into its own stdio from a background thread.
    ## `internetAccess` is unused: the WFP fence (keyed on the sandbox
    ## user) is installed by `3code setup` and confines the child to
    ## loopback automatically; the caller points the child at the wall
    ## proxy via env when the policy has host rules.
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
    putenv("NIMBOX_OUT_PIPE", relayPipe.childName)
    let relay = when defined(swNoRelay): ""
                else: getAppFilename() & " wall stdio-relay --"
    let cmdW = newWideCString(relay & " " & quoteCmdLine(cmd))
    let userW = newWideCString(winuser.sandwallUserName)
    let domW = newWideCString(".")
    let pwW = newWideCString(password)
    let cwdW: WideCString = when defined(swNullCwd): nil
                            else: newWideCString(getCurrentDir())
    var ph: Handle = 0
    let rc = swSpawnWithLogon(userW, domW, pwW, cmdW, cwdW, addr ph)
    if rc != 0:
      raise newException(OSError,
        "sandwall windows-user: CreateProcessWithLogonW failed (error " &
        $rc & ")")
    when not defined(swNoJob):
      if assignProcessToJobObject(job, ph) == 0:
        discard closeHandle(ph)
        fail("AssignProcessToJobObject")
    when defined(swNoPump): discard
    else: stdio.pumpRelay(relayPipe)
    ph


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
