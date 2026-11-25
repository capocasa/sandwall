## winffi: Win32 FFI declarations shared by the Windows backends.
##
## acl.nim (fs), wfp.nim (network fence) and winuser.nim (dedicated
## user) all talk to advapi32/userenv/kernel32 for SIDs, security
## descriptors and LocalFree/LocalAlloc. Those declarations were
## copy-pasted across the three modules; they live here once.
## Windows-only; the whole module is a no-op elsewhere.

when defined(windows):
  import std/[winlean, widestrs]

  type
    # Reuse winlean.PSID (ptr SID) so the backends share one SID type;
    # re-export it so callers can `import winffi` alone.
    PSID* = winlean.PSID
    HRESULT* = int32
    SIZE_T* = uint

  # kernel32: winlean already provides localFree (use that). localAlloc
  # it lacks.
  proc localAlloc*(uFlags: DWORD; bytes: SIZE_T): pointer {.stdcall,
      dynlib: "kernel32", importc: "LocalAlloc".}

  # advapi32: security descriptors and SIDs
  proc convertStringSecurityDescriptorToSecurityDescriptorW*(
      stringSecurityDescriptor: WideCString; stringSDRevision: DWORD;
      securityDescriptor: ptr pointer;
      securityDescriptorSize: ptr DWORD): WINBOOL {.stdcall,
      dynlib: "advapi32",
      importc: "ConvertStringSecurityDescriptorToSecurityDescriptorW".}
  proc convertSidToStringSidW*(sid: PSID;
      stringSid: ptr WideCString): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "ConvertSidToStringSidW".}
  proc getLengthSid*(pSid: PSID): DWORD {.stdcall, dynlib: "advapi32",
      importc: "GetLengthSid".}
  proc copySid*(destSidLen: DWORD; destSid: PSID;
      sourceSid: PSID): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "CopySid".}

  # The calling process's own user: OpenProcessToken +
  # GetTokenInformation(TokenUser)
  proc openProcessToken(process: Handle; desiredAccess: DWORD;
      token: ptr Handle): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "OpenProcessToken".}
  proc getTokenInformation(token: Handle; tokenInformationClass: cint;
      tokenInformation: pointer; tokenInformationLength: DWORD;
      returnLength: ptr DWORD): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "GetTokenInformation".}

  proc currentUserSid*(): string =
    ## The calling process's user as an S-1-5-... string, "" when the
    ## token does not say. The per-run permit filters grant their own
    ## deletion to it (wall/wfp.nim), so the process that stamps is the
    ## process that may un-stamp.
    const tokenQuery = 0x0008'i32
    const tokenUser = 1'i32
    var token: Handle
    if openProcessToken(getCurrentProcess(), DWORD(tokenQuery),
        addr token) == 0: return ""
    defer: discard closeHandle(token)
    var size: DWORD
    discard getTokenInformation(token, tokenUser, nil, 0, addr size)
    if size == 0: return ""
    let buf = localAlloc(0, size.uint)   # LMEM_FIXED, so LocalFree's
    if buf.isNil: return ""
    defer: localFree(buf)
    if getTokenInformation(token, tokenUser, buf, size, addr size) == 0:
      return ""
    # TOKEN_USER is { PSID Sid; DWORD Attributes }: the SID is the
    # first pointer, into the same buffer.
    let sid = cast[ptr PSID](buf)[]
    if sid.isNil: return ""
    var wstr: WideCString = nil
    if convertSidToStringSidW(sid, addr wstr) == 0: return ""
    result = $wstr
    localFree(wstr)

  # userenv: AppContainer profile
  proc deriveAppContainerSidFromAppContainerName*(name: WideCString;
      sid: ptr PSID): HRESULT {.stdcall, dynlib: "userenv",
      importc: "DeriveAppContainerSidFromAppContainerName".}
  proc createAppContainerProfile*(name, display, desc: WideCString;
      caps: pointer; capCount: DWORD; sid: ptr PSID): HRESULT {.stdcall,
      dynlib: "userenv", importc: "CreateAppContainerProfile".}
