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

  # userenv: AppContainer profile
  proc deriveAppContainerSidFromAppContainerName*(name: WideCString;
      sid: ptr PSID): HRESULT {.stdcall, dynlib: "userenv",
      importc: "DeriveAppContainerSidFromAppContainerName".}
  proc createAppContainerProfile*(name, display, desc: WideCString;
      caps: pointer; capCount: DWORD; sid: ptr PSID): HRESULT {.stdcall,
      dynlib: "userenv", importc: "CreateAppContainerProfile".}
