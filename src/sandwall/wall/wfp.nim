## wfp: the Windows half of the wall's kernel fence.
##
## Persistent Windows Filtering Platform filters that confine the
## dedicated local user `sandwall` (see winuser.nim) to loopback plus
## the fixed proxy port range, blocking all other egress for that
## user. Everyone else falls through to default-permit, so the host
## user is unaffected. Filters live in our own provider+sublayer
## (fixed GUIDs, hardcoded) and survive reboots; install/uninstall
## need elevation (the BFE denies non-admin enumeration, which
## fenceStatus reports instead of raising).
##
## Filter table, checked against srt's srt-win-src/src/wfp.rs:
##
##   layers  FWPM_LAYER_ALE_AUTH_CONNECT_V4 and _V6 (same shape twice)
##   PERMIT  weight 0x0F80_0000_0000_0000
##           v4: IP_REMOTE_ADDRESS in 127.0.0.0/8  AND
##               IP_REMOTE_PORT in range (FWP_MATCH_RANGE)
##           v6: IP_REMOTE_ADDRESS == ::1          AND
##               IP_REMOTE_PORT in range
##           (srt keys the permit on the user SID too; we leave it
##           unconditional - the only listener on the port range is
##           our proxy, so a non-sandwall user reaching it is fine)
##   BLOCK   weight 0x0F40_0000_0000_0000 (below the permit)
##           ALE_USER_ID matches the SD built from SDDL
##           `O:LSG:LSD:(A;;CC;;;<sid>)` for the sandwall user
##           action types: FWP_ACTION_BLOCK 0x00002001,
##           FWP_ACTION_PERMIT 0x00002002
##
## Compile-verified only: there is no Windows machine in this
## environment. Pure helpers (SDDL, GUID bytes, port validation) run
## on Linux; the FFI half is checked with the mingw cross compiler.

import std/strutils

const
  FirstProxyPort* = 60080'u16
  LastProxyPort* = 60089'u16

# Fixed GUIDs for provider / sublayer / filters, generated once and
# hardcoded so a second install finds the first one's objects.
const
  providerGuidText* = "1f8b3d7a-6c2e-4a91-9b5d-2e7c4a0f1d35"
  sublayerGuidText* = "3c9e2b18-5d4f-4e72-a8c1-9f6b0d3e5271"
  permitV4GuidText* = "5a1d4c72-9e3b-4f58-b6a2-7d0c8e1f4a63"
  blockV4GuidText*  = "6b2e5d83-0f4c-5a69-c7b3-8e1d9f2a5b74"
  permitV6GuidText* = "7c3f6e94-1a5d-6b70-d8c4-9f2e0a3b6c85"
  blockV6GuidText*  = "8d4a7fa5-2b6e-7c81-e9d5-0a3f1b4c7d96"

  acPermitV4GuidText* = "CDBF134B-0C89-4AF6-8114-712C909AD282"
  acBlockV4GuidText*  = "7776A764-193C-4EAE-B513-8EA59118F909"
  acPermitV6GuidText* = "083F2DED-64CE-444F-815D-DC04F8752F1A"
  acBlockV6GuidText*  = "AB977372-A5E9-4DE2-9D59-A9F3A561DA07"

type
  GUID* {.bycopy.} = object
    data1: uint32
    data2: uint16
    data3: uint16
    data4: array[8, uint8]

proc parseGuid*(text: string): GUID =
  ## Parse "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (hex, any case) into
  ## the Win32 GUID byte layout.
  let t = text.replace("-", "")
  doAssert t.len == 32
  proc byteAt(i: int): uint8 =
    fromHex[uint8](t.substr(i * 2, i * 2 + 1))
  result.data1 = (byteAt(0).uint32 shl 24) or (byteAt(1).uint32 shl 16) or
    (byteAt(2).uint32 shl 8) or byteAt(3).uint32
  result.data2 = (byteAt(4).uint16 shl 8) or byteAt(5).uint16
  result.data3 = (byteAt(6).uint16 shl 8) or byteAt(7).uint16
  for i in 0..7:
    result.data4[i] = byteAt(8 + i)

proc guidBytes*(g: GUID): array[16, uint8] =
  ## In-memory GUID layout (first three fields little-endian).
  result[0] = uint8(g.data1 and 0xff)
  result[1] = uint8((g.data1 shr 8) and 0xff)
  result[2] = uint8((g.data1 shr 16) and 0xff)
  result[3] = uint8((g.data1 shr 24) and 0xff)
  result[4] = uint8(g.data2 and 0xff)
  result[5] = uint8((g.data2 shr 8) and 0xff)
  result[6] = uint8(g.data3 and 0xff)
  result[7] = uint8((g.data3 shr 8) and 0xff)
  for i in 0..7:
    result[8 + i] = g.data4[i]

proc `==`*(a, b: GUID): bool =
  a.data1 == b.data1 and a.data2 == b.data2 and a.data3 == b.data3 and
    a.data4 == b.data4

proc validPortRange*(firstPort, lastPort: uint16): bool =
  firstPort > 0 and firstPort <= lastPort

proc sddlForUserSid*(sid: string): string =
  ## Security descriptor SDDL whose DACL grants Connect access to the
  ## given user SID. The ALE_USER_ID filter condition matches the
  ## connecting token's user against this descriptor.
  "O:LSG:LSD:(A;;CC;;;" & sid & ")"

when defined(windows):
  import std/[winlean, widestrs, net]

  type SIZE_T* = uint
  {.passL: "-lfwpuclnt -ladvapi32".}
  {.compile: "csrc/wfp_shim.c".}

  # C shim wrappers (see csrc/wfp_shim.c) — avoid Nim ORC GC issues
  # with WFP RPC when passing structs containing GC-managed pointers.
  proc swProviderAdd(engine: Handle; rawGuid: ptr byte;
      name: ptr UncheckedArray[Utf16Char]): DWORD {.stdcall,
      importc: "sw_provider_add".}
  proc swSublayerAdd(engine: Handle; rawGuid: ptr byte;
      name: ptr UncheckedArray[Utf16Char];
      weight: uint16): DWORD {.stdcall,
      importc: "sw_sublayer_add".}
  type
    SwCondDesc* {.bycopy.} = object
      fieldKey: array[16, byte]
      matchType: uint32
      kind: uint32
      pad: uint32
      value: uint64

  proc swFilterAdd(engine: Handle; providerGuid: ptr byte;
      filterKey: ptr byte; sublayerGuid: ptr byte; layerGuid: ptr byte;
      weight: uint64; name: ptr UncheckedArray[Utf16Char];
      actionType: uint32; conds: ptr SwCondDesc; numConds: uint32;
      outId: ptr uint64): DWORD {.stdcall,
      importc: "sw_filter_add".}

  # --- types (fwpmu.h / fwptypes.h) ---

  type
    FWP_BYTE_BLOB* {.bycopy.} = object
      size: uint32
      data: ptr uint8

    FWP_V4_ADDR_AND_MASK* {.bycopy.} = object
      addr4: uint32
      mask: uint32

    FWP_BYTE_ARRAY16* {.bycopy.} = object
      bytes: array[16, uint8]

    FWPM_DISPLAY_DATA0* {.bycopy.} = object
      name: ptr UncheckedArray[Utf16Char]
      description: ptr UncheckedArray[Utf16Char]

    # FWP_VALUE0: a kind tag (uint32) plus 4 bytes of padding plus an
    # 8-byte union payload (matches the Win32 FWP_VALUE0 on amd64).
    # Using a union avoids the struct-size bug where sequential fields
    # bloated FWP_VALUE0 to 56 bytes and corrupted FWPM_FILTER0 offsets
    # after `weight`, which hung FwpmFilterEnum0.
    FWP_VALUE_DATA* {.union.} = object
      uint8Value: uint8
      uint16Value: uint16
      uint32Value: uint32
      uint64Value: ptr uint64  # FWP_VALUE0 stores UINT64 by reference
      v4AddrMask: ptr FWP_V4_ADDR_AND_MASK
      v6Addr: ptr FWP_BYTE_ARRAY16
      rangeValue: pointer  # ptr FWP_RANGE0
      sd: ptr FWP_BYTE_BLOB
    FWP_VALUE0* {.bycopy.} = object
      kind: uint32
      data: FWP_VALUE_DATA

    FWP_RANGE0* {.bycopy.} = object
      valueLow, valueHigh: FWP_VALUE0

    FWPM_FILTER_CONDITION0* {.bycopy.} = object
      fieldKey: GUID
      matchType: uint32  # FWP_MATCH_TYPE
      conditionValue: FWP_VALUE0

    FWPM_PROVIDER0* {.bycopy.} = object
      providerKey: GUID
      displayData: FWPM_DISPLAY_DATA0
      flags: uint32
      providerData: FWP_BYTE_BLOB

    FWPM_SUBLAYER0* {.bycopy.} = object
      subLayerKey: GUID
      displayData: FWPM_DISPLAY_DATA0
      flags: uint32
      providerKey: ptr GUID
      providerData: FWP_BYTE_BLOB
      weight: uint16

    # rawContext (UINT64) / providerContextKey (GUID) union: 16 bytes.
    FWP_RAW_CONTEXT_UNION* {.union.} = object
      rawContext: uint64
      providerContextKey: GUID
    FWPM_FILTER0* {.bycopy.} = object
      filterKey: GUID
      displayData: FWPM_DISPLAY_DATA0
      flags: uint32
      providerKey: ptr GUID
      providerData: FWP_BYTE_BLOB
      layerKey: GUID
      subLayerKey: GUID
      weight: FWP_VALUE0
      numFilterConditions: uint32
      filterCondition: ptr UncheckedArray[FWPM_FILTER_CONDITION0]
      action: FWPM_ACTION0
      rawContextOrProviderContext: FWP_RAW_CONTEXT_UNION
      reserved: ptr GUID
      filterId: uint64
      effectiveWeight: FWP_VALUE0

    FWPM_ACTION0* {.bycopy.} = object
      actionType: uint32
      filterType: ptr GUID

    FWPM_SESSION0* {.bycopy.} = object
      sessionKey: GUID
      displayData: FWPM_DISPLAY_DATA0
      flags: uint32
      txnWaitTimeoutInMSec: uint32
      processId: DWORD
      sid: pointer
      username: ptr UncheckedArray[Utf16Char]
      kernelMode: WINBOOL

  const
    # layers (fwpmk.h)
    FWPM_LAYER_ALE_AUTH_CONNECT_V4 = GUID(data1: 0xc38d57d1'u32,
      data2: 0x05a7'u16, data3: 0x4c33'u16,
      data4: [0x90'u8, 0x4f, 0x0f, 0xbd, 0x96, 0x4e, 0xe6, 0x0e])
    FWPM_LAYER_ALE_AUTH_CONNECT_V6 = GUID(data1: 0x4a72393b'u32,
      data2: 0x319f'u16, data3: 0x44bc'u16,
      data4: [0x84'u8, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4])

    # condition fields (fwpmk.h)
    FWPM_CONDITION_IP_REMOTE_ADDRESS = GUID(data1: 0xb235ae9a'u32,
      data2: 0x1d64'u16, data3: 0x49b8'u16,
      data4: [0xa4'u8, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x44])
    FWPM_CONDITION_IP_REMOTE_PORT = GUID(data1: 0xc35a604d'u32,
      data2: 0xd04b'u16, data3: 0x4e1b'u16,
      data4: [0x9a'u8, 0xd9, 0x06, 0x14, 0x0b, 0xd3, 0x8c, 0xb5])
    FWPM_CONDITION_ALE_USER_ID = GUID(data1: 0xaf043a8a'u32,
      data2: 0x34c2'u16, data3: 0x4f05'u16,
      data4: [0xbc'u8, 0x3b, 0x02, 0x88, 0x0a, 0x31, 0x3a, 0x1c])

    FWPM_CONDITION_ALE_APP_ID = GUID(data1: 0xd78e1e87'u32,
      data2: 0x8644'u16, data3: 0x4ea5'u16,
      data4: [0x94'u8, 0x37, 0xd8, 0x09, 0xec, 0xfc, 0x97, 0x19])

    FWP_MATCH_EQUAL = 0'u32
    FWP_MATCH_RANGE = 1'u32

    # FWP_DATA_TYPE (fwptypes.h)
    FWP_EMPTY = 0'u32
    FWP_UINT8 = 1'u32
    FWP_UINT16 = 2'u32
    FWP_UINT32 = 3'u32
    FWP_UINT64 = 4'u32
    FWP_BYTE_ARRAY16_TYPE = 11'u32
    FWP_BYTE_BLOB_TYPE = 12'u32
    FWP_SECURITY_DESCRIPTOR = 14'u32
    FWP_V4_ADDR_MASK = 0x100'u32
    FWP_V6_ADDR_MASK = 0x101'u32
    FWP_RANGE = 0x102'u32

    FWP_ACTION_BLOCK = 0x00002001'u32
    FWP_ACTION_PERMIT = 0x00002002'u32

    RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF'u32  # FWPM_SESSION0.authnService

    ERROR_ACCESS_DENIED = 5'u32
    FWP_E_ALREADY_EXISTS = 0x80320009'u32

  let
    providerKey* = parseGuid(providerGuidText)
    sublayerKey* = parseGuid(sublayerGuidText)
    permitV4Key* = parseGuid(permitV4GuidText)
    blockV4Key* = parseGuid(blockV4GuidText)
    permitV6Key* = parseGuid(permitV6GuidText)
    blockV6Key* = parseGuid(blockV6GuidText)

  # --- fwpuclnt / advapi32 FFI ---

  proc fwpmEngineOpen0(serverName: WideCString; authnService: uint32;
      authInfo: pointer; session: ptr FWPM_SESSION0;
      engineHandle: ptr Handle): DWORD {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmEngineOpen0".}
  proc fwpmEngineClose0(engineHandle: Handle): DWORD {.stdcall,
      dynlib: "fwpuclnt", importc: "FwpmEngineClose0".}
  proc fwpmProviderAdd0(engineHandle: Handle; provider: ptr FWPM_PROVIDER0;
      sd: pointer): DWORD {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmProviderAdd0".}
  proc fwpmSubLayerAdd0(engineHandle: Handle; subLayer: ptr FWPM_SUBLAYER0;
      sd: pointer): DWORD {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmSubLayerAdd0".}
  proc fwpmSubLayerDeleteByKey0(engineHandle: Handle;
      key: ptr GUID): DWORD {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmSubLayerDeleteByKey0".}
  proc fwpmProviderDeleteByKey0(engineHandle: Handle;
      key: ptr GUID): DWORD {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmProviderDeleteByKey0".}
  proc fwpmFilterAdd0(engineHandle: Handle; filter: ptr FWPM_FILTER0;
      sd: pointer; id: ptr uint64): DWORD {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmFilterAdd0".}
  proc fwpmFilterDeleteById0(engineHandle: Handle; id: uint64): DWORD {.
      stdcall, dynlib: "fwpuclnt", importc: "FwpmFilterDeleteById0".}
  proc fwpmFilterCreateEnumHandle0(engineHandle: Handle;
      enumTemplate: pointer; enumHandle: ptr Handle): DWORD {.stdcall,
      dynlib: "fwpuclnt", importc: "FwpmFilterCreateEnumHandle0".}
  proc fwpmFilterEnum0(engineHandle: Handle; enumHandle: Handle;
      numEntriesRequested: uint32;
      entries: ptr ptr UncheckedArray[ptr FWPM_FILTER0];
      numEntriesReturned: ptr uint32): DWORD {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmFilterEnum0".}
  proc fwpmFilterDestroyEnumHandle0(engineHandle: Handle;
      enumHandle: Handle): DWORD {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmFilterDestroyEnumHandle0".}
  proc fwpmFreeMemory0(p: ptr pointer) {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmFreeMemory0".}

  proc convertStringSecurityDescriptorToSecurityDescriptorW(
      stringSecurityDescriptor: WideCString; stringSDRevision: DWORD;
      securityDescriptor: ptr pointer;
      securityDescriptorSize: ptr DWORD): WINBOOL {.stdcall,
      dynlib: "advapi32",
      importc: "ConvertStringSecurityDescriptorToSecurityDescriptorW".}
  proc localFree(hMem: pointer): pointer {.stdcall, dynlib: "kernel32",
      importc: "LocalFree".}
  type
    PSID* = pointer
    HRESULT* = int32

  proc deriveAppContainerSidFromAppContainerName(name: WideCString;
      sid: ptr PSID): HRESULT {.stdcall, dynlib: "userenv",
      importc: "DeriveAppContainerSidFromAppContainerName".}

  proc getLengthSid(pSid: PSID): DWORD {.stdcall, dynlib: "advapi32",
      importc: "GetLengthSid".}

  proc copySid(destSidLen: DWORD; destSid: PSID;
      sourceSid: PSID): WINBOOL {.stdcall, dynlib: "advapi32",
      importc: "CopySid".}

  proc localAlloc(uFlags: DWORD; bytes: SIZE_T): pointer {.stdcall, dynlib: "kernel32",
      importc: "LocalAlloc".}

  proc fwpmFilterDeleteByKey0(engineHandle: Handle;
      key: ptr GUID): DWORD {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmFilterDeleteByKey0".}



  proc allocWide(s: string): ptr UncheckedArray[Utf16Char] =
    ## Copy a string to a non-GC wide-char buffer. WFP structs store
    ## raw pointers to display-data strings across the FFI call; Nim's
    ## ORC GC can move or collect newWideCString results mid-call, so
    ## every string embedded in a WFP struct must come from here.
    let n = (s.len + 1) * 2
    result = cast[ptr UncheckedArray[Utf16Char]](alloc(n))
    let w = newWideCString(s)
    copyMem(result, unsafeAddr w[0], n)

  proc fail(what: string; code: DWORD) {.noinline.} =
    raise newException(OSError, "sandwall wfp: " & what &
      " failed (win32 error " & $code & ")")

  proc openEngine(name: ptr UncheckedArray[Utf16Char]): Handle =
    var session: FWPM_SESSION0
    zeroMem(addr session, sizeof(session))
    session.displayData.name = name
    session.displayData.description = name
    let rc = fwpmEngineOpen0(nil, RPC_C_AUTHN_DEFAULT, nil,
      addr session, addr result)
    if rc != 0: fail("FwpmEngineOpen0", rc)

  proc ensureProviderAndSublayer(engine: Handle) =
    let name = allocWide("sandwall")
    var rc = swProviderAdd(engine, cast[ptr byte](unsafeAddr providerKey),
      name)
    if rc != 0'i32 and rc != cast[DWORD](FWP_E_ALREADY_EXISTS):
      fail("FwpmProviderAdd0", rc)
    rc = swSublayerAdd(engine, cast[ptr byte](unsafeAddr sublayerKey),
      name, 0xFFFF)
    if rc != 0'i32 and rc != cast[DWORD](FWP_E_ALREADY_EXISTS):
      fail("FwpmSubLayerAdd0", rc)

  proc enumOurFilters(engine: Handle): seq[uint64] =
    ## IDs of all filters in our sublayer (any layer), via enum.
    var eh: Handle
    let rc = fwpmFilterCreateEnumHandle0(engine, nil, addr eh)
    if rc != 0: fail("FwpmFilterCreateEnumHandle0", rc)
    defer: discard fwpmFilterDestroyEnumHandle0(engine, eh)
    var entries: ptr UncheckedArray[ptr FWPM_FILTER0]
    var n: uint32
    let erc = fwpmFilterEnum0(engine, eh, 256, addr entries, addr n)
    if erc != 0: fail("FwpmFilterEnum0", erc)
    var entriesP: pointer = entries
    defer: fwpmFreeMemory0(addr entriesP)
    for i in 0 ..< n.int:
      let f = entries[i]
      if f[].subLayerKey == sublayerKey:
        result.add f[].filterId

  proc guidToBytes(g: GUID): array[16, byte] = guidBytes(g)

  proc addFilter(engine: Handle; key: GUID; name: ptr UncheckedArray[Utf16Char];
      layer: GUID; weight: uint64; actionType: uint32;
      conditions: openArray[FWPM_FILTER_CONDITION0]) =
    # Build SwCondDesc array from the Nim-built conditions, then delegate
    # to the C shim which constructs FWPM_FILTER0 in C (avoiding Nim GC
    # issues with the WFP RPC stack).
    var descs: array[4, SwCondDesc]
    let n = min(conditions.len, 4)
    for i in 0 ..< n:
      let c = conditions[i]
      descs[i].fieldKey = guidToBytes(c.fieldKey)
      descs[i].matchType = c.matchType
      descs[i].kind = c.conditionValue.kind
      descs[i].pad = 0
      # Extract the value based on kind
      case c.conditionValue.kind
      of FWP_V4_ADDR_MASK:
        let v4 = c.conditionValue.data.v4AddrMask
        if v4 != nil:
          descs[i].value = uint64(v4[].addr4) or (uint64(v4[].mask) shl 32)
      of FWP_BYTE_ARRAY16_TYPE:
        descs[i].value = cast[uint64](c.conditionValue.data.v6Addr)
      of FWP_SECURITY_DESCRIPTOR:
        descs[i].value = cast[uint64](c.conditionValue.data.sd)
      of FWP_RANGE:
        descs[i].value = cast[uint64](c.conditionValue.data.rangeValue)
      else:
        descs[i].value = 0
    var id: uint64
    var keyBytes = guidToBytes(key)
    let rc = swFilterAdd(engine, cast[ptr byte](unsafeAddr providerKey),
      addr keyBytes[0], cast[ptr byte](unsafeAddr sublayerKey),
      cast[ptr byte](unsafeAddr layer), weight, name, actionType,
      addr descs[0], n.uint32, addr id)
    if rc != 0: fail("FwpmFilterAdd0", rc)

  proc installFence*(userSid: string; firstPort, lastPort: uint16) =
    ## Idempotent install: provider + sublayer (tolerate existing),
    ## delete any previous filters of ours, then the 4 filters.
    doAssert validPortRange(firstPort, lastPort)
    let engine = openEngine(allocWide("sandwall-setup"))
    defer: discard fwpmEngineClose0(engine)
    ensureProviderAndSublayer(engine)
    for id in enumOurFilters(engine):
      discard fwpmFilterDeleteById0(engine, id)

    # port range condition storage (referenced by pointer)
    var lo = FWP_VALUE0(kind: FWP_UINT16)
    lo.data.uint16Value = firstPort
    var hi = FWP_VALUE0(kind: FWP_UINT16)
    hi.data.uint16Value = lastPort
    var rng = FWP_RANGE0(valueLow: lo, valueHigh: hi)
    var portCond: FWPM_FILTER_CONDITION0
    portCond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT
    portCond.matchType = FWP_MATCH_RANGE
    portCond.conditionValue.kind = FWP_RANGE
    portCond.conditionValue.data.rangeValue = addr rng

    # v4 permit: remote addr in 127.0.0.0/8 AND remote port in range.
    # Addrs are in network order: 127.0.0.0 = 0x7F000000, /8 mask.
    var v4am = FWP_V4_ADDR_AND_MASK(addr4: 0x7F000000'u32,
      mask: 0xFF000000'u32)
    var permitV4Cond: array[2, FWPM_FILTER_CONDITION0]
    permitV4Cond[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS
    permitV4Cond[0].matchType = FWP_MATCH_EQUAL
    permitV4Cond[0].conditionValue.kind = FWP_V4_ADDR_MASK
    permitV4Cond[0].conditionValue.data.v4AddrMask = addr v4am
    permitV4Cond[1] = portCond
    addFilter(engine, permitV4Key, allocWide("sandwall-permit-v4"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0x0F80_0000_0000_0000'u64,
      FWP_ACTION_PERMIT, permitV4Cond)

    # block condition: ALE_USER_ID vs SDDL-built security descriptor
    var sd: pointer
    var sdSize: DWORD
    let sddl = allocWide(sddlForUserSid(userSid))
    if convertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1,
        addr sd, addr sdSize) == 0:
      fail("ConvertStringSecurityDescriptorToSecurityDescriptorW",
        DWORD(getLastError()))
    defer: discard localFree(sd)
    var sdBlob = FWP_BYTE_BLOB(size: uint32(sdSize), data: cast[ptr uint8](sd))
    var blockCond: array[1, FWPM_FILTER_CONDITION0]
    blockCond[0].fieldKey = FWPM_CONDITION_ALE_USER_ID
    blockCond[0].matchType = FWP_MATCH_EQUAL
    blockCond[0].conditionValue.kind = FWP_SECURITY_DESCRIPTOR
    blockCond[0].conditionValue.data.sd = addr sdBlob

    addFilter(engine, blockV4Key, allocWide("sandwall-block-v4"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0x0F40_0000_0000_0000'u64,
      FWP_ACTION_BLOCK, blockCond)

    # v6 permit: remote addr == ::1 AND remote port in range
    var loopback6: FWP_BYTE_ARRAY16
    loopback6.bytes[15] = 1
    var permitV6Cond: array[2, FWPM_FILTER_CONDITION0]
    permitV6Cond[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS
    permitV6Cond[0].matchType = FWP_MATCH_EQUAL
    permitV6Cond[0].conditionValue.kind = FWP_V6_ADDR_MASK
    permitV6Cond[0].conditionValue.data.v6Addr = addr loopback6
    permitV6Cond[1] = portCond
    addFilter(engine, permitV6Key, allocWide("sandwall-permit-v6"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0x0F80_0000_0000_0000'u64,
      FWP_ACTION_PERMIT, permitV6Cond)

    addFilter(engine, blockV6Key, allocWide("sandwall-block-v6"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0x0F40_0000_0000_0000'u64,
      FWP_ACTION_BLOCK, blockCond)

  proc uninstallFence*() =
    ## Remove our filters, sublayer and provider. Missing objects are
    ## tolerated so uninstall is safe to run repeatedly.
    let engine = openEngine(allocWide("sandwall-setup"))
    defer: discard fwpmEngineClose0(engine)
    for id in enumOurFilters(engine):
      discard fwpmFilterDeleteById0(engine, id)
    discard fwpmSubLayerDeleteByKey0(engine, unsafeAddr sublayerKey)
    discard fwpmProviderDeleteByKey0(engine, unsafeAddr providerKey)

  proc fenceStatus*(): tuple[installed: bool; filters: int; hint: string] =
    ## Enum-based status. Access denied (non-admin) is not an error:
    ## report it with a hint pointing at the behavioral check.
    var engine: Handle
    var session: FWPM_SESSION0
    zeroMem(addr session, sizeof(session))
    let name = allocWide("sandwall-status")
    session.displayData.name = name
    session.displayData.description = name
    let rc = fwpmEngineOpen0(nil, RPC_C_AUTHN_DEFAULT, nil,
      addr session, addr engine)
    if rc == DWORD(ERROR_ACCESS_DENIED):
      return (false, 0,
        "WFP status needs admin; run the sandwall-user behavioral " &
        "verify (verifyFenceBehavioral) for a non-elevated check")
    if rc != 0: fail("FwpmEngineOpen0", rc)
    defer: discard fwpmEngineClose0(engine)
    let ids = enumOurFilters(engine)
    (ids.len > 0, ids.len, "")

  proc wfpProbeMain*(): int =
    ## Self-command run AS the sandwall user (see
    ## winuser.verifyFenceBehavioral): attempt a TCP connect to
    ## 192.0.2.1:9 (TEST-NET-1). The fence blocks with WSAEACCES
    ## (10013) before routing matters, so the address being unroutable
    ## is irrelevant. Returns 0 iff the probe was blocked. The
    ## consumer (3code) wires one line: `<self> wall wfp-probe` ->
    ## this proc.
    let s = newSocket()
    defer: s.close()
    try:
      s.connect("192.0.2.1", Port(9), timeout = 5000)
      result = 1  # connected: fence missing
    except OSError as e:
      # WSAEACCES = 10013: blocked by the fence
      result = (if e.errorCode.int32 == 10013'i32: 0 else: 2)

  proc convertSidToStringSidW(sid: PSID; str: ptr WideCString): WINBOOL {.stdcall,
      dynlib: "advapi32", importc: "ConvertSidToStringSidW".}

  proc getAppContainerSidString*(): string =
    ## Derive the `sandwall.fs` AppContainer SID and return it as its
    ## canonical S-string form (S-1-15-2-...). Uses the existing SDDL
    ## builder to feed ALE_USER_ID conditions (AppContainer processes
    ## run under their AC SID as the token user).
    let name = allocWide("sandwall.fs")
    var sid: PSID = nil
    let hr = deriveAppContainerSidFromAppContainerName(name, addr sid)
    if hr != 0'i32:
      fail("DeriveAppContainerSidFromAppContainerName", cast[DWORD](hr))
    var wstr: WideCString = nil
    if convertSidToStringSidW(sid, addr wstr) == 0:
      fail("ConvertSidToStringSidW", DWORD(getLastError()))
    result = $wstr
    discard localFree(wstr)

  proc buildAcSdBlob(): tuple[blob: FWP_BYTE_BLOB, sd: pointer] =
    ## Build the FWP_BYTE_BLOB wrapping a self-relative security
    ## descriptor whose DACL grants Connect access to the
    ## `sandwall.fs` AppContainer SID. The caller must localFree
    ## result.sd.
    let acSid = getAppContainerSidString()
    var sd: pointer
    var sdSize: DWORD
    let sddl = allocWide(sddlForUserSid(acSid))
    if convertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1,
        addr sd, addr sdSize) == 0:
      fail("ConvertStringSecurityDescriptorToSecurityDescriptorW",
        DWORD(getLastError()))
    result = (FWP_BYTE_BLOB(size: uint32(sdSize),
      data: cast[ptr uint8](sd)), sd)

  proc installAcFence*() =
    let engine = openEngine(allocWide("sandwall-ac-setup"))
    defer: discard fwpmEngineClose0(engine)
    ensureProviderAndSublayer(engine)
    let (acSidBlob, sd) = buildAcSdBlob()
    defer: discard localFree(sd)

    var v4am = FWP_V4_ADDR_AND_MASK(addr4: 0x7F000000'u32, mask: 0xFF000000'u32)
    var permitV4Cond: array[2, FWPM_FILTER_CONDITION0]
    permitV4Cond[0].fieldKey = FWPM_CONDITION_ALE_USER_ID
    permitV4Cond[0].matchType = FWP_MATCH_EQUAL
    permitV4Cond[0].conditionValue.kind = FWP_SECURITY_DESCRIPTOR
    permitV4Cond[0].conditionValue.data.sd = addr acSidBlob
    permitV4Cond[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS
    permitV4Cond[1].matchType = FWP_MATCH_EQUAL
    permitV4Cond[1].conditionValue.kind = FWP_V4_ADDR_MASK
    permitV4Cond[1].conditionValue.data.v4AddrMask = addr v4am
    addFilter(engine, parseGuid(acPermitV4GuidText), allocWide("sandwall-ac-permit-v4"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0x0F80_0000_0000_0000'u64, FWP_ACTION_PERMIT, permitV4Cond)

    var blockV4Cond: array[1, FWPM_FILTER_CONDITION0]
    blockV4Cond[0].fieldKey = FWPM_CONDITION_ALE_USER_ID
    blockV4Cond[0].matchType = FWP_MATCH_EQUAL
    blockV4Cond[0].conditionValue.kind = FWP_SECURITY_DESCRIPTOR
    blockV4Cond[0].conditionValue.data.sd = addr acSidBlob
    addFilter(engine, parseGuid(acBlockV4GuidText), allocWide("sandwall-ac-block-v4"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0x0F40_0000_0000_0000'u64, FWP_ACTION_BLOCK, blockV4Cond)

    var loopback6: FWP_BYTE_ARRAY16
    loopback6.bytes[15] = 1
    var permitV6Cond: array[2, FWPM_FILTER_CONDITION0]
    permitV6Cond[0].fieldKey = FWPM_CONDITION_ALE_USER_ID
    permitV6Cond[0].matchType = FWP_MATCH_EQUAL
    permitV6Cond[0].conditionValue.kind = FWP_SECURITY_DESCRIPTOR
    permitV6Cond[0].conditionValue.data.sd = addr acSidBlob
    permitV6Cond[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS
    permitV6Cond[1].matchType = FWP_MATCH_EQUAL
    permitV6Cond[1].conditionValue.kind = FWP_V6_ADDR_MASK
    permitV6Cond[1].conditionValue.data.v6Addr = addr loopback6
    addFilter(engine, parseGuid(acPermitV6GuidText), allocWide("sandwall-ac-permit-v6"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0x0F80_0000_0000_0000'u64, FWP_ACTION_PERMIT, permitV6Cond)

    var blockV6Cond: array[1, FWPM_FILTER_CONDITION0]
    blockV6Cond[0].fieldKey = FWPM_CONDITION_ALE_USER_ID
    blockV6Cond[0].matchType = FWP_MATCH_EQUAL
    blockV6Cond[0].conditionValue.kind = FWP_SECURITY_DESCRIPTOR
    blockV6Cond[0].conditionValue.data.sd = addr acSidBlob
    addFilter(engine, parseGuid(acBlockV6GuidText), allocWide("sandwall-ac-block-v6"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0x0F40_0000_0000_0000'u64, FWP_ACTION_BLOCK, blockV6Cond)

  proc uninstallAcFence*() =
    let engine = openEngine(allocWide("sandwall-ac-setup"))
    defer: discard fwpmEngineClose0(engine)
    for keyText in [acPermitV4GuidText, acBlockV4GuidText, acPermitV6GuidText, acBlockV6GuidText]:
      let key = parseGuid(keyText)
      discard fwpmFilterDeleteByKey0(engine, unsafeAddr key)

  proc acFenceStatus*(): tuple[installed: bool; filters: int; hint: string] =
    var engine: Handle
    var session: FWPM_SESSION0
    zeroMem(addr session, sizeof(session))
    let name = allocWide("sandwall-ac-status")
    session.displayData.name = name
    session.displayData.description = name
    let rc = fwpmEngineOpen0(nil, RPC_C_AUTHN_DEFAULT, nil, addr session, addr engine)
    if rc == DWORD(ERROR_ACCESS_DENIED):
      return (false, 0, "WFP status needs admin; run 'sandwall setup' elevated")
    if rc != 0: fail("FwpmEngineOpen0", rc)
    defer: discard fwpmEngineClose0(engine)

    var found = 0
    for keyText in [acPermitV4GuidText, acBlockV4GuidText, acPermitV6GuidText, acBlockV6GuidText]:
      var eh: Handle
      let rc2 = fwpmFilterCreateEnumHandle0(engine, nil, addr eh)
      if rc2 != 0:
        fail("fwpmFilterCreateEnumHandle0", rc2)
      var entries: ptr UncheckedArray[ptr FWPM_FILTER0]
      var n: uint32
      let erc = fwpmFilterEnum0(engine, eh, 256, addr entries, addr n)
      discard fwpmFilterDestroyEnumHandle0(engine, eh)
      if erc != 0:
        fail("fwpmFilterEnum0", erc)
      for i in 0 ..< n.int:
        if entries[i][].filterKey == parseGuid(keyText):
          inc found
      var entriesP: pointer = entries
      fwpmFreeMemory0(addr entriesP)

    (found == 4, found, "")
