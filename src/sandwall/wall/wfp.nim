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
  import std/winlean except PSID
  import std/[widestrs, net, osproc]
  import ./winffi
  export winffi.PSID

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

    FWP_V6_ADDR_AND_MASK* {.bycopy.} = object
      v6addr: array[16, uint8]
      prefixLength: uint8
      pad: array[7, uint8]

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
      v6AddrMask: ptr FWP_V6_ADDR_AND_MASK
      v6Addr: ptr FWP_BYTE_ARRAY16
      rangeValue: pointer  # ptr FWP_RANGE0
      sd: ptr FWP_BYTE_BLOB
      sid: pointer  # PSID
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
      data4: [0x90'u8, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82])
    FWPM_LAYER_ALE_AUTH_CONNECT_V6 = GUID(data1: 0x4a72393b'u32,
      data2: 0x319f'u16, data3: 0x44bc'u16,
      data4: [0x84'u8, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4])

    # condition fields (fwpmk.h)
    FWPM_CONDITION_IP_REMOTE_ADDRESS = GUID(data1: 0xb235ae9a'u32,
      data2: 0x1d64'u16, data3: 0x49b8'u16,
      data4: [0xa4'u8, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45])
    FWPM_CONDITION_IP_REMOTE_PORT = GUID(data1: 0xc35a604d'u32,
      data2: 0xd22b'u16, data3: 0x4e1a'u16,
      data4: [0x91'u8, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b])
    FWPM_CONDITION_ALE_USER_ID = GUID(data1: 0xaf043a0a'u32,
      data2: 0xb34d'u16, data3: 0x4f86'u16,
      data4: [0x97'u8, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66])

    FWPM_CONDITION_ALE_APP_ID = GUID(data1: 0xd78e1e87'u32,
      data2: 0x8644'u16, data3: 0x4ea5'u16,
      data4: [0x94'u8, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71])
    FWPM_CONDITION_ALE_PACKAGE_ID = GUID(data1: 0x71bc78fa'u32,
      data2: 0xf17c'u16, data3: 0x4997'u16,
      data4: [0xa6'u8, 0x02, 0x6a, 0xbb, 0x26, 0x1f, 0x35, 0x1c])

    FWP_MATCH_EQUAL = 0'u32
    FWP_MATCH_RANGE = 5'u32

    # FWP_DATA_TYPE (fwptypes.h)
    FWP_EMPTY = 0'u32
    FWP_UINT8 = 1'u32
    FWP_UINT16 = 2'u32
    FWP_UINT32 = 3'u32
    FWP_UINT64 = 4'u32
    FWP_BYTE_ARRAY16_TYPE = 11'u32
    FWP_BYTE_BLOB_TYPE = 12'u32
    FWP_SECURITY_DESCRIPTOR = 14'u32
    FWP_SID = 13'u32
    FWP_V4_ADDR_MASK = 0x100'u32
    FWP_V6_ADDR_MASK = 0x101'u32
    FWP_RANGE = 0x102'u32

    FWP_ACTION_BLOCK = 0x00001001'u32
    FWP_ACTION_PERMIT = 0x00001002'u32

    RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF'u32  # FWPM_SESSION0.authnService

    ERROR_ACCESS_DENIED = 5'u32
    FWP_E_ALREADY_EXISTS = 0x80320009'u32
    FWP_E_FILTER_NOT_FOUND = 0x80320003'u32

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

  # SID / security-descriptor / LocalAlloc FFI is shared in winffi.
  # (convertStringSecurityDescriptorToSecurityDescriptorW, getLengthSid,
  # copySid, localAlloc, deriveAppContainerSidFromAppContainerName,
  # convertSidToStringSidW, PSID, HRESULT). localFree comes from winlean.
  proc fwpmFilterDeleteByKey0(engineHandle: Handle;
      key: ptr GUID): DWORD {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmFilterDeleteByKey0".}
  proc fwpmFilterGetByKey0(engineHandle: Handle; key: ptr GUID;
      filter: ptr ptr FWPM_FILTER0): DWORD {.stdcall, dynlib: "fwpuclnt",
      importc: "FwpmFilterGetByKey0".}



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
    while true:
      var entries: ptr UncheckedArray[ptr FWPM_FILTER0]
      var n: uint32
      let erc = fwpmFilterEnum0(engine, eh, 1024, addr entries, addr n)
      if erc != 0: fail("FwpmFilterEnum0", erc)
      if n == 0: break
      var entriesP: pointer = entries
      block:
        defer: fwpmFreeMemory0(addr entriesP)
        for i in 0 ..< n.int:
          let f = entries[i]
          if f[].subLayerKey == sublayerKey:
            result.add f[].filterId

  proc guidToBytes(g: GUID): array[16, byte] = guidBytes(g)

  # --- condition constructors -----------------------------------------
  # Each fence is a permit/block pair over a small set of condition
  # shapes. These build one FWPM_FILTER_CONDITION0; the value storage
  # they point at must outlive the addFilter call (stack locals in the
  # installer procs, which they do).

  proc condRangePort(field: GUID; rng: ptr FWP_RANGE0): FWPM_FILTER_CONDITION0 =
    result.fieldKey = field
    result.matchType = FWP_MATCH_RANGE
    result.conditionValue.kind = FWP_RANGE
    result.conditionValue.data.rangeValue = rng

  proc condV4Mask(field: GUID; m: ptr FWP_V4_ADDR_AND_MASK): FWPM_FILTER_CONDITION0 =
    result.fieldKey = field
    result.matchType = FWP_MATCH_EQUAL
    result.conditionValue.kind = FWP_V4_ADDR_MASK
    result.conditionValue.data.v4AddrMask = m

  proc condV6Mask(field: GUID; m: ptr FWP_V6_ADDR_AND_MASK): FWPM_FILTER_CONDITION0 =
    result.fieldKey = field
    result.matchType = FWP_MATCH_EQUAL
    result.conditionValue.kind = FWP_V6_ADDR_MASK
    result.conditionValue.data.v6AddrMask = m

  proc condSd(field: GUID; sd: ptr FWP_BYTE_BLOB): FWPM_FILTER_CONDITION0 =
    result.fieldKey = field
    result.matchType = FWP_MATCH_EQUAL
    result.conditionValue.kind = FWP_SECURITY_DESCRIPTOR
    result.conditionValue.data.sd = sd

  proc condSid(field: GUID; sid: PSID): FWPM_FILTER_CONDITION0 =
    result.fieldKey = field
    result.matchType = FWP_MATCH_EQUAL
    result.conditionValue.kind = FWP_SID
    result.conditionValue.data.sid = sid

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
      of FWP_V6_ADDR_MASK:
        descs[i].value = cast[uint64](c.conditionValue.data.v6AddrMask)
      of FWP_BYTE_ARRAY16_TYPE:
        descs[i].value = cast[uint64](c.conditionValue.data.v6Addr)
      of FWP_SECURITY_DESCRIPTOR:
        descs[i].value = cast[uint64](c.conditionValue.data.sd)
      of FWP_SID:
        descs[i].value = cast[uint64](c.conditionValue.data.sid)
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
    for key in [permitV4Key, blockV4Key, permitV6Key, blockV6Key]:
      discard fwpmFilterDeleteByKey0(engine, unsafeAddr key)

    # Shared condition value storage (referenced by pointer; stack
    # locals here outlive each addFilter call). Addrs are network
    # order: 127.0.0.0/8 permit, ::1 permit, the proxy port range.
    var lo = FWP_VALUE0(kind: FWP_UINT16)
    lo.data.uint16Value = firstPort
    var hi = FWP_VALUE0(kind: FWP_UINT16)
    hi.data.uint16Value = lastPort
    var rng = FWP_RANGE0(valueLow: lo, valueHigh: hi)
    var portCond = condRangePort(FWPM_CONDITION_IP_REMOTE_PORT, addr rng)
    var v4am = FWP_V4_ADDR_AND_MASK(addr4: 0x7F000000'u32,
      mask: 0xFF000000'u32)
    var loopback6: FWP_V6_ADDR_AND_MASK
    loopback6.v6addr[15] = 1
    loopback6.prefixLength = 128

    # Block: ALE_USER_ID matches the SDDL-built descriptor for userSid.
    var sd: pointer
    var sdSize: DWORD
    let sddl = allocWide(sddlForUserSid(userSid))
    if convertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1,
        addr sd, addr sdSize) == 0:
      fail("ConvertStringSecurityDescriptorToSecurityDescriptorW",
        DWORD(getLastError()))
    defer: localFree(sd)
    var sdBlob = FWP_BYTE_BLOB(size: uint32(sdSize), data: cast[ptr uint8](sd))
    let blockCond = [condSd(FWPM_CONDITION_ALE_USER_ID, addr sdBlob)]

    # v4/v6 permit (loopback + port range), then the block (user SID).
    let permitV4 = [condV4Mask(FWPM_CONDITION_IP_REMOTE_ADDRESS, addr v4am),
                    portCond]
    addFilter(engine, permitV4Key, allocWide("sandwall-permit-v4"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0x0F80_0000_0000_0000'u64,
      FWP_ACTION_PERMIT, permitV4)
    addFilter(engine, blockV4Key, allocWide("sandwall-block-v4"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0x0F40_0000_0000_0000'u64,
      FWP_ACTION_BLOCK, blockCond)
    let permitV6 = [condV6Mask(FWPM_CONDITION_IP_REMOTE_ADDRESS, addr loopback6),
                    portCond]
    addFilter(engine, permitV6Key, allocWide("sandwall-permit-v6"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0x0F80_0000_0000_0000'u64,
      FWP_ACTION_PERMIT, permitV6)
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
    # Also delete by key (covers filters enum may miss on busy systems)
    for key in [permitV4Key, blockV4Key, permitV6Key, blockV6Key]:
      discard fwpmFilterDeleteByKey0(engine, unsafeAddr key)
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
    localFree(wstr)

  proc getAcSidRaw*(): PSID =
    ## Derive the raw PSID for the `sandwall.fs` AppContainer.
    let name = allocWide("sandwall.fs")
    if deriveAppContainerSidFromAppContainerName(name, addr result) != 0:
      fail("DeriveAppContainerSidFromAppContainerName", DWORD(getLastError()))

  proc installAcFence*() =
    ## Idempotent like installFence: delete our previous filters by
    ## key first so a re-run over an existing install does not fail
    ## with FwpmFilterAdd0 ALREADY_EXISTS.
    let engine = openEngine(allocWide("sandwall-ac-setup"))
    defer: discard fwpmEngineClose0(engine)
    ensureProviderAndSublayer(engine)
    for keyText in [acPermitV4GuidText, acBlockV4GuidText,
                    acPermitV6GuidText, acBlockV6GuidText]:
      let key = parseGuid(keyText)
      discard fwpmFilterDeleteByKey0(engine, unsafeAddr key)
    let acSid = getAcSidRaw()

    # Same loopback permits as the user fence, but keyed on the
    # AppContainer package SID instead of the port range + user SD.
    var v4am = FWP_V4_ADDR_AND_MASK(addr4: 0x7F000000'u32, mask: 0xFF000000'u32)
    var loopback6: FWP_V6_ADDR_AND_MASK
    loopback6.v6addr[15] = 1
    loopback6.prefixLength = 128
    let pkgSid = condSid(FWPM_CONDITION_ALE_PACKAGE_ID, acSid)

    let permitV4 = [pkgSid, condV4Mask(FWPM_CONDITION_IP_REMOTE_ADDRESS, addr v4am)]
    addFilter(engine, parseGuid(acPermitV4GuidText), allocWide("sandwall-ac-permit-v4"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0x0F80_0000_0000_0000'u64, FWP_ACTION_PERMIT, permitV4)
    let blockCond = [pkgSid]
    addFilter(engine, parseGuid(acBlockV4GuidText), allocWide("sandwall-ac-block-v4"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0x0F40_0000_0000_0000'u64, FWP_ACTION_BLOCK, blockCond)
    let permitV6 = [pkgSid, condV6Mask(FWPM_CONDITION_IP_REMOTE_ADDRESS, addr loopback6)]
    addFilter(engine, parseGuid(acPermitV6GuidText), allocWide("sandwall-ac-permit-v6"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0x0F80_0000_0000_0000'u64, FWP_ACTION_PERMIT, permitV6)
    addFilter(engine, parseGuid(acBlockV6GuidText), allocWide("sandwall-ac-block-v6"),
      FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0x0F40_0000_0000_0000'u64, FWP_ACTION_BLOCK, blockCond)

  proc uninstallAcFence*() =
    let engine = openEngine(allocWide("sandwall-ac-setup"))
    defer: discard fwpmEngineClose0(engine)
    for keyText in [acPermitV4GuidText, acBlockV4GuidText, acPermitV6GuidText, acBlockV6GuidText]:
      let key = parseGuid(keyText)
      discard fwpmFilterDeleteByKey0(engine, unsafeAddr key)

  proc exemptAcLoopback*() =
    ## Add the `sandwall.fs` AppContainer to the loopback exemption
    ## list. Windows ships a built-in "AppContainerLoopback" block
    ## filter (MPSSVC app-isolation sublayer) that silently drops an
    ## AppContainer child's connects to 127.0.0.1 servers unless the
    ## container is exempted; without this the sandboxed child can
    ## never reach the wall proxy and every proxied request hangs on
    ## SYN. Uses CheckNetIsolation, the supported interface (needs
    ## admin, which setup already requires).
    let rc = execCmd("CheckNetIsolation LoopbackExempt -a -n=sandwall.fs")
    if rc != 0:
      raise newException(OSError,
        "sandwall: CheckNetIsolation LoopbackExempt failed: " & $rc)

  proc unexemptAcLoopback*() =
    ## Remove the loopback exemption. Best-effort: a missing entry is
    ## not an error (uninstall must be safe to run repeatedly).
    discard execCmd("CheckNetIsolation LoopbackExempt -d -n=sandwall.fs")

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
      let key = parseGuid(keyText)
      var fptr: ptr FWPM_FILTER0
      let grc = fwpmFilterGetByKey0(engine, unsafeAddr key, addr fptr)
      if grc == 0:
        inc found
        var p: pointer = fptr
        fwpmFreeMemory0(addr p)
      elif grc != cast[DWORD](FWP_E_FILTER_NOT_FOUND):
        fail("FwpmFilterGetByKey0", grc)

    (found == 4, found, "")
