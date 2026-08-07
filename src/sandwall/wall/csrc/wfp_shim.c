// C shim for WFP operations. Nim's ORC GC interacts badly with the
// WFP RPC stack when structs containing GC-managed pointers are
// passed across the FFI boundary (SIGSEGV in FwpmProviderAdd0 etc).
// This shim constructs the WFP structs in C, avoiding all Nim GC
// involvement in the RPC path.
#include <windows.h>
#include <fwpmu.h>
#include <string.h>

DWORD sw_provider_add(HANDLE engine, const void* raw_guid, const wchar_t* name) {
    FWPM_PROVIDER0 prov;
    ZeroMemory(&prov, sizeof(prov));
    memcpy(&prov.providerKey, raw_guid, sizeof(GUID));
    prov.displayData.name = (PWSTR)name;
    prov.displayData.description = (PWSTR)name;
    return FwpmProviderAdd0(engine, &prov, NULL);
}

DWORD sw_sublayer_add(HANDLE engine, const void* raw_guid,
                      const wchar_t* name, UINT16 weight) {
    FWPM_SUBLAYER0 sub;
    ZeroMemory(&sub, sizeof(sub));
    memcpy(&sub.subLayerKey, raw_guid, sizeof(GUID));
    sub.displayData.name = (PWSTR)name;
    sub.displayData.description = (PWSTR)name;
    sub.weight = weight;
    return FwpmSubLayerAdd0(engine, &sub, NULL);
}

// Add a filter with one or two conditions. Each condition is described
// by a flat struct: fieldKey(16 bytes) + matchType(4 bytes) + kind(4 bytes)
// + value(8 bytes, either inline or pointer depending on kind).
// For simplicity we pre-define two condition shapes used by the fence:
// 1. ALE_USER_ID == SD (security descriptor blob)
// 2. IP_REMOTE_ADDRESS == v4 mask or v6 addr

// Condition descriptor passed from Nim. We avoid passing FWPM_FILTER_CONDITION0
// directly because Nim's struct layout may not match C's exactly.
typedef struct {
    BYTE fieldKey[16];     // GUID
    UINT32 matchType;      // FWP_MATCH_EQUAL etc
    UINT32 kind;           // FWP_DATA_TYPE
    UINT32 pad;
    UINT64 value;          // pointer or inline value
} sw_cond_desc;

DWORD sw_filter_add(HANDLE engine,
                    const void* provider_guid,   // NULL = no provider
                    const void* filter_key,      // NULL = auto-generate
                    const void* sublayer_guid,
                    const void* layer_guid,
                    UINT64 weight,
                    const wchar_t* name,
                    UINT32 action_type,
                    const sw_cond_desc* conds,
                    UINT32 num_conds,
                    UINT64* out_id) {
    FWPM_FILTER_CONDITION0 conditions[4];
    FWP_V4_ADDR_AND_MASK v4am;
    FWP_BYTE_ARRAY16 v6addr;
    FWP_BYTE_BLOB sd_blob;
    FWP_RANGE0 port_range;
    UINT16 port_lo, port_hi;
    UINT64 weight_val = weight;
    UINT8 weight_u8 = 0x0F; /* fallback if UINT64 fails */

    ZeroMemory(conditions, sizeof(conditions));
    if (num_conds > 4) num_conds = 4;

    for (UINT32 i = 0; i < num_conds; i++) {
        const sw_cond_desc* c = &conds[i];
        memcpy(&conditions[i].fieldKey, c->fieldKey, 16);
        conditions[i].matchType = c->matchType;
        conditions[i].conditionValue.type = c->kind;
        switch (c->kind) {
        case FWP_V4_ADDR_MASK:
            // value is a pointer to FWP_V4_ADDR_AND_MASK (8 bytes inline)
            v4am.addr = (UINT32)(c->value & 0xFFFFFFFF);
            v4am.mask = (UINT32)(c->value >> 32);
            conditions[i].conditionValue.v4AddrMask = &v4am;
            break;
        case FWP_BYTE_ARRAY16_TYPE:
            // value is a pointer to 16-byte array
            memcpy(v6addr.byteArray16, (void*)(UINT_PTR)c->value, 16);
            conditions[i].conditionValue.byteArray16 = &v6addr;
            break;
        case FWP_SECURITY_DESCRIPTOR_TYPE:
            // value is a pointer to FWP_BYTE_BLOB
            sd_blob.size = ((FWP_BYTE_BLOB*)(UINT_PTR)c->value)->size;
            sd_blob.data = ((FWP_BYTE_BLOB*)(UINT_PTR)c->value)->data;
            conditions[i].conditionValue.sd = &sd_blob;
            break;
        case FWP_RANGE_TYPE:
            // value is two UINT16 port values packed: lo in low 16, hi in next 16
            port_lo = (UINT16)(c->value & 0xFFFF);
            port_hi = (UINT16)((c->value >> 16) & 0xFFFF);
            port_range.valueLow.type = FWP_UINT16;
            port_range.valueLow.uint16 = port_lo;
            port_range.valueHigh.type = FWP_UINT16;
            port_range.valueHigh.uint16 = port_hi;
            conditions[i].conditionValue.rangeValue = &port_range;
            break;
        }
    }

    FWPM_FILTER0 filt;
    ZeroMemory(&filt, sizeof(filt));
    if (filter_key) memcpy(&filt.filterKey, filter_key, sizeof(GUID));
    if (provider_guid) filt.providerKey = (GUID*)provider_guid;
    memcpy(&filt.layerKey, layer_guid, sizeof(GUID));
    memcpy(&filt.subLayerKey, sublayer_guid, sizeof(GUID));
    filt.displayData.name = (PWSTR)name;
    filt.displayData.description = (PWSTR)name;
    filt.weight.type = FWP_EMPTY; /* let BFE auto-assign */
    filt.numFilterConditions = num_conds;
    filt.filterCondition = (num_conds > 0) ? conditions : NULL;
    filt.action.type = action_type;

    return FwpmFilterAdd0(engine, &filt, NULL, out_id);
}
