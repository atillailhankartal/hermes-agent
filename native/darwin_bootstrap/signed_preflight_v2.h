#ifndef BH_SIGNED_PREFLIGHT_V2_H
#define BH_SIGNED_PREFLIGHT_V2_H

#include <stddef.h>
#include <stdint.h>

/* Structure-only observations never authorize a signer, process, or source. */
enum bh_v2_structure_status {
    BH_V2_STRUCTURE_ONLY = 0,
    BH_V2_DENY_ARGUMENT,
    BH_V2_DENY_POLICY_WIRE,
    BH_V2_DENY_POLICY_TLV,
    BH_V2_DENY_MANIFEST_WIRE,
    BH_V2_DENY_MANIFEST_TLV,
    BH_V2_DENY_MANIFEST_DIGEST,
    BH_V2_DENY_ENTRY_TABLE,
    BH_V2_DENY_MODE_MASK,
    BH_V2_DENY_HOST_MODE_MISSING,
    BH_V2_DENY_HOST_TABLE,
    BH_V2_DENY_HOST_ENTRY,
    BH_V2_DENY_MODEL_GRAPH
};

enum bh_v2_structure_status bh_v2_validate_structure(
    const uint8_t *policy, size_t policy_len,
    const uint8_t *manifest, size_t manifest_len);

#endif
