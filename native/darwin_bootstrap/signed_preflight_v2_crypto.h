#ifndef BH_SIGNED_PREFLIGHT_V2_CRYPTO_H
#define BH_SIGNED_PREFLIGHT_V2_CRYPTO_H

#include "signed_preflight_v2.h"

#include <stddef.h>
#include <stdint.h>

/* A valid result establishes consistency with the supplied key only. It does
 * not pin that key, admit a process, or authorize an installed policy. Caller
 * spans must remain readable and stable until all four owned copies finish. */
enum bh_v2_crypto_status {
    BH_V2_CRYPTO_DENY = 0,
    BH_V2_CRYPTO_VALID_ONLY,
    BH_V2_CRYPTO_DENY_ARGUMENT,
    BH_V2_CRYPTO_DENY_POLICY_WIRE,
    BH_V2_CRYPTO_DENY_KEY,
    BH_V2_CRYPTO_DENY_SIGNATURE_FORMAT,
    BH_V2_CRYPTO_DENY_SIGNATURE,
    BH_V2_CRYPTO_DENY_STRUCTURE,
    BH_V2_CRYPTO_UNAVAILABLE
};

struct bh_v2_crypto_result {
    enum bh_v2_crypto_status status;
    /* Meaningful only for BH_V2_CRYPTO_DENY_STRUCTURE. */
    enum bh_v2_structure_status structure_reason;
};

struct bh_v2_crypto_result bh_v2_check_signed_pair(
    const uint8_t *policy, size_t policy_len,
    const uint8_t *manifest, size_t manifest_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key, size_t public_key_len);

#endif
