#ifndef BH_SIGNED_PREFLIGHT_V2_KEY_POLICY_H
#define BH_SIGNED_PREFLIGHT_V2_KEY_POLICY_H
#include <stddef.h>
#include <stdint.h>
#include "signed_preflight_v2_crypto.h"

enum bh_key_policy_status {
    BH_KEY_POLICY_DENY = 0,
    BH_KEY_POLICY_CONSISTENT_ONLY,
    BH_KEY_POLICY_DENY_ARGUMENT,
    BH_KEY_POLICY_DENY_CONFIG,
    BH_KEY_POLICY_DENY_POLICY_WIRE,
    BH_KEY_POLICY_DENY_POLICY_TLV,
    BH_KEY_POLICY_DENY_KEY_ID,
    BH_KEY_POLICY_DENY_EPOCH,
    BH_KEY_POLICY_DENY_INSTALLATION,
    BH_KEY_POLICY_DENY_TRANSITION,
    BH_KEY_POLICY_DENY_STRUCTURE,
    BH_KEY_POLICY_DENY_CRYPTO,
    BH_KEY_POLICY_UNAVAILABLE
};
struct bh_key_policy_entry {
    uint8_t id[32];                  /* SHA256 of exact public_key[65] */
    uint8_t public_key[65];          /* uncompressed P-256 X9.63 */
    size_t public_key_len;           /* must equal 65 */
};
struct bh_key_policy_test_config {
    size_t entry_count;              /* exactly 2; no iteration before check */
    struct bh_key_policy_entry entries[2]; /* 0 old, 1 new; never search order */
    uint64_t transition_epoch;
    uint8_t installation_digest[32];
};
/* Dormant consistency only: config provenance is NOT authenticated and this
 * stateless function has no floor/selector or installed consumer.
 * Every non-NULL input must designate readable storage for its declared size;
 * config and bytes remain stable until capture finishes. Accepted lengths are
 * policy 49..65584, manifest 17..65552 and signature 64. Inputs may overlap and
 * need no alignment. They are copied before semantics/callback; no output view
 * escapes. The callback receives owned read-only spans borrowed only until it
 * returns: never retain, free or modify them. ctx is opaque and may be NULL.
 * A callback may mutate original caller buffers after capture. No concurrent
 * source writer during capture is permitted; this is not atomic FD provenance.
 * Only explicit CONSISTENT_ONLY equality indicates local consistency, never
 * installation, operator custody, signer authorization or permission to launch.
 * Test-image-only seam. No callback/config registration in installed code. */
typedef struct bh_v2_crypto_result (*bh_key_policy_test_verify_fn)(
    void *ctx,
    const uint8_t *policy, size_t policy_len,
    const uint8_t *manifest, size_t manifest_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key, size_t public_key_len);
enum bh_key_policy_status bh_v2_check_key_policy_for_test(
    const struct bh_key_policy_test_config *config,
    const uint8_t *policy, size_t policy_len,
    const uint8_t *manifest, size_t manifest_len,
    const uint8_t *signature, size_t signature_len,
    bh_key_policy_test_verify_fn verify, void *ctx);

/* Only explicit test builds expose per-invocation fault injection. */
#ifdef BH_KEY_POLICY_TESTING
enum bh_key_policy_status bh_v2_key_policy_fault_test(
 const struct bh_key_policy_test_config *, const uint8_t *, size_t,
 const uint8_t *, size_t, const uint8_t *, size_t,
 bh_key_policy_test_verify_fn, void *, unsigned, unsigned);
#endif
#endif
