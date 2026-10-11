#include "signed_preflight_v2_crypto.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { BH_POLICY_HEADER = 48, BH_POLICY_MAX = 65584,
       BH_MANIFEST_MIN = 16, BH_MANIFEST_MAX = 65552,
       BH_RAW_SIGNATURE = 64, BH_X963_KEY = 65 };

struct bh_v2_snapshots {
    uint8_t *policy;
    size_t policy_len;
    uint8_t *manifest;
    size_t manifest_len;
    uint8_t signature[BH_RAW_SIGNATURE];
    uint8_t key[BH_X963_KEY];
};

static const uint8_t bh_p256_order[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,
    0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51
};

static bool bh_nonzero(const uint8_t *bytes, size_t len) {
    uint8_t combined = 0;
    for (size_t i = 0; i < len; i++) combined |= bytes[i];
    return combined != 0;
}

static uint16_t bh_u16(const uint8_t *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t bh_u32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16)
        | ((uint32_t)bytes[2] << 8) | bytes[3];
}

static bool bh_policy_header_valid(const uint8_t *policy, size_t len) {
    static const uint8_t magic[8] = {'B','H','P','O','L','2',0,0};
    uint32_t body_len = bh_u32(policy + 12);
    return memcmp(policy, magic, sizeof(magic)) == 0
        && bh_u16(policy + 8) == 2
        && bh_u16(policy + 10) == BH_POLICY_HEADER
        && body_len >= 1 && body_len <= 65536
        && len == BH_POLICY_HEADER + (size_t)body_len
        && bh_nonzero(policy + 16, 32);
}

static bool bh_canonical_raw_signature(const uint8_t signature[BH_RAW_SIGNATURE]) {
    uint8_t half_order[32];
    unsigned carry = 0;
    for (size_t i = 0; i < sizeof(half_order); i++) {
        half_order[i] = (uint8_t)((bh_p256_order[i] >> 1) | carry);
        carry = (bh_p256_order[i] & 1u) ? 0x80u : 0u;
    }
    return bh_nonzero(signature, 32)
        && memcmp(signature, bh_p256_order, 32) < 0
        && bh_nonzero(signature + 32, 32)
        && memcmp(signature + 32, half_order, 32) <= 0;
}

static bool bh_p256_public_attributes(SecKeyRef key) {
    bool valid = false;
    CFDictionaryRef attrs = SecKeyCopyAttributes(key);
    if (attrs == NULL) return false;
    if (CFGetTypeID(attrs) == CFDictionaryGetTypeID()) {
        CFTypeRef key_type = CFDictionaryGetValue(attrs, kSecAttrKeyType);
        CFTypeRef key_class = CFDictionaryGetValue(attrs, kSecAttrKeyClass);
        CFTypeRef bits = CFDictionaryGetValue(attrs, kSecAttrKeySizeInBits);
        int32_t size = 0;
        valid = key_type != NULL && key_class != NULL && bits != NULL
            && CFGetTypeID(key_type) == CFStringGetTypeID()
            && CFGetTypeID(key_class) == CFStringGetTypeID()
            && CFGetTypeID(bits) == CFNumberGetTypeID()
            && CFEqual(key_type, kSecAttrKeyTypeECSECPrimeRandom)
            && CFEqual(key_class, kSecAttrKeyClassPublic)
            && CFNumberGetValue((CFNumberRef)bits, kCFNumberSInt32Type, &size)
            && size == 256;
    }
    CFRelease(attrs);
    return valid;
}

static enum bh_v2_crypto_status bh_verify_with_apple(
    const uint8_t key_bytes[BH_X963_KEY], const uint8_t signature[BH_RAW_SIGNATURE],
    const uint8_t digest[CC_SHA256_DIGEST_LENGTH]) {
    enum bh_v2_crypto_status status = BH_V2_CRYPTO_UNAVAILABLE;
    CFDataRef key_data = NULL;
    CFDictionaryRef import_attrs = NULL;
    CFDataRef digest_data = NULL;
    CFDataRef signature_data = NULL;
    CFErrorRef error = NULL;
    SecKeyRef key = NULL;
    const void *attr_keys[2] = {kSecAttrKeyType, kSecAttrKeyClass};
    const void *attr_values[2] = {kSecAttrKeyTypeECSECPrimeRandom,
                                  kSecAttrKeyClassPublic};
    bool verified;

    key_data = CFDataCreate(kCFAllocatorDefault, key_bytes, BH_X963_KEY);
    if (key_data == NULL) goto cleanup;
    import_attrs = CFDictionaryCreate(kCFAllocatorDefault, attr_keys, attr_values,
                                      2, &kCFTypeDictionaryKeyCallBacks,
                                      &kCFTypeDictionaryValueCallBacks);
    if (import_attrs == NULL) goto cleanup;
    key = SecKeyCreateWithData(key_data, import_attrs, &error);
    if (key == NULL) {
        status = error != NULL ? BH_V2_CRYPTO_DENY_KEY : BH_V2_CRYPTO_UNAVAILABLE;
        goto cleanup;
    }
    if (error != NULL) goto cleanup;
    if (!bh_p256_public_attributes(key)) goto cleanup;
    if (!SecKeyIsAlgorithmSupported(key, kSecKeyOperationTypeVerify,
            kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256)) goto cleanup;

    digest_data = CFDataCreate(kCFAllocatorDefault, digest, CC_SHA256_DIGEST_LENGTH);
    signature_data = CFDataCreate(kCFAllocatorDefault, signature, BH_RAW_SIGNATURE);
    if (digest_data == NULL || signature_data == NULL) goto cleanup;
    verified = SecKeyVerifySignature(
        key, kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256,
        digest_data, signature_data, &error);
    if (error != NULL && verified) goto cleanup;
    status = verified ? BH_V2_CRYPTO_VALID_ONLY : BH_V2_CRYPTO_DENY_SIGNATURE;

cleanup:
    if (error != NULL) CFRelease(error);
    if (signature_data != NULL) CFRelease(signature_data);
    if (digest_data != NULL) CFRelease(digest_data);
    if (key != NULL) CFRelease(key);
    if (import_attrs != NULL) CFRelease(import_attrs);
    if (key_data != NULL) CFRelease(key_data);
    return status;
}

struct bh_v2_crypto_result bh_v2_check_signed_pair(
    const uint8_t *policy, size_t policy_len,
    const uint8_t *manifest, size_t manifest_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key, size_t public_key_len) {
    static const uint8_t domain[] = "BeeHermes.OperatorPolicy.v2";
    struct bh_v2_crypto_result result = {BH_V2_CRYPTO_DENY, BH_V2_DENY_ARGUMENT};
    struct bh_v2_snapshots snapshot = {0};
    uint8_t key_id[CC_SHA256_DIGEST_LENGTH];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    uint8_t *preimage = NULL;
    size_t preimage_len;
    enum bh_v2_structure_status structure;

    /* No pointed-to byte is read before every pointer and length is checked. */
    if (policy == NULL || manifest == NULL || signature == NULL || public_key == NULL
        || policy_len < BH_POLICY_HEADER || policy_len > BH_POLICY_MAX
        || manifest_len < BH_MANIFEST_MIN || manifest_len > BH_MANIFEST_MAX) {
        result.status = BH_V2_CRYPTO_DENY_ARGUMENT;
        return result;
    }
    if (signature_len != BH_RAW_SIGNATURE) {
        result.status = BH_V2_CRYPTO_DENY_SIGNATURE_FORMAT;
        return result;
    }
    if (public_key_len != BH_X963_KEY) {
        result.status = BH_V2_CRYPTO_DENY_KEY;
        return result;
    }

    snapshot.policy_len = policy_len;
    snapshot.manifest_len = manifest_len;
    snapshot.policy = malloc(policy_len);
    snapshot.manifest = malloc(manifest_len);
    if (snapshot.policy == NULL || snapshot.manifest == NULL) {
        result.status = BH_V2_CRYPTO_UNAVAILABLE;
        goto cleanup;
    }
    memcpy(snapshot.policy, policy, policy_len);
    memcpy(snapshot.manifest, manifest, manifest_len);
    memcpy(snapshot.signature, signature, BH_RAW_SIGNATURE);
    memcpy(snapshot.key, public_key, BH_X963_KEY);
    /* From here onward only owned snapshot addresses are used. */

    if (!bh_policy_header_valid(snapshot.policy, snapshot.policy_len)) {
        result.status = BH_V2_CRYPTO_DENY_POLICY_WIRE;
        goto cleanup;
    }
    if (snapshot.key[0] != 0x04) {
        result.status = BH_V2_CRYPTO_DENY_KEY;
        goto cleanup;
    }
    if (CC_SHA256(snapshot.key, BH_X963_KEY, key_id) == NULL) {
        result.status = BH_V2_CRYPTO_UNAVAILABLE;
        goto cleanup;
    }
    if (memcmp(snapshot.policy + 16, key_id, sizeof(key_id)) != 0) {
        result.status = BH_V2_CRYPTO_DENY_KEY;
        goto cleanup;
    }
    if (!bh_canonical_raw_signature(snapshot.signature)) {
        result.status = BH_V2_CRYPTO_DENY_SIGNATURE_FORMAT;
        goto cleanup;
    }
    if (snapshot.policy_len > SIZE_MAX - sizeof(domain)) {
        result.status = BH_V2_CRYPTO_UNAVAILABLE;
        goto cleanup;
    }
    preimage_len = sizeof(domain) + snapshot.policy_len;
    preimage = malloc(preimage_len);
    if (preimage == NULL) {
        result.status = BH_V2_CRYPTO_UNAVAILABLE;
        goto cleanup;
    }
    memcpy(preimage, domain, sizeof(domain)); /* Includes the single 00 separator. */
    memcpy(preimage + sizeof(domain), snapshot.policy, snapshot.policy_len);
    if (CC_SHA256(preimage, (CC_LONG)preimage_len, digest) == NULL) {
        result.status = BH_V2_CRYPTO_UNAVAILABLE;
        goto cleanup;
    }
    result.status = bh_verify_with_apple(snapshot.key, snapshot.signature, digest);
    if (result.status != BH_V2_CRYPTO_VALID_ONLY) goto cleanup;

    structure = bh_v2_validate_structure(snapshot.policy, snapshot.policy_len,
                                          snapshot.manifest, snapshot.manifest_len);
    if (structure == BH_V2_STRUCTURE_ONLY) {
        result.status = BH_V2_CRYPTO_VALID_ONLY;
    } else {
        result.status = BH_V2_CRYPTO_DENY_STRUCTURE;
        result.structure_reason = structure;
    }

cleanup:
    free(preimage);
    free(snapshot.manifest);
    free(snapshot.policy);
    return result;
}
