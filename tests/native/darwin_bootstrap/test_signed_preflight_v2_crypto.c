#include "signed_preflight_v2_crypto.h"

#include <CommonCrypto/CommonDigest.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { POLICY_CAP = 65585, MANIFEST_CAP = 65553, EXPECTED_CASES = 47 };

struct fixture {
    uint8_t policy[POLICY_CAP];
    uint8_t manifest[MANIFEST_CAP];
    uint8_t signature[72];
    uint8_t key[66];
    size_t policy_len, manifest_len, signature_len, key_len;
};

static const uint8_t p256_order[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,
    0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51
};
static const uint8_t p256_base_point[65] = {
    0x04,0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,
    0xe5,0x63,0xa4,0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,
    0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,
    0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,
    0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
};

static const char *names[EXPECTED_CASES] = {
    "CheckSignedPair_WhenS2FrozenPair_ReturnsCryptoValidOnly",
    "CheckSignedPair_WhenSignedGatewayHostMissing_DeniesHostModeMissing",
    "CheckSignedPair_WhenSignedGatewayHostSubstituted_DeniesHostEntry",
    "CheckSignedPair_WhenResultZeroInitialized_RemainsDenial",
    "CheckSignedPair_WhenPolicyBodyByteTampered_DeniesSignature",
    "CheckSignedPair_WhenRawRByteTampered_DeniesSignature",
    "CheckSignedPair_WhenRawSByteTampered_DeniesSignature",
    "CheckSignedPair_WhenS2PolicyWithMissingHostSignature_DeniesSignature",
    "CheckSignedPair_WhenSubstitutedHostPolicyWithS2Signature_DeniesSignature",
    "CheckSignedPair_WhenWrongValidPublicKey_DeniesKey",
    "CheckSignedPair_WhenWrongKeyIdReboundButS2Signature_DeniesSignature",
    "CheckSignedPair_WhenOffCurveKeyWithMatchingHeaderId_DeniesKey",
    "CheckSignedPair_WhenPublicKeyPrefixWrong_DeniesKey",
    "CheckSignedPair_WhenPublicKeyLength64_DeniesKey",
    "CheckSignedPair_WhenPublicKeyLength66_DeniesKey",
    "CheckSignedPair_WhenMissingHostManifestSwapped_DeniesManifestDigest",
    "CheckSignedPair_WhenSubstitutedHostManifestSwapped_DeniesManifestDigest",
    "CheckSignedPair_WhenManifestValueByteTampered_DeniesManifestDigest",
    "CheckSignedPair_WhenV1ManifestMagic_DeniesManifestWire",
    "CheckSignedPair_WhenManifestHeaderOnly_DeniesManifestWire",
    "CheckSignedPair_WhenManifestSuffix_DeniesManifestWire",
    "CheckSignedPair_WhenV1PolicyMagic_DeniesPolicyWire",
    "CheckSignedPair_WhenPolicyBodyLengthMismatch_DeniesPolicyWire",
    "CheckSignedPair_WhenPolicySuffix_DeniesPolicyWire",
    "CheckSignedPair_WhenPolicyHeaderOnly_DeniesPolicyWire",
    "CheckSignedPair_WhenPolicyTruncated_DeniesPolicyWire",
    "CheckSignedPair_WhenPolicyNull_DeniesArgument",
    "CheckSignedPair_WhenManifestNull_DeniesArgument",
    "CheckSignedPair_WhenSignatureNull_DeniesArgument",
    "CheckSignedPair_WhenPublicKeyNull_DeniesArgument",
    "CheckSignedPair_WhenPolicyLength47_DeniesArgument",
    "CheckSignedPair_WhenPolicyLength65585_DeniesArgument",
    "CheckSignedPair_WhenManifestLength15_DeniesArgument",
    "CheckSignedPair_WhenManifestLength65553_DeniesArgument",
    "CheckSignedPair_WhenSignatureLength0_DeniesSignatureFormat",
    "CheckSignedPair_WhenSignatureLength63_DeniesSignatureFormat",
    "CheckSignedPair_WhenSignatureLength65_DeniesSignatureFormat",
    "CheckSignedPair_WhenS2DerSignature_DeniesSignatureFormat",
    "CheckSignedPair_WhenMissingHostDerSignature_DeniesSignatureFormat",
    "CheckSignedPair_WhenRawRZero_DeniesSignatureFormat",
    "CheckSignedPair_WhenRawROrder_DeniesSignatureFormat",
    "CheckSignedPair_WhenRawSZero_DeniesSignatureFormat",
    "CheckSignedPair_WhenRawSOrder_DeniesSignatureFormat",
    "CheckSignedPair_WhenRawSAboveHalfOrder_DeniesSignatureFormat",
    "CheckSignedPair_WhenRawHighSMalleation_DeniesSignatureFormat",
    "CheckSignedPair_WhenRawRMaxCanonicalButWrong_DeniesSignature",
    "CheckSignedPair_WhenRawSOneCanonicalButWrong_DeniesSignature"
};

static void fixture_error(const char *message) {
    (void)fprintf(stderr, "FIXTURE_ERROR %s\n", message);
    exit(2);
}

static uint16_t u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static size_t load(const char *dir, const char *name, uint8_t *out, size_t cap) {
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path)) fixture_error("path overflow");
    FILE *f = fopen(path, "rb");
    if (f == NULL) fixture_error("open");
    if (fseek(f, 0, SEEK_END) != 0) fixture_error("seek end");
    long len = ftell(f);
    if (len <= 0 || (unsigned long)len > cap) fixture_error("size");
    if (fseek(f, 0, SEEK_SET) != 0) fixture_error("seek start");
    if (fread(out, 1, (size_t)len, f) != (size_t)len || fgetc(f) != EOF)
        fixture_error("read");
    if (fclose(f) != 0) fixture_error("close");
    return (size_t)len;
}

static size_t load_named(const char *dir, const char *prefix, const char *suffix,
                         uint8_t *out, size_t cap) {
    char name[128];
    int n = snprintf(name, sizeof(name), "%s-%s", prefix, suffix);
    if (n < 0 || (size_t)n >= sizeof(name)) fixture_error("name overflow");
    return load(dir, name, out, cap);
}

static void load_pair(const char *dir, const char *prefix, struct fixture *f) {
    memset(f, 0, sizeof(*f));
    f->policy_len = load_named(dir, prefix, "policy.bin", f->policy, sizeof(f->policy));
    f->manifest_len = load_named(dir, prefix, "manifest.bin", f->manifest,
                                 sizeof(f->manifest));
    f->signature_len = load_named(dir, prefix, "signature.raw", f->signature,
                                  sizeof(f->signature));
    f->key_len = load_named(dir, "S2", "public-key.x963", f->key, sizeof(f->key));
    if (f->policy_len != 391 || f->signature_len != 64 || f->key_len != 65)
        fixture_error("frozen shape");
}

static size_t tag_value(uint8_t *bytes, size_t len, size_t header, uint16_t tag) {
    size_t off = header;
    while (off <= len && len - off >= 4) {
        uint16_t value_len = u16(bytes + off + 2);
        if (value_len > len - off - 4) fixture_error("tlv bounds");
        if (u16(bytes + off) == tag) return off + 4;
        off += 4 + value_len;
    }
    fixture_error("missing tag");
    return 0;
}

static void half_order(uint8_t half[32]) {
    unsigned carry = 0;
    for (size_t i = 0; i < 32; i++) {
        half[i] = (uint8_t)((p256_order[i] >> 1) | carry);
        carry = (p256_order[i] & 1u) ? 0x80u : 0u;
    }
}

static bool canonical(const uint8_t sig[64]) {
    uint8_t half[32];
    uint8_t zero[32] = {0};
    half_order(half);
    return memcmp(sig, zero, 32) > 0 && memcmp(sig, p256_order, 32) < 0
        && memcmp(sig + 32, zero, 32) > 0
        && memcmp(sig + 32, half, 32) <= 0;
}

static void high_s(const uint8_t low[32], uint8_t out[32]) {
    unsigned borrow = 0;
    for (size_t i = 32; i > 0; i--) {
        unsigned minuend = p256_order[i - 1];
        unsigned subtrahend = (unsigned)low[i - 1] + borrow;
        out[i - 1] = (uint8_t)(minuend - subtrahend);
        borrow = minuend < subtrahend;
    }
    if (borrow) fixture_error("high-s underflow");
}

static void require_canonical(const uint8_t sig[64]) {
    if (!canonical(sig)) fixture_error("test candidate noncanonical");
}

static enum bh_v2_crypto_status expected(size_t case_number) {
    if (case_number == 1 || case_number == 4) return BH_V2_CRYPTO_VALID_ONLY;
    if (case_number == 2 || case_number == 3
        || (case_number >= 16 && case_number <= 21)) return BH_V2_CRYPTO_DENY_STRUCTURE;
    if ((case_number >= 5 && case_number <= 9) || case_number == 11
        || case_number == 46 || case_number == 47) return BH_V2_CRYPTO_DENY_SIGNATURE;
    if (case_number == 10 || (case_number >= 12 && case_number <= 15))
        return BH_V2_CRYPTO_DENY_KEY;
    if (case_number >= 22 && case_number <= 26) return BH_V2_CRYPTO_DENY_POLICY_WIRE;
    if (case_number >= 27 && case_number <= 34) return BH_V2_CRYPTO_DENY_ARGUMENT;
    return BH_V2_CRYPTO_DENY_SIGNATURE_FORMAT;
}

static enum bh_v2_structure_status expected_reason(size_t n) {
    if (n == 2) return BH_V2_DENY_HOST_MODE_MISSING;
    if (n == 3) return BH_V2_DENY_HOST_ENTRY;
    if (n >= 16 && n <= 18) return BH_V2_DENY_MANIFEST_DIGEST;
    return BH_V2_DENY_MANIFEST_WIRE;
}

static bool run_case(const char *dir, size_t n) {
    struct fixture f;
    load_pair(dir, "S2", &f);
    const uint8_t *policy = f.policy;
    const uint8_t *manifest = f.manifest;
    const uint8_t *signature = f.signature;
    const uint8_t *key = f.key;
    size_t policy_len = f.policy_len, manifest_len = f.manifest_len;
    size_t signature_len = f.signature_len, key_len = f.key_len;
    uint8_t half[32];
    if (n == 2 || n == 3 || n == 9 || n == 17)
        load_pair(dir, n == 2 ? "H-MISSING" : "H-SUB", &f);
    policy_len = f.policy_len; manifest_len = f.manifest_len;
    signature_len = f.signature_len; key_len = f.key_len;
    switch (n) {
    case 5: f.policy[tag_value(f.policy, policy_len, 48, 13)] ^= 1; break;
    case 6: f.signature[0] ^= 1; require_canonical(f.signature); break;
    case 7: f.signature[63] ^= 1; require_canonical(f.signature); break;
    case 8: signature_len = load_named(dir, "H-MISSING", "signature.raw",
                                       f.signature, sizeof(f.signature)); break;
    case 9: signature_len = load_named(dir, "S2", "signature.raw",
                                       f.signature, sizeof(f.signature)); break;
    case 10: memcpy(f.key, p256_base_point, 65); break;
    case 11: memcpy(f.key, p256_base_point, 65);
             if (CC_SHA256(f.key, 65, f.policy + 16) == NULL) fixture_error("key hash");
             break;
    case 12: memset(f.key + 1, 0, 64);
             if (CC_SHA256(f.key, 65, f.policy + 16) == NULL) fixture_error("key hash");
             break;
    case 13: f.key[0] = 5; break;
    case 14: key_len = 64; break;
    case 15: f.key[65] = 0; key_len = 66; break;
    case 16: manifest_len = load_named(dir, "H-MISSING", "manifest.bin",
                                        f.manifest, sizeof(f.manifest)); break;
    case 17: manifest_len = load_named(dir, "S2", "manifest.bin",
                                        f.manifest, sizeof(f.manifest)); break;
    case 18: f.manifest[tag_value(f.manifest, manifest_len, 16, 1)] ^= 1; break;
    case 19: f.manifest[5] = '1'; break;
    case 20: manifest_len = 16; break;
    case 21: f.manifest[manifest_len++] = 0; break;
    case 22: f.policy[5] = '1'; break;
    case 23: f.policy[15] ^= 1; break;
    case 24: f.policy[policy_len++] = 0; break;
    case 25: policy_len = 48; memset(f.policy + 12, 0, 4); break;
    case 26: policy_len--; break;
    case 27: policy = NULL; break;
    case 28: manifest = NULL; break;
    case 29: signature = NULL; break;
    case 30: key = NULL; break;
    case 31: policy_len = 47; break;
    case 32: policy = f.key; policy_len = 65585; break;
    case 33: manifest_len = 15; break;
    case 34: manifest = f.key; manifest_len = 65553; break;
    case 35: signature_len = 0; break;
    case 36: signature_len = 63; break;
    case 37: f.signature[64] = 0; signature_len = 65; break;
    case 38: signature_len = load_named(dir, "S2", "signature.der",
                                        f.signature, sizeof(f.signature)); break;
    case 39: signature_len = load_named(dir, "H-MISSING", "signature.der",
                                        f.signature, sizeof(f.signature)); break;
    case 40: memset(f.signature, 0, 32); break;
    case 41: memcpy(f.signature, p256_order, 32); break;
    case 42: memset(f.signature + 32, 0, 32); break;
    case 43: memcpy(f.signature + 32, p256_order, 32); break;
    case 44: half_order(half); memcpy(f.signature + 32, half, 32);
             for (size_t i = 32; i > 0; i--) {
                 if (++f.signature[31 + i] != 0) break;
             }
             break;
    case 45: high_s(f.signature + 32, f.signature + 32); break;
    case 46: memcpy(f.signature, p256_order, 32);
             f.signature[31]--; require_canonical(f.signature); break;
    case 47: memset(f.signature + 32, 0, 32);
             f.signature[63] = 1; require_canonical(f.signature); break;
    default: break;
    }
    struct bh_v2_crypto_result result = bh_v2_check_signed_pair(
        policy, policy_len, manifest, manifest_len, signature, signature_len,
        key, key_len);
    enum bh_v2_crypto_status want = expected(n);
    bool ok = result.status == want;
    if (want == BH_V2_CRYPTO_DENY_STRUCTURE)
        ok = ok && result.structure_reason == expected_reason(n);
    if (n == 4) {
        struct bh_v2_crypto_result zero = {0};
        ok = ok && zero.status == BH_V2_CRYPTO_DENY
             && BH_V2_CRYPTO_VALID_ONLY != BH_V2_CRYPTO_DENY;
    }
    if (!ok)
        (void)fprintf(stderr, "ASSERT %s expected=%d actual=%d expected_inner=%d actual_inner=%d\n",
                      names[n - 1], (int)want, (int)result.status,
                      (int)expected_reason(n), (int)result.structure_reason);
    return ok;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    unsigned failures = 0;
    for (size_t n = 1; n <= EXPECTED_CASES; n++) {
        bool ok = run_case(argv[1], n);
        if (!ok) failures++;
        (void)printf("%s %s\n", ok ? "PASS" : "FAIL", names[n - 1]);
    }
    (void)printf("signed_preflight_v2_crypto cases=%d failures=%u\n",
                 EXPECTED_CASES, failures);
    return failures == 0 ? 0 : 1;
}
