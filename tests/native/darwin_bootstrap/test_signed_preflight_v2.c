#include "signed_preflight_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_POLICY = 65584, MAX_MANIFEST = 65552 };

static uint8_t policy[MAX_POLICY];
static uint8_t manifest[MAX_MANIFEST];
static size_t policy_len;
static size_t manifest_len;
static const char *fixture_dir;
static unsigned int cases;
static unsigned int failures;

struct tlv_ref {
    size_t header;
    size_t value;
    size_t length;
};

struct entry_ref {
    uint8_t kind;
    size_t path_length_field;
    size_t path;
    size_t path_length;
    size_t algorithm;
    size_t cdhash;
    size_t requirement_length_field;
    size_t requirement;
    size_t requirement_length;
};

static void fixture_error(const char *reason) {
    (void)fprintf(stderr, "FIXTURE_ERROR %s\n", reason);
    exit(2);
}

static uint16_t read_u16(const uint8_t *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t read_u32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16)
        | ((uint32_t)bytes[2] << 8) | bytes[3];
}

static void write_u16(uint8_t *bytes, uint16_t value) {
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void write_u32(uint8_t *bytes, uint32_t value) {
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static size_t load_file(const char *name, uint8_t *out, size_t capacity) {
    char path[1024];
    FILE *file;
    long size;
    int written = snprintf(path, sizeof(path), "%s/%s", fixture_dir, name);
    if (written < 0 || (size_t)written >= sizeof(path)) fixture_error("path too long");
    file = fopen(path, "rb");
    if (file == NULL) fixture_error("cannot open pinned fixture");
    if (fseek(file, 0, SEEK_END) != 0) fixture_error("fixture seek end");
    size = ftell(file);
    if (size <= 0 || (unsigned long)size > capacity) fixture_error("fixture size");
    if (fseek(file, 0, SEEK_SET) != 0) fixture_error("fixture seek start");
    if (fread(out, 1, (size_t)size, file) != (size_t)size) fixture_error("fixture read");
    if (fgetc(file) != EOF) fixture_error("fixture suffix");
    if (fclose(file) != 0) fixture_error("fixture close");
    return (size_t)size;
}

static void load_pair(const char *prefix) {
    char name[64];
    int written = snprintf(name, sizeof(name), "%s-policy.bin", prefix);
    if (written < 0 || (size_t)written >= sizeof(name)) fixture_error("policy name");
    policy_len = load_file(name, policy, sizeof(policy));
    written = snprintf(name, sizeof(name), "%s-manifest.bin", prefix);
    if (written < 0 || (size_t)written >= sizeof(name)) fixture_error("manifest name");
    manifest_len = load_file(name, manifest, sizeof(manifest));
}

static struct tlv_ref find_tlv(const uint8_t *bytes, size_t length,
                               size_t header_length, uint16_t tag) {
    size_t offset = header_length;
    if (length < header_length) fixture_error("short fixture header");
    while (offset <= length && length - offset >= 4) {
        uint16_t current = read_u16(bytes + offset);
        uint16_t value_length = read_u16(bytes + offset + 2);
        struct tlv_ref found = {offset, offset + 4, value_length};
        if (value_length > length - found.value) fixture_error("bad fixture TLV span");
        if (current == tag) return found;
        offset = found.value + value_length;
    }
    fixture_error("fixture TLV not found");
    return (struct tlv_ref){0, 0, 0};
}

static void rebind_manifest_digest(void) {
    struct tlv_ref digest = find_tlv(policy, policy_len, 48, 3);
    if (digest.length != CC_SHA256_DIGEST_LENGTH || manifest_len > UINT32_MAX)
        fixture_error("manifest digest field");
    if (CC_SHA256(manifest, (CC_LONG)manifest_len, policy + digest.value) == NULL)
        fixture_error("manifest digest calculation");
}

static void replace_tlv_value(uint8_t *bytes, size_t *length, size_t capacity,
                              size_t header_length, uint16_t tag,
                              const uint8_t *replacement, size_t replacement_len) {
    struct tlv_ref ref = find_tlv(bytes, *length, header_length, tag);
    size_t old_tail = ref.value + ref.length;
    size_t new_tail;
    size_t new_length;
    if (replacement_len == 0 || replacement_len > UINT16_MAX)
        fixture_error("replacement length");
    if (read_u32(bytes + 12) != *length - header_length)
        fixture_error("original envelope length");
    if (*length - ref.length > capacity - replacement_len)
        fixture_error("replacement capacity");
    new_length = *length - ref.length + replacement_len;
    new_tail = ref.value + replacement_len;
    memmove(bytes + new_tail, bytes + old_tail, *length - old_tail);
    memcpy(bytes + ref.value, replacement, replacement_len);
    write_u16(bytes + ref.header + 2, (uint16_t)replacement_len);
    write_u32(bytes + 12, (uint32_t)(new_length - header_length));
    *length = new_length;
}

static struct entry_ref fixture_entry(unsigned int ordinal) {
    struct tlv_ref table = find_tlv(manifest, manifest_len, 16, 6);
    size_t offset = table.value + 2;
    size_t end = table.value + table.length;
    uint16_t count;
    unsigned int index;
    if (table.length < 2) fixture_error("entry table count");
    count = read_u16(manifest + table.value);
    if (ordinal == 0 || ordinal > count) fixture_error("entry ordinal");
    for (index = 1; index <= count; index++) {
        struct entry_ref entry;
        if (offset > end || end - offset < 3) fixture_error("entry header");
        entry.kind = manifest[offset];
        entry.path_length_field = offset + 1;
        entry.path_length = read_u16(manifest + entry.path_length_field);
        entry.path = offset + 3;
        if (entry.path_length > end - entry.path ||
            end - entry.path - entry.path_length < 55)
            fixture_error("entry fixed fields");
        entry.algorithm = entry.path + entry.path_length + 32;
        entry.cdhash = entry.algorithm + 1;
        entry.requirement_length_field = entry.cdhash + 20;
        entry.requirement_length = read_u16(manifest + entry.requirement_length_field);
        entry.requirement = entry.requirement_length_field + 2;
        if (entry.requirement_length > end - entry.requirement)
            fixture_error("entry requirement");
        if (index == ordinal) return entry;
        offset = entry.requirement + entry.requirement_length;
    }
    fixture_error("entry ordinal unreachable");
    return (struct entry_ref){0};
}

static void require_model_wire_shape(const uint8_t *value, size_t length,
                                     const uint8_t expected_counts[3]) {
    size_t offset = 1;
    unsigned int mode;
    if (length < 1 || value[0] != 3) fixture_error("model mode count");
    for (mode = 1; mode <= 3; mode++) {
        size_t nodes;
        if (offset > length || length - offset < 2 || value[offset] != mode)
            fixture_error("model mode header");
        nodes = value[offset + 1];
        if (nodes != expected_counts[mode - 1]) fixture_error("model node count");
        offset += 2;
        if (nodes > (length - offset) / 11) fixture_error("model node bytes");
        offset += nodes * 11;
    }
    if (offset != length) fixture_error("model trailing bytes");
}

static void expect_result(const char *name, enum bh_v2_structure_status expected) {
    enum bh_v2_structure_status actual = bh_v2_validate_structure(
        policy, policy_len, manifest, manifest_len);
    cases++;
    if (actual != expected) {
        failures++;
        (void)fprintf(stderr, "ASSERT %s expected=%d actual=%d\n", name,
                      (int)expected, (int)actual);
    }
}

static void positive_and_signed_negative_cases(void) {
    load_pair("S2");
    expect_result("ValidateStructure_WhenS2Canonical_ReturnsStructureOnly",
                  BH_V2_STRUCTURE_ONLY);
    load_pair("H-MISSING");
    expect_result("ValidateStructure_WhenGatewayHostMissing_DeniesHostModeMissing",
                  BH_V2_DENY_HOST_MODE_MISSING);
    load_pair("H-SUB");
    expect_result("ValidateStructure_WhenGatewayHostIsInterpreter_DeniesHostEntry",
                  BH_V2_DENY_HOST_ENTRY);
}

static void argument_and_header_cases(void) {
    enum bh_v2_structure_status actual;
    load_pair("S2");
    actual = bh_v2_validate_structure(NULL, policy_len, manifest, manifest_len);
    cases++;
    if (actual != BH_V2_DENY_ARGUMENT) {
        failures++;
        (void)fprintf(stderr, "ASSERT ValidateStructure_WhenPolicyNull_DeniesArgument expected=%d actual=%d\n",
                      BH_V2_DENY_ARGUMENT, actual);
    }
    actual = bh_v2_validate_structure(policy, policy_len, manifest, 0);
    cases++;
    if (actual != BH_V2_DENY_ARGUMENT) {
        failures++;
        (void)fprintf(stderr, "ASSERT ValidateStructure_WhenManifestEmpty_DeniesArgument expected=%d actual=%d\n",
                      BH_V2_DENY_ARGUMENT, actual);
    }

    load_pair("S2"); policy[5] = '1';
    expect_result("ValidateStructure_WhenPolicyV1Magic_DeniesPolicyWire", BH_V2_DENY_POLICY_WIRE);
    load_pair("S2"); policy[9] = 1;
    expect_result("ValidateStructure_WhenPolicyV1Version_DeniesPolicyWire", BH_V2_DENY_POLICY_WIRE);
    load_pair("S2"); policy_len--;
    expect_result("ValidateStructure_WhenPolicyTruncated_DeniesPolicyWire", BH_V2_DENY_POLICY_WIRE);
    load_pair("S2"); policy[policy_len++] = 0;
    expect_result("ValidateStructure_WhenPolicyHasSuffix_DeniesPolicyWire", BH_V2_DENY_POLICY_WIRE);
    load_pair("S2"); manifest[5] = '1'; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenManifestV1Magic_DeniesManifestWire", BH_V2_DENY_MANIFEST_WIRE);
    load_pair("S2"); manifest[9] = 1; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenManifestV1Version_DeniesManifestWire", BH_V2_DENY_MANIFEST_WIRE);
    load_pair("S2"); manifest_len--; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenManifestTruncated_DeniesManifestWire", BH_V2_DENY_MANIFEST_WIRE);
    load_pair("S2"); manifest[manifest_len++] = 0; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenManifestHasSuffix_DeniesManifestWire", BH_V2_DENY_MANIFEST_WIRE);
    load_pair("S2"); write_u32(manifest + 12, 65537); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenManifestBodyOverLimit_DeniesManifestWire", BH_V2_DENY_MANIFEST_WIRE);
}

static void policy_semantic_cases(void) {
    struct tlv_ref ref;
    uint8_t release_root[255];
    size_t release_root_len;
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 13);
    write_u16(policy + ref.header, 14);
    expect_result("ValidateStructure_WhenPolicyHasUnknownTLV_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 13);
    write_u16(policy + ref.header, 12);
    expect_result("ValidateStructure_WhenPolicyDuplicatesTLV_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 13);
    write_u16(policy + ref.header + 2, (uint16_t)(ref.length + 1));
    expect_result("ValidateStructure_WhenPolicyTLVValueOverrunsBody_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 1);
    write_u16(policy + ref.header + 2, UINT16_MAX);
    expect_result("ValidateStructure_WhenFirstPolicyTLVLengthOverrunsBuffer_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 13);
    write_u16(policy + ref.header + 2, (uint16_t)(ref.length - 1));
    expect_result("ValidateStructure_WhenPolicyTLVLeavesPartialHeader_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 1);
    memset(policy + ref.value, 0, ref.length);
    expect_result("ValidateStructure_WhenEpochZero_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 2);
    policy[ref.value + ref.length - 1] = 2;
    expect_result("ValidateStructure_WhenMinimumExceedsEpoch_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 8);
    policy[ref.value] = 0;
    expect_result("ValidateStructure_WhenReleasePathHasNul_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 8);
    policy[ref.value] = 'x';
    expect_result("ValidateStructure_WhenReleasePathRelative_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 8);
    policy[ref.value + ref.length - 1] = '/';
    expect_result("ValidateStructure_WhenReleasePathHasTrailingSlash_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 8);
    policy[ref.value + 6] = 0xc0;
    policy[ref.value + 7] = 0xaf;
    expect_result("ValidateStructure_WhenReleasePathHasOverlongUTF8_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 8);
    release_root_len = ref.length;
    if (release_root_len > sizeof(release_root)) fixture_error("release root bound");
    memcpy(release_root, policy + ref.value, release_root_len);
    replace_tlv_value(policy, &policy_len, sizeof(policy), 48, 9,
                      release_root, release_root_len);
    expect_result("ValidateStructure_WhenProtectedPathsEqual_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2");
    replace_tlv_value(policy, &policy_len, sizeof(policy), 48, 9,
                      (const uint8_t *)"/test/beehermes", strlen("/test/beehermes"));
    expect_result("ValidateStructure_WhenProtectedPathIsAncestor_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 12);
    if (ref.length < 21) fixture_error("role table bound");
    memcpy(policy + ref.value + 12, policy + ref.value + 2, 4);
    expect_result("ValidateStructure_WhenRoleUIDRepeated_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 12);
    policy[ref.value + 10] = 17;
    expect_result("ValidateStructure_WhenRoleSupplementaryCountAbove16_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 12);
    {
        uint8_t roles[128];
        if (ref.length != 61 || ref.length + 4 > sizeof(roles))
            fixture_error("cross-role group setup");
        memcpy(roles, policy + ref.value, 21);
        roles[20] = 1; /* role 2 gains one supplementary GID */
        memcpy(roles + 21, policy + ref.value + 6, 4); /* role 1 primary GID */
        memcpy(roles + 25, policy + ref.value + 21, ref.length - 21);
        replace_tlv_value(policy, &policy_len, sizeof(policy), 48, 12,
                          roles, ref.length + 4);
    }
    expect_result("ValidateStructure_WhenModelSupplementaryGroupOverlapsOtherRolePrimary_DeniesPolicyTLV",
                  BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 5);
    policy[ref.value] = 'X';
    expect_result("ValidateStructure_WhenOSBuildDiffers_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 4);
    policy[ref.value] ^= 1;
    expect_result("ValidateStructure_WhenInstallIDDiffers_DeniesPolicyTLV", BH_V2_DENY_POLICY_TLV);
}

static void manifest_tlv_and_digest_cases(void) {
    struct tlv_ref ref;
    struct entry_ref entry;
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    write_u16(manifest + ref.header, 11); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenManifestHasUnknownTLV_DeniesManifestTLV", BH_V2_DENY_MANIFEST_TLV);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    write_u16(manifest + ref.header, 9); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenManifestDuplicatesTLV_DeniesManifestTLV", BH_V2_DENY_MANIFEST_TLV);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    write_u16(manifest + ref.header + 2, (uint16_t)(ref.length + 1)); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenManifestTLVValueOverrunsBody_DeniesManifestTLV", BH_V2_DENY_MANIFEST_TLV);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 1);
    write_u16(manifest + ref.header + 2, UINT16_MAX); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenFirstManifestTLVLengthOverrunsBuffer_DeniesManifestTLV", BH_V2_DENY_MANIFEST_TLV);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    write_u16(manifest + ref.header + 2, (uint16_t)(ref.length - 1)); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenManifestTLVLeavesPartialHeader_DeniesManifestTLV", BH_V2_DENY_MANIFEST_TLV);
    load_pair("S2"); ref = find_tlv(policy, policy_len, 48, 3);
    policy[ref.value] ^= 1;
    expect_result("ValidateStructure_WhenManifestDigestSwapped_DeniesManifestDigest", BH_V2_DENY_MANIFEST_DIGEST);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 6);
    if (ref.length < 49) fixture_error("entry table bound");
    manifest[ref.value + 47] = 0; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenMachOAlgorithmIsZero_DeniesEntryTable", BH_V2_DENY_ENTRY_TABLE);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 6);
    write_u16(manifest + ref.value, 23); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenEntryCountExceedsRecords_DeniesEntryTable", BH_V2_DENY_ENTRY_TABLE);
    load_pair("S2"); entry = fixture_entry(22);
    write_u16(manifest + entry.path_length_field, 255); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenFinalEntryPathLengthOverrunsTable_DeniesEntryTable", BH_V2_DENY_ENTRY_TABLE);
    load_pair("S2"); entry = fixture_entry(22);
    if (entry.requirement_length >= 512) fixture_error("requirement overrun setup");
    write_u16(manifest + entry.requirement_length_field,
              (uint16_t)(entry.requirement_length + 1)); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenFinalRequirementLengthOverrunsTable_DeniesEntryTable", BH_V2_DENY_ENTRY_TABLE);
    load_pair("S2");
    {
        struct entry_ref first = fixture_entry(13);
        struct entry_ref duplicate = fixture_entry(15);
        if (first.kind != 6 || duplicate.kind != 6 ||
            first.path_length != duplicate.path_length) fixture_error("duplicate path setup");
        memcpy(manifest + duplicate.path, manifest + first.path, first.path_length);
    }
    rebind_manifest_digest();
    expect_result("ValidateStructure_WhenEntryKindPathDuplicated_DeniesEntryTable", BH_V2_DENY_ENTRY_TABLE);
    load_pair("S2"); entry = fixture_entry(15);
    if (entry.kind != 6 || entry.path_length <= 12 || manifest[entry.path + 12] != 't')
        fixture_error("entry order setup");
    manifest[entry.path + 12] = 'a'; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenEntryPathSortsBackward_DeniesEntryTable", BH_V2_DENY_ENTRY_TABLE);
    load_pair("S2"); entry = fixture_entry(6);
    if (entry.kind != 5) fixture_error("kind5 setup");
    manifest[entry.algorithm] = 2; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenKind5AlgorithmNonzero_DeniesEntryTable", BH_V2_DENY_ENTRY_TABLE);
    load_pair("S2"); entry = fixture_entry(10);
    if (entry.kind != 6) fixture_error("kind6 setup");
    manifest[entry.cdhash] = 1; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenKind6CDHashNonzero_DeniesEntryTable", BH_V2_DENY_ENTRY_TABLE);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 6);
    entry = fixture_entry(10);
    {
        uint8_t extended[4096];
        size_t insert_at = entry.requirement - ref.value;
        if (entry.kind != 6 || entry.requirement_length != 0 ||
            ref.length >= sizeof(extended) || insert_at > ref.length)
            fixture_error("kind6 requirement setup");
        memcpy(extended, manifest + ref.value, insert_at);
        extended[insert_at] = 'x';
        memcpy(extended + insert_at + 1, manifest + entry.requirement,
               ref.length - insert_at);
        write_u16(extended + entry.requirement_length_field - ref.value, 1);
        replace_tlv_value(manifest, &manifest_len, sizeof(manifest), 16, 6,
                          extended, ref.length + 1);
    }
    rebind_manifest_digest();
    expect_result("ValidateStructure_WhenKind6RequirementNonzero_DeniesEntryTable", BH_V2_DENY_ENTRY_TABLE);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 7);
    memset(manifest + ref.value, 0, ref.length); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenLoaderDigestZero_DeniesManifestTLV", BH_V2_DENY_MANIFEST_TLV);
}

static void mode_and_host_cases(void) {
    struct tlv_ref ref;
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 8);
    if (ref.length != 1) fixture_error("mode mask bound");
    manifest[ref.value] = 8; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenModeMaskUnknownBit_DeniesModeMask", BH_V2_DENY_MODE_MASK);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 8);
    manifest[ref.value] = 0; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenModeMaskZero_DeniesModeMask", BH_V2_DENY_MODE_MASK);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 9);
    if (ref.length != 19 || manifest[ref.value] != 3) fixture_error("host table bound");
    manifest[ref.value + 7] = 1; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenHostModeDuplicated_DeniesHostTable", BH_V2_DENY_HOST_TABLE);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 9);
    manifest[ref.value + 8] = 0; manifest[ref.value + 9] = 0; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenHostOrdinalZero_DeniesHostEntry", BH_V2_DENY_HOST_ENTRY);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 9);
    write_u16(manifest + ref.value + 8, 23); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenHostOrdinalPastEntryCount_DeniesHostEntry", BH_V2_DENY_HOST_ENTRY);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 9);
    memcpy(manifest + ref.value + 8, manifest + ref.value + 2, 2); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenHostImageSharedAcrossModes_DeniesHostEntry", BH_V2_DENY_HOST_ENTRY);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 9);
    memcpy(manifest + ref.value + 10, manifest + ref.value + 8, 2); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenHostConfigPointsToHostImage_DeniesHostEntry", BH_V2_DENY_HOST_ENTRY);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 9);
    memcpy(manifest + ref.value + 10, manifest + ref.value + 4, 2); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenHostConfigSharedAcrossModes_DeniesHostEntry", BH_V2_DENY_HOST_ENTRY);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 9);
    manifest[ref.value + 12] = 1; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenHostRoleIsModel_DeniesHostTable", BH_V2_DENY_HOST_TABLE);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 8);
    manifest[ref.value] = 1; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenDisabledHostModesRemain_DeniesHostTable", BH_V2_DENY_HOST_TABLE);
}

static void model_graph_cases(void) {
    struct tlv_ref ref;
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    if (ref.length != 62 || manifest[ref.value] != 3) fixture_error("model graph bound");
    manifest[ref.value + 16 + 2] = 2; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenGatewayNodeUsesHostRole_DeniesModelGraph", BH_V2_DENY_MODEL_GRAPH);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    manifest[ref.value + 27 + 1] = 0; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenGatewayChildHasNoParent_DeniesModelGraph", BH_V2_DENY_MODEL_GRAPH);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    manifest[ref.value + 27] = 3; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenGatewayChildNodeIDSkipsTwo_DeniesModelGraph", BH_V2_DENY_MODEL_GRAPH);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    manifest[ref.value + 15] = 1; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenGatewayNodeCountLeavesTrailingRecord_DeniesModelGraph", BH_V2_DENY_MODEL_GRAPH);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    {
        uint8_t shortened[62];
        const uint8_t expected_counts[3] = {1, 1, 2};
        if (ref.length != sizeof(shortened)) fixture_error("model deletion setup");
        memcpy(shortened, manifest + ref.value, sizeof(shortened));
        memmove(shortened + 27, shortened + 38, sizeof(shortened) - 38);
        shortened[15] = 1;
        require_model_wire_shape(shortened, sizeof(shortened) - 11, expected_counts);
        replace_tlv_value(manifest, &manifest_len, sizeof(manifest), 16, 10,
                          shortened, sizeof(shortened) - 11);
    }
    rebind_manifest_digest();
    expect_result("ValidateStructure_WhenGatewayGraphWellFramedButHasOneNode_DeniesModelGraph", BH_V2_DENY_MODEL_GRAPH);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    write_u16(manifest + ref.value + 16 + 3, 1); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenInterpreterOrdinalIsSupervisor_DeniesModelGraph", BH_V2_DENY_MODEL_GRAPH);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    write_u16(manifest + ref.value + 16 + 5, 1); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenScriptOrdinalIsSupervisor_DeniesModelGraph", BH_V2_DENY_MODEL_GRAPH);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    write_u16(manifest + ref.value + 16 + 7, 1); rebind_manifest_digest();
    expect_result("ValidateStructure_WhenArgvOrdinalIsSupervisor_DeniesModelGraph", BH_V2_DENY_MODEL_GRAPH);
    load_pair("S2"); ref = find_tlv(manifest, manifest_len, 16, 10);
    manifest[ref.value + 38] = 2; rebind_manifest_digest();
    expect_result("ValidateStructure_WhenModelModeDuplicated_DeniesModelGraph", BH_V2_DENY_MODEL_GRAPH);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        (void)fprintf(stderr, "usage: %s fixture-directory\n", argv[0]);
        return 2;
    }
    fixture_dir = argv[1];
    positive_and_signed_negative_cases();
    argument_and_header_cases();
    policy_semantic_cases();
    manifest_tlv_and_digest_cases();
    mode_and_host_cases();
    model_graph_cases();
    (void)printf("signed_preflight_v2 cases=%u failures=%u\n", cases, failures);
    return failures == 0 ? 0 : 1;
}
