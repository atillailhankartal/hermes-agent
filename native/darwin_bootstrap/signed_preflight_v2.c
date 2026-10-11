#include "signed_preflight_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <stdbool.h>
#include <string.h>

enum { BH_BODY_MAX = 65536, BH_ENTRY_MAX = 1024, BH_PATH_MAX = 255 };

struct bh_field {
    const uint8_t *bytes;
    size_t len;
};

struct bh_entry {
    uint8_t kind;
    struct bh_field path;
};

static uint16_t bh_u16(const uint8_t *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t bh_u32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16)
        | ((uint32_t)bytes[2] << 8) | bytes[3];
}

static uint64_t bh_u64(const uint8_t *bytes) {
    return ((uint64_t)bh_u32(bytes) << 32) | bh_u32(bytes + 4);
}

static bool bh_zero(const uint8_t *bytes, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (bytes[i] != 0) return false;
    }
    return true;
}

static bool bh_equal(struct bh_field a, struct bh_field b) {
    return a.len == b.len && memcmp(a.bytes, b.bytes, a.len) == 0;
}

static bool bh_envelope(const uint8_t *bytes, size_t len, const char magic[8],
                        size_t header_len) {
    uint32_t body_len;
    if (len < header_len || memcmp(bytes, magic, 8) != 0
        || bh_u16(bytes + 8) != 2 || bh_u16(bytes + 10) != header_len)
        return false;
    body_len = bh_u32(bytes + 12);
    return body_len >= 1 && body_len <= BH_BODY_MAX
        && len == header_len + (size_t)body_len;
}

static bool bh_tlvs(const uint8_t *bytes, size_t len, size_t header_len,
                    size_t count, struct bh_field *fields) {
    size_t offset = header_len;
    size_t tag;
    for (tag = 1; tag <= count; tag++) {
        uint16_t value_len;
        if (len - offset < 4 || bh_u16(bytes + offset) != tag) return false;
        value_len = bh_u16(bytes + offset + 2);
        offset += 4;
        if (value_len == 0 || value_len > len - offset) return false;
        fields[tag].bytes = bytes + offset;
        fields[tag].len = value_len;
        offset += value_len;
    }
    return offset == len;
}

static bool bh_ascii(struct bh_field value, size_t max_len) {
    size_t i;
    if (value.len == 0 || value.len > max_len) return false;
    for (i = 0; i < value.len; i++) {
        if (value.bytes[i] < 0x21 || value.bytes[i] > 0x7e) return false;
    }
    return true;
}

/* Decode shortest-form UTF-8 and reject surrogates, noncharacters and controls. */
static bool bh_utf8(const uint8_t *bytes, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint32_t cp;
        uint8_t first = bytes[i++];
        size_t trailing;
        size_t j;
        if (first < 0x80) {
            cp = first;
            trailing = 0;
        } else if (first >= 0xc2 && first <= 0xdf) {
            cp = first & 0x1f;
            trailing = 1;
        } else if (first >= 0xe0 && first <= 0xef) {
            cp = first & 0x0f;
            trailing = 2;
        } else if (first >= 0xf0 && first <= 0xf4) {
            cp = first & 0x07;
            trailing = 3;
        } else {
            return false;
        }
        if (trailing > len - i) return false;
        for (j = 0; j < trailing; j++) {
            uint8_t next = bytes[i++];
            if ((next & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (next & 0x3f);
        }
        if ((trailing == 1 && cp < 0x80)
            || (trailing == 2 && cp < 0x800)
            || (trailing == 3 && cp < 0x10000)
            || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)
            || (cp >= 0xfdd0 && cp <= 0xfdef)
            || (cp & 0xfffeu) == 0xfffeu
            || cp < 0x20 || cp == 0x7f) return false;
    }
    return true;
}

static bool bh_path(struct bh_field path, bool absolute) {
    size_t i;
    size_t component;
    if (path.len == 0 || path.len > BH_PATH_MAX
        || (path.bytes[0] == '/') != absolute
        || path.bytes[path.len - 1] == '/'
        || !bh_utf8(path.bytes, path.len)) return false;
    component = absolute ? 1 : 0;
    if (component == path.len) return false;
    for (i = component; i <= path.len; i++) {
        if (i == path.len || path.bytes[i] == '/') {
            size_t part_len = i - component;
            if (part_len == 0
                || (part_len == 1 && path.bytes[component] == '.')
                || (part_len == 2 && path.bytes[component] == '.'
                    && path.bytes[component + 1] == '.')) return false;
            component = i + 1;
        }
    }
    return true;
}

/* Map Darwin's /var alias before comparing protected root containment. */
static size_t bh_mapped_path(struct bh_field path, uint8_t out[BH_PATH_MAX + 9]) {
    if (path.len >= 4 && memcmp(path.bytes, "/var", 4) == 0
        && (path.len == 4 || path.bytes[4] == '/')) {
        memcpy(out, "/private", 8);
        memcpy(out + 8, path.bytes, path.len);
        return path.len + 8;
    }
    memcpy(out, path.bytes, path.len);
    return path.len;
}

static bool bh_disjoint_paths(struct bh_field a, struct bh_field b) {
    uint8_t first[BH_PATH_MAX + 9];
    uint8_t second[BH_PATH_MAX + 9];
    size_t a_len = bh_mapped_path(a, first);
    size_t b_len = bh_mapped_path(b, second);
    size_t shared = a_len < b_len ? a_len : b_len;
    if (memcmp(first, second, shared) != 0) return true;
    if (a_len == b_len) return false;
    return (a_len < b_len ? second[a_len] : first[b_len]) != '/';
}

static bool bh_roles(struct bh_field table) {
    size_t offset = 0;
    uint32_t uids[6];
    uint32_t gids[6];
    uint32_t effective_groups[6][17];
    size_t effective_counts[6];
    size_t role;
    if (table.len < 1 || table.bytes[offset++] != 6) return false;
    for (role = 0; role < 6; role++) {
        uint8_t groups;
        uint32_t prior = 0;
        size_t i;
        if (table.len - offset < 10 || table.bytes[offset++] != role + 1)
            return false;
        uids[role] = bh_u32(table.bytes + offset); offset += 4;
        gids[role] = bh_u32(table.bytes + offset); offset += 4;
        groups = table.bytes[offset++];
        if (uids[role] == 0 || gids[role] == 0 || groups > 16
            || (size_t)groups > (table.len - offset) / 4) return false;
        effective_groups[role][0] = gids[role];
        effective_counts[role] = 1;
        for (i = 0; i < role; i++) {
            if (uids[i] == uids[role] || gids[i] == gids[role]) return false;
        }
        for (i = 0; i < groups; i++) {
            uint32_t group = bh_u32(table.bytes + offset);
            offset += 4;
            if (group == 0 || group <= prior) return false;
            prior = group;
            if (group != gids[role]) {
                effective_groups[role][effective_counts[role]++] = group;
            }
        }
        /* No in-memory connect-only ACL allowlist exists in this source slice. */
        for (i = 0; i < role; i++) {
            size_t own;
            size_t other;
            for (own = 0; own < effective_counts[role]; own++) {
                for (other = 0; other < effective_counts[i]; other++) {
                    if (effective_groups[role][own] == effective_groups[i][other])
                        return false;
                }
            }
        }
    }
    return offset == table.len;
}

static bool bh_policy_fields(const struct bh_field *fields) {
    size_t i;
    size_t j;
    if (fields[1].len != 8 || fields[2].len != 8
        || bh_u64(fields[1].bytes) == 0 || bh_u64(fields[2].bytes) == 0
        || bh_u64(fields[2].bytes) > bh_u64(fields[1].bytes)
        || fields[3].len != 32 || bh_zero(fields[3].bytes, 32)
        || fields[4].len != 32 || bh_zero(fields[4].bytes, 32)
        || !bh_ascii(fields[5], 64) || !bh_ascii(fields[6], 64)
        || !bh_ascii(fields[7], 128) || !bh_roles(fields[12])
        || fields[13].len != 32) return false;
    for (i = 8; i <= 11; i++) {
        if (!bh_path(fields[i], true)) return false;
        for (j = 8; j < i; j++) {
            if (!bh_disjoint_paths(fields[i], fields[j])) return false;
        }
    }
    return true;
}

static bool bh_manifest_fields(const struct bh_field *manifest) {
    return manifest[1].len == 32 && !bh_zero(manifest[1].bytes, 32)
        && bh_path(manifest[2], true) && bh_ascii(manifest[3], 64)
        && bh_ascii(manifest[4], 64) && bh_ascii(manifest[5], 128)
        && manifest[7].len == 32 && !bh_zero(manifest[7].bytes, 32);
}

static bool bh_manifest_matches_policy(const struct bh_field *policy,
                                       const struct bh_field *manifest) {
    return bh_equal(manifest[1], policy[4])
        && bh_equal(manifest[2], policy[8])
        && bh_equal(manifest[3], policy[5])
        && bh_equal(manifest[4], policy[6])
        && bh_equal(manifest[5], policy[7]);
}

static int bh_path_compare(struct bh_field a, struct bh_field b) {
    size_t shared = a.len < b.len ? a.len : b.len;
    int order = memcmp(a.bytes, b.bytes, shared);
    if (order != 0) return order;
    return a.len < b.len ? -1 : (a.len > b.len ? 1 : 0);
}

static bool bh_entries(struct bh_field table, struct bh_entry entries[BH_ENTRY_MAX + 1],
                       uint16_t *entry_count) {
    size_t offset = 2;
    uint16_t count;
    uint16_t index;
    unsigned int mandatory[4] = {0, 0, 0, 0};
    if (table.len < 2) return false;
    count = bh_u16(table.bytes);
    if (count < 3 || count > BH_ENTRY_MAX) return false;
    for (index = 1; index <= count; index++) {
        uint8_t kind;
        uint16_t path_len;
        uint16_t req_len;
        struct bh_field path;
        uint16_t prior;
        bool macho;
        if (table.len - offset < 3) return false;
        kind = table.bytes[offset++];
        path_len = bh_u16(table.bytes + offset); offset += 2;
        if (kind < 1 || kind > 8 || path_len == 0 || path_len > BH_PATH_MAX
            || table.len - offset < (size_t)path_len + 55) return false;
        path.bytes = table.bytes + offset;
        path.len = path_len;
        offset += path_len;
        if (!bh_path(path, false) || bh_zero(table.bytes + offset, 32)) return false;
        offset += 32;
        macho = kind <= 4 || kind == 7 || kind == 8;
        if (macho) {
            if (table.bytes[offset] != 2 || bh_zero(table.bytes + offset + 1, 20))
                return false;
        } else if (table.bytes[offset] != 0
                   || !bh_zero(table.bytes + offset + 1, 20)) return false;
        offset += 21;
        req_len = bh_u16(table.bytes + offset); offset += 2;
        if (req_len > 512 || req_len > table.len - offset
            || (macho && (req_len == 0 || !bh_utf8(table.bytes + offset, req_len)))
            || (!macho && req_len != 0)) return false;
        offset += req_len;
        if (index > 1 && (entries[index - 1].kind > kind
            || (entries[index - 1].kind == kind
                && bh_path_compare(entries[index - 1].path, path) >= 0))) return false;
        for (prior = 1; prior < index; prior++) {
            if (bh_path_compare(entries[prior].path, path) == 0) return false;
        }
        entries[index].kind = kind;
        entries[index].path = path;
        if (kind <= 3) mandatory[kind]++;
    }
    if (offset != table.len || mandatory[1] != 1 || mandatory[2] != 1
        || mandatory[3] != 1) return false;
    *entry_count = count;
    return true;
}

static unsigned int bh_popcount(uint8_t mask) {
    return (unsigned int)((mask & 1u) != 0) + (unsigned int)((mask & 2u) != 0)
        + (unsigned int)((mask & 4u) != 0);
}

static bool bh_entry_is(const struct bh_entry *entries, uint16_t count,
                        uint16_t ordinal, uint8_t kind) {
    return ordinal != 0 && ordinal <= count && entries[ordinal].kind == kind;
}

static enum bh_v2_structure_status bh_hosts(struct bh_field table, uint8_t mask,
                                            const struct bh_entry *entries,
                                            uint16_t entry_count) {
    uint8_t count;
    uint8_t seen = 0;
    uint16_t host_ordinals[3] = {0, 0, 0};
    uint16_t config_ordinals[3] = {0, 0, 0};
    size_t i;
    if (table.len == 0) return BH_V2_DENY_HOST_TABLE;
    count = table.bytes[0];
    if (count > 3 || table.len != 1 + (size_t)count * 6)
        return BH_V2_DENY_HOST_TABLE;
    if (count > bh_popcount(mask)) return BH_V2_DENY_HOST_TABLE;
    for (i = 0; i < count; i++) {
        const uint8_t *record = table.bytes + 1 + i * 6;
        uint8_t mode = record[0];
        uint16_t host = bh_u16(record + 1);
        uint16_t config = bh_u16(record + 3);
        size_t prior;
        if (mode < 1 || mode > 3 || (i > 0 && mode <= table.bytes[1 + (i - 1) * 6])
            || (mask & (1u << (mode - 1))) == 0 || record[5] != 2)
            return BH_V2_DENY_HOST_TABLE;
        seen |= (uint8_t)(1u << (mode - 1));
        if (!bh_entry_is(entries, entry_count, host, 8)
            || !bh_entry_is(entries, entry_count, config, 6))
            return BH_V2_DENY_HOST_ENTRY;
        for (prior = 0; prior < i; prior++) {
            if (host_ordinals[prior] == host || config_ordinals[prior] == config
                || bh_path_compare(entries[host_ordinals[prior]].path,
                                   entries[host].path) == 0)
                return BH_V2_DENY_HOST_ENTRY;
        }
        host_ordinals[i] = host;
        config_ordinals[i] = config;
    }
    if (seen != mask) return BH_V2_DENY_HOST_MODE_MISSING;
    /* A declared native host image must be assigned to exactly one enabled mode. */
    for (i = 1; i <= entry_count; i++) {
        size_t j;
        bool assigned = false;
        if (entries[i].kind != 8) continue;
        for (j = 0; j < count; j++) {
            if (host_ordinals[j] == i) assigned = true;
        }
        if (!assigned) return BH_V2_DENY_HOST_ENTRY;
    }
    return BH_V2_STRUCTURE_ONLY;
}

static enum bh_v2_structure_status bh_models(struct bh_field table, uint8_t mask,
                                             const struct bh_entry *entries,
                                             uint16_t entry_count) {
    uint8_t count;
    uint8_t seen = 0;
    uint8_t previous_mode = 0;
    size_t offset = 1;
    size_t i;
    if (table.len == 0) return BH_V2_DENY_MODEL_GRAPH;
    count = table.bytes[0];
    if (count != bh_popcount(mask)) return BH_V2_DENY_MODEL_GRAPH;
    for (i = 0; i < count; i++) {
        uint8_t mode;
        uint8_t nodes;
        size_t node;
        if (table.len - offset < 2) return BH_V2_DENY_MODEL_GRAPH;
        mode = table.bytes[offset++];
        nodes = table.bytes[offset++];
        if (mode < 1 || mode > 3 || (mask & (1u << (mode - 1))) == 0
            || mode <= previous_mode || nodes != (mode == 1 ? 1 : 2)
            || nodes > (table.len - offset) / 11) return BH_V2_DENY_MODEL_GRAPH;
        seen |= (uint8_t)(1u << (mode - 1));
        previous_mode = mode;
        for (node = 1; node <= nodes; node++) {
            const uint8_t *record = table.bytes + offset;
            uint16_t interpreter = bh_u16(record + 3);
            uint16_t script = bh_u16(record + 5);
            uint16_t argv = bh_u16(record + 7);
            uint16_t loader = bh_u16(record + 9);
            if (record[0] != node || record[1] != (node == 1 ? 0 : 1)
                || record[2] != 1
                || !bh_entry_is(entries, entry_count, interpreter, 4)
                || !bh_entry_is(entries, entry_count, script, 5)
                || !bh_entry_is(entries, entry_count, argv, 6)
                || !bh_entry_is(entries, entry_count, loader, 6))
                return BH_V2_DENY_MODEL_GRAPH;
            offset += 11;
        }
    }
    return offset == table.len && seen == mask
        ? BH_V2_STRUCTURE_ONLY : BH_V2_DENY_MODEL_GRAPH;
}

enum bh_v2_structure_status bh_v2_validate_structure(
    const uint8_t *policy, size_t policy_len,
    const uint8_t *manifest, size_t manifest_len) {
    static const char policy_magic[8] = {'B','H','P','O','L','2',0,0};
    static const char manifest_magic[8] = {'B','H','M','N','F','2',0,0};
    struct bh_field p[14] = {{0}};
    struct bh_field m[11] = {{0}};
    struct bh_entry entries[BH_ENTRY_MAX + 1] = {{0}};
    uint16_t entry_count;
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    uint8_t mask;
    enum bh_v2_structure_status status;
    if (policy == NULL || manifest == NULL || policy_len == 0 || manifest_len == 0)
        return BH_V2_DENY_ARGUMENT;
    if (!bh_envelope(policy, policy_len, policy_magic, 48)
        || bh_zero(policy + 16, 32)) return BH_V2_DENY_POLICY_WIRE;
    if (!bh_tlvs(policy, policy_len, 48, 13, p) || !bh_policy_fields(p))
        return BH_V2_DENY_POLICY_TLV;
    if (!bh_envelope(manifest, manifest_len, manifest_magic, 16))
        return BH_V2_DENY_MANIFEST_WIRE;
    if (!bh_tlvs(manifest, manifest_len, 16, 10, m))
        return BH_V2_DENY_MANIFEST_TLV;
    if (CC_SHA256(manifest, (CC_LONG)manifest_len, digest) == NULL
        || memcmp(digest, p[3].bytes, sizeof(digest)) != 0)
        return BH_V2_DENY_MANIFEST_DIGEST;
    if (!bh_manifest_fields(m)) return BH_V2_DENY_MANIFEST_TLV;
    if (!bh_manifest_matches_policy(p, m)) return BH_V2_DENY_POLICY_TLV;
    if (!bh_entries(m[6], entries, &entry_count)) return BH_V2_DENY_ENTRY_TABLE;
    if (m[8].len != 1 || m[8].bytes[0] < 1 || m[8].bytes[0] > 7)
        return BH_V2_DENY_MODE_MASK;
    mask = m[8].bytes[0];
    status = bh_hosts(m[9], mask, entries, entry_count);
    if (status != BH_V2_STRUCTURE_ONLY) return status;
    return bh_models(m[10], mask, entries, entry_count);
}
