#include "install_preflight.h"

#include <string.h>

static struct bh_ip_result result(enum bh_ip_status status, enum bh_ip_reason reason,
                                  int synthetic) {
    struct bh_ip_result value = {status, reason, synthetic, 0};
    return value;
}

static int distinct_nonzero(uint32_t first, uint32_t second, uint32_t third) {
    return first != 0U && second != 0U && third != 0U &&
           first != second && first != third && second != third;
}

static int canonical_path(const char path[BH_IP_PATH_CAP]) {
    size_t length = 0U;
    while (length < BH_IP_PATH_CAP && path[length] != '\0') {
        length++;
    }
    if (length == 0U || length == BH_IP_PATH_CAP || path[0] != '/') {
        return 0;
    }
    for (size_t index = length + 1U; index < BH_IP_PATH_CAP; index++) {
        if (path[index] != '\0') return 0;
    }
    if (length == 1U) return 1;
    if (path[length - 1U] == '/') return 0;

    size_t component = 1U;
    for (size_t index = 1U; index <= length; index++) {
        if (index != length && path[index] != '/') continue;
        const size_t size = index - component;
        if (size == 0U ||
            (size == 1U && path[component] == '.') ||
            (size == 2U && path[component] == '.' && path[component + 1U] == '.')) {
            return 0;
        }
        component = index + 1U;
    }
    return 1;
}

static int nonzero_digest(const unsigned char digest[BH_IP_SHA256_SIZE]) {
    unsigned char accumulated = 0U;
    for (size_t index = 0U; index < BH_IP_SHA256_SIZE; index++) {
        accumulated |= digest[index];
    }
    return accumulated != 0U;
}

struct bh_ip_result bh_install_preflight(const struct bh_ip_test_policy *policy,
                                         const struct bh_ip_provider *provider) {
    if (provider == NULL) return result(BH_IP_UNAVAILABLE, BH_IP_REASON_INVALID_PROVIDER, 0);
    if (provider->provenance == BH_IP_PROVENANCE_NO_POLICY) {
        return result(BH_IP_UNAVAILABLE, BH_IP_REASON_NO_POLICY, 0);
    }
    if (provider->provenance != BH_IP_PROVENANCE_TEST_SYNTHETIC) {
        return result(BH_IP_UNAVAILABLE, BH_IP_REASON_INVALID_PROVIDER, 0);
    }
    if (policy == NULL) return result(BH_IP_REJECTED, BH_IP_REASON_MISSING_POLICY, 0);
    if (!distinct_nonzero(policy->model_uid, policy->broker_uid, policy->client_uid) ||
        !distinct_nonzero(policy->model_gid, policy->broker_gid, policy->client_gid)) {
        return result(BH_IP_REJECTED, BH_IP_REASON_ID_COLLISION, 0);
    }
    if (!canonical_path(policy->release_root) || !canonical_path(policy->journal_root) ||
        !canonical_path(policy->credential_root) ||
        strcmp(policy->release_root, policy->journal_root) == 0 ||
        strcmp(policy->release_root, policy->credential_root) == 0 ||
        strcmp(policy->journal_root, policy->credential_root) == 0) {
        return result(BH_IP_REJECTED, BH_IP_REASON_INVALID_PATH, 0);
    }
    if (!nonzero_digest(policy->release_sha256) || !nonzero_digest(policy->broker_sha256)) {
        return result(BH_IP_REJECTED, BH_IP_REASON_INVALID_DIGEST, 0);
    }
    if (policy->expected_epoch == 0U) {
        return result(BH_IP_REJECTED, BH_IP_REASON_INVALID_EPOCH, 0);
    }
    if (policy->expected_item_count == 0U || policy->expected_item_count > BH_IP_MAX_ITEMS) {
        return result(BH_IP_REJECTED, BH_IP_REASON_INVALID_COUNT, 0);
    }
    if (provider->observe == NULL) {
        return result(BH_IP_UNAVAILABLE, BH_IP_REASON_MISSING_OBSERVATION, 0);
    }

    struct bh_ip_observation observation = {0};
    if (provider->observe(provider->context, &observation) != 0) {
        return result(BH_IP_UNAVAILABLE, BH_IP_REASON_PROBE_ERROR, 0);
    }
    if (observation.epoch != policy->expected_epoch ||
        observation.item_count != policy->expected_item_count ||
        memcmp(observation.release_sha256, policy->release_sha256, BH_IP_SHA256_SIZE) != 0 ||
        memcmp(observation.broker_sha256, policy->broker_sha256, BH_IP_SHA256_SIZE) != 0) {
        return result(BH_IP_REJECTED, BH_IP_REASON_MISMATCH, 0);
    }
    return result(BH_IP_OBSERVED_UNTRUSTED, BH_IP_REASON_NONE, 1);
}

const char *bh_install_preflight_reason(enum bh_ip_reason reason) {
    switch (reason) {
        case BH_IP_REASON_NONE: return "none";
        case BH_IP_REASON_MISSING_POLICY: return "missing_policy";
        case BH_IP_REASON_ID_COLLISION: return "id_collision";
        case BH_IP_REASON_INVALID_PATH: return "invalid_path";
        case BH_IP_REASON_INVALID_DIGEST: return "invalid_digest";
        case BH_IP_REASON_INVALID_EPOCH: return "invalid_epoch";
        case BH_IP_REASON_INVALID_COUNT: return "invalid_count";
        case BH_IP_REASON_INVALID_PROVIDER: return "invalid_provider";
        case BH_IP_REASON_NO_POLICY: return "no_policy";
        case BH_IP_REASON_MISSING_OBSERVATION: return "missing_observation";
        case BH_IP_REASON_PROBE_ERROR: return "probe_error";
        case BH_IP_REASON_MISMATCH: return "mismatch";
        default: return "unknown";
    }
}
