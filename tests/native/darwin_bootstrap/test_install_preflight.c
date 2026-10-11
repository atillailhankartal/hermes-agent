#include "../../../native/darwin_bootstrap/install_preflight.h"
#include <stdio.h>
#include <string.h>

struct bh_ip_provider bh_ip_test_synthetic_provider(struct bh_ip_observation *observation);

static struct bh_ip_test_policy good_policy(void) {
    struct bh_ip_test_policy policy = {0};
    policy.model_uid = 101;
    policy.broker_uid = 102;
    policy.client_uid = 103;
    policy.model_gid = 201;
    policy.broker_gid = 202;
    policy.client_gid = 203;
    policy.expected_epoch = 42;
    policy.expected_item_count = 2;
    (void)strcpy(policy.release_root, "/protected/release");
    (void)strcpy(policy.journal_root, "/protected/journal");
    (void)strcpy(policy.credential_root, "/protected/credential");
    (void)memset(policy.release_sha256, 0x31, BH_IP_SHA256_SIZE);
    (void)memset(policy.broker_sha256, 0x42, BH_IP_SHA256_SIZE);
    return policy;
}

static struct bh_ip_observation matching_observation(const struct bh_ip_test_policy *policy) {
    struct bh_ip_observation observation = {0};
    observation.epoch = policy->expected_epoch;
    observation.item_count = policy->expected_item_count;
    (void)memcpy(observation.release_sha256, policy->release_sha256, BH_IP_SHA256_SIZE);
    (void)memcpy(observation.broker_sha256, policy->broker_sha256, BH_IP_SHA256_SIZE);
    return observation;
}

static int probe_error(void *context, struct bh_ip_observation *observation) {
    (void)context;
    (void)observation;
    return -1;
}

static int forbidden_calls;
static int forbidden_observe(void *context, struct bh_ip_observation *observation) {
    (void)context;
    (void)observation;
    forbidden_calls++;
    return 0;
}

static int expected(struct bh_ip_result actual, enum bh_ip_status status,
                    enum bh_ip_reason reason, int synthetic) {
    return actual.status == status && actual.reason == reason &&
           actual.synthetic == synthetic && actual.installed_authority == 0;
}

static int run_case(const char *name) {
    struct bh_ip_test_policy policy = good_policy();
    struct bh_ip_observation observation = matching_observation(&policy);
    struct bh_ip_provider provider = bh_ip_test_synthetic_provider(&observation);
    enum bh_ip_reason reason = BH_IP_REASON_NONE;
    enum bh_ip_status status = BH_IP_REJECTED;
    int synthetic = 0;

    if (strcmp(name, "SyntheticValid_RemainsUntrusted") == 0) {
        status = BH_IP_OBSERVED_UNTRUSTED;
        synthetic = 1;
    } else if (strcmp(name, "MissingPolicy_ReturnsRejected") == 0) {
        return expected(bh_install_preflight(NULL, &provider), BH_IP_REJECTED,
                        BH_IP_REASON_MISSING_POLICY, 0);
    } else if (strcmp(name, "ModelBrokerUidCollision_ReturnsRejected") == 0) {
        policy.broker_uid = policy.model_uid;
        reason = BH_IP_REASON_ID_COLLISION;
    } else if (strcmp(name, "ModelClientUidCollision_ReturnsRejected") == 0) {
        policy.client_uid = policy.model_uid;
        reason = BH_IP_REASON_ID_COLLISION;
    } else if (strcmp(name, "BrokerClientUidCollision_ReturnsRejected") == 0) {
        policy.client_uid = policy.broker_uid;
        reason = BH_IP_REASON_ID_COLLISION;
    } else if (strcmp(name, "ModelBrokerGidCollision_ReturnsRejected") == 0) {
        policy.broker_gid = policy.model_gid;
        reason = BH_IP_REASON_ID_COLLISION;
    } else if (strcmp(name, "ModelClientGidCollision_ReturnsRejected") == 0) {
        policy.client_gid = policy.model_gid;
        reason = BH_IP_REASON_ID_COLLISION;
    } else if (strcmp(name, "BrokerClientGidCollision_ReturnsRejected") == 0) {
        policy.client_gid = policy.broker_gid;
        reason = BH_IP_REASON_ID_COLLISION;
    } else if (strcmp(name, "ZeroUid_ReturnsRejected") == 0) {
        policy.model_uid = 0;
        reason = BH_IP_REASON_ID_COLLISION;
    } else if (strcmp(name, "RelativePath_ReturnsRejected") == 0) {
        (void)strcpy(policy.release_root, "relative/release");
        reason = BH_IP_REASON_INVALID_PATH;
    } else if (strcmp(name, "EmptyPath_ReturnsRejected") == 0) {
        policy.release_root[0] = '\0';
        reason = BH_IP_REASON_INVALID_PATH;
    } else if (strcmp(name, "DotComponent_ReturnsRejected") == 0) {
        (void)strcpy(policy.release_root, "/protected/./release");
        reason = BH_IP_REASON_INVALID_PATH;
    } else if (strcmp(name, "DotDotComponent_ReturnsRejected") == 0) {
        (void)strcpy(policy.release_root, "/protected/../release");
        reason = BH_IP_REASON_INVALID_PATH;
    } else if (strcmp(name, "EmptyComponent_ReturnsRejected") == 0) {
        (void)strcpy(policy.release_root, "/protected//release");
        reason = BH_IP_REASON_INVALID_PATH;
    } else if (strcmp(name, "TrailingSlash_ReturnsRejected") == 0) {
        (void)strcpy(policy.release_root, "/protected/release/");
        reason = BH_IP_REASON_INVALID_PATH;
    } else if (strcmp(name, "PathWithoutNul_ReturnsRejected") == 0) {
        (void)memset(policy.release_root, 'a', BH_IP_PATH_CAP);
        policy.release_root[0] = '/';
        reason = BH_IP_REASON_INVALID_PATH;
    } else if (strcmp(name, "PathWithTrailingBytes_ReturnsRejected") == 0) {
        policy.release_root[sizeof("/protected/release")] = 'x';
        reason = BH_IP_REASON_INVALID_PATH;
    } else if (strcmp(name, "DuplicateRoots_ReturnsRejected") == 0) {
        (void)memcpy(policy.journal_root, policy.release_root, BH_IP_PATH_CAP);
        reason = BH_IP_REASON_INVALID_PATH;
    } else if (strcmp(name, "LongestCanonicalPath_RemainsUntrusted") == 0) {
        (void)memset(policy.release_root, 'a', BH_IP_PATH_CAP - 1U);
        policy.release_root[0] = '/';
        policy.release_root[BH_IP_PATH_CAP - 1U] = '\0';
        status = BH_IP_OBSERVED_UNTRUSTED;
        synthetic = 1;
    } else if (strcmp(name, "ZeroDigest_ReturnsRejected") == 0) {
        (void)memset(policy.release_sha256, 0, BH_IP_SHA256_SIZE);
        reason = BH_IP_REASON_INVALID_DIGEST;
    } else if (strcmp(name, "ZeroEpoch_ReturnsRejected") == 0) {
        policy.expected_epoch = 0;
        reason = BH_IP_REASON_INVALID_EPOCH;
    } else if (strcmp(name, "ZeroCount_ReturnsRejected") == 0) {
        policy.expected_item_count = 0;
        reason = BH_IP_REASON_INVALID_COUNT;
    } else if (strcmp(name, "ExcessiveCount_ReturnsRejected") == 0) {
        policy.expected_item_count = (size_t)BH_IP_MAX_ITEMS + 1U;
        reason = BH_IP_REASON_INVALID_COUNT;
    } else if (strcmp(name, "OverflowCount_ReturnsRejected") == 0) {
        policy.expected_item_count = SIZE_MAX;
        reason = BH_IP_REASON_INVALID_COUNT;
    } else if (strcmp(name, "UnknownProvider_ReturnsUnavailable") == 0) {
        provider.provenance = (enum bh_ip_provenance)77;
        status = BH_IP_UNAVAILABLE;
        reason = BH_IP_REASON_INVALID_PROVIDER;
    } else if (strcmp(name, "MissingProvider_ReturnsUnavailable") == 0) {
        return expected(bh_install_preflight(&policy, NULL), BH_IP_UNAVAILABLE,
                        BH_IP_REASON_INVALID_PROVIDER, 0);
    } else if (strcmp(name, "NoPolicy_StopsBeforeObservation") == 0) {
        provider = bh_install_preflight_unavailable_provider();
        provider.observe = forbidden_observe;
        forbidden_calls = 0;
        return expected(bh_install_preflight(&policy, &provider), BH_IP_UNAVAILABLE,
                        BH_IP_REASON_NO_POLICY, 0) && forbidden_calls == 0;
    } else if (strcmp(name, "MissingObservation_ReturnsUnavailable") == 0) {
        provider.observe = NULL;
        status = BH_IP_UNAVAILABLE;
        reason = BH_IP_REASON_MISSING_OBSERVATION;
    } else if (strcmp(name, "ProbeError_ReturnsUnavailable") == 0) {
        provider.observe = probe_error;
        status = BH_IP_UNAVAILABLE;
        reason = BH_IP_REASON_PROBE_ERROR;
    } else if (strcmp(name, "EpochMismatch_ReturnsRejected") == 0) {
        observation.epoch++;
        reason = BH_IP_REASON_MISMATCH;
    } else if (strcmp(name, "CountMismatch_ReturnsRejected") == 0) {
        observation.item_count++;
        reason = BH_IP_REASON_MISMATCH;
    } else if (strcmp(name, "ReleaseDigestMismatch_ReturnsRejected") == 0) {
        observation.release_sha256[0] ^= 1U;
        reason = BH_IP_REASON_MISMATCH;
    } else if (strcmp(name, "BrokerDigestMismatch_ReturnsRejected") == 0) {
        observation.broker_sha256[0] ^= 1U;
        reason = BH_IP_REASON_MISMATCH;
    } else if (strcmp(name, "UnknownReason_MapsToNonsecretUnknown") == 0) {
        const char *value = bh_install_preflight_reason((enum bh_ip_reason)999);
        return value != NULL && strcmp(value, "unknown") == 0;
    } else {
        return 0;
    }
    return expected(bh_install_preflight(&policy, &provider), status, reason, synthetic);
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    int success = run_case(argv[1]);
    (void)printf("%s %s\n", success ? "PASS" : "FAIL", argv[1]);
    return success ? 0 : 1;
}
