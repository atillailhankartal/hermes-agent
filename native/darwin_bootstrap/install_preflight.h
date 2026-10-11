#ifndef BH_INSTALL_PREFLIGHT_H
#define BH_INSTALL_PREFLIGHT_H

#include <stddef.h>
#include <stdint.h>

#define BH_IP_PATH_CAP 256U
#define BH_IP_SHA256_SIZE 32U
#define BH_IP_MAX_ITEMS 1024U

/* This interface has no verified or installed-authority result. */
enum bh_ip_status {
    BH_IP_REJECTED = 1,
    BH_IP_UNAVAILABLE = 2,
    BH_IP_OBSERVED_UNTRUSTED = 3
};

enum bh_ip_reason {
    BH_IP_REASON_NONE = 0,
    BH_IP_REASON_MISSING_POLICY,
    BH_IP_REASON_ID_COLLISION,
    BH_IP_REASON_INVALID_PATH,
    BH_IP_REASON_INVALID_DIGEST,
    BH_IP_REASON_INVALID_EPOCH,
    BH_IP_REASON_INVALID_COUNT,
    BH_IP_REASON_INVALID_PROVIDER,
    BH_IP_REASON_NO_POLICY,
    BH_IP_REASON_MISSING_OBSERVATION,
    BH_IP_REASON_PROBE_ERROR,
    BH_IP_REASON_MISMATCH
};

enum bh_ip_provenance {
    BH_IP_PROVENANCE_NO_POLICY = 1,
    BH_IP_PROVENANCE_TEST_SYNTHETIC = 2
};

/* In-memory exercise fields only. This is not an installed policy format. */
struct bh_ip_test_policy {
    uint32_t model_uid, broker_uid, client_uid;
    uint32_t model_gid, broker_gid, client_gid;
    uint64_t expected_epoch;
    size_t expected_item_count;
    char release_root[BH_IP_PATH_CAP];
    char journal_root[BH_IP_PATH_CAP];
    char credential_root[BH_IP_PATH_CAP];
    unsigned char release_sha256[BH_IP_SHA256_SIZE];
    unsigned char broker_sha256[BH_IP_SHA256_SIZE];
};

struct bh_ip_observation {
    uint64_t epoch;
    size_t item_count;
    unsigned char release_sha256[BH_IP_SHA256_SIZE];
    unsigned char broker_sha256[BH_IP_SHA256_SIZE];
};

struct bh_ip_provider {
    enum bh_ip_provenance provenance;
    int (*observe)(void *context, struct bh_ip_observation *out);
    void *context;
};

struct bh_ip_result {
    enum bh_ip_status status;
    enum bh_ip_reason reason;
    int synthetic;
    int installed_authority;
};

struct bh_ip_result bh_install_preflight(const struct bh_ip_test_policy *policy,
                                         const struct bh_ip_provider *provider);
struct bh_ip_provider bh_install_preflight_unavailable_provider(void);
const char *bh_install_preflight_reason(enum bh_ip_reason reason);

#endif
