#ifndef BH_A2C_POLICY_H
#define BH_A2C_POLICY_H
#include "abi_v1.h"
/* Uninstalled phase-1 mechanics only. No signed policy or admission result. */
#define BH_A2C_VERSION 1U
#define BH_A2C_EPOCH 0x41324331U
#define BH_A2C_TIMEOUT_MS 2000
#define BH_A2C_FRESH "SOURCE_FIXTURE_FRESH\n"
#define BH_A2C_PENDING "ATTEMPT_PENDING_SOURCE_ONLY\n"
struct bh_a2c_config {
    uint32_t version;
    uint32_t epoch;
    char parent[104];
};
int bh_a2c_pending(int directory_fd);
int bh_a2c_candidate(const struct bh_a2c_config *config, int parent_fd,
                     struct bh_a2a_manifest_v1 *manifest);
#endif
