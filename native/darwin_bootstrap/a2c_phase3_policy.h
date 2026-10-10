#ifndef BH_A2C_PHASE3_POLICY_H
#define BH_A2C_PHASE3_POLICY_H
#include "abi_v1.h"
#define BH_A2C_PHASE3_VERSION 2U
#define BH_A2C_PHASE3_WIRE 152U
#define BH_A2C_PHASE3_JOURNAL_MAX 4096U
struct bh_a2c_phase3_core {
    uint32_t version, epoch;
    uint64_t generation;
    unsigned char nonce[32], incarnation[32], exercise_key[32];
    char bundle[128];
};
struct bh_a2c_phase3_manifest {
    char leaf[104], stage[1024], final[1024];
    unsigned char release[32], stage_digest[32], final_digest[32];
};
/* Link-time providers only. Uninstalled targets return NULL; fixtures are separate. */
const struct bh_a2c_phase3_core *bh_a2c_phase3_core(void);
const struct bh_a2c_phase3_manifest *bh_a2c_phase3_manifest(void);
int bh_a2c_phase3_core_valid(const struct bh_a2c_phase3_core *core);
int bh_a2c_phase3_manifest_valid(const struct bh_a2c_phase3_core *core,
                                const struct bh_a2c_phase3_manifest *manifest);
int bh_a2c_phase3_images(const struct bh_a2c_phase3_manifest *manifest);
int bh_a2c_phase3_frame(unsigned char wire[BH_A2C_PHASE3_WIRE],
                        const unsigned char inventory[32]);
int bh_a2c_phase3_verify(const unsigned char wire[BH_A2C_PHASE3_WIRE]);
/* Only the disposable test curator calls encode(FRESH); runtime never creates it. */
size_t bh_a2c_phase3_journal_encode(int directory, unsigned char state,
                                    unsigned char out[BH_A2C_PHASE3_JOURNAL_MAX]);
int bh_a2c_phase3_pending(int directory);
int bh_a2c_phase3_check_pending(int directory, struct stat *identity, int pinned);
#endif
