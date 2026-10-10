#include "a2c_phase3_policy.h"
#include "launch_authority.h"
#include "a2c_policy.h"
#include <string.h>
static int present(const unsigned char bytes[32]) {
    unsigned char value = 0;
    for (size_t i = 0; i < 32; i++) value |= bytes[i];
    return value != 0;
}
int bh_a2c_phase3_core_valid(const struct bh_a2c_phase3_core *core) {
    return core && core->version == BH_A2C_PHASE3_VERSION && core->epoch == BH_A2C_EPOCH &&
        core->generation && present(core->nonce) && present(core->incarnation) &&
        present(core->exercise_key) && core->bundle[0] &&
        strnlen(core->bundle, sizeof(core->bundle)) < sizeof(core->bundle);
}
int bh_a2c_phase3_frame(unsigned char wire[BH_A2C_PHASE3_WIRE],
                        const unsigned char inventory[32]) {
    const struct bh_a2c_phase3_core *core = bh_a2c_phase3_core();
    struct bh_a2a_close_frame frame = { .version = BH_A2A_FRAME_VERSION,
        .type = BH_A2A_FRAME_ROOT_CLOSED, .sequence = 1 };
    if (!wire || !inventory || !bh_a2c_phase3_core_valid(core)) return 0;
    frame.generation = core->generation;
    memcpy(frame.launch_nonce, core->nonce, 32);
    memcpy(frame.incarnation, core->incarnation, 32);
    memcpy(frame.inventory_digest, inventory, 32);
    if (bh_a2a_frame_sign(&frame, core->exercise_key) != BH_A2A_OK) return 0;
    bh_a2c_frame_encode(&frame, wire);
    return 1;
}
int bh_a2c_phase3_verify(const unsigned char wire[BH_A2C_PHASE3_WIRE]) {
    const struct bh_a2c_phase3_core *core = bh_a2c_phase3_core();
    struct bh_a2a_close_frame frame;
    if (!wire || !bh_a2c_phase3_core_valid(core)) return 0;
    bh_a2c_frame_decode(wire, &frame);
    return frame.generation == core->generation &&
        !memcmp(frame.launch_nonce, core->nonce, 32) &&
        !memcmp(frame.incarnation, core->incarnation, 32) &&
        bh_a2a_frame_verify(&frame, core->exercise_key, 1) == BH_A2A_OK;
}
