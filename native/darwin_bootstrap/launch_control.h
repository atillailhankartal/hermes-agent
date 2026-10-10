#ifndef BH_A2C_LAUNCH_CONTROL_H
#define BH_A2C_LAUNCH_CONTROL_H
#include "a2c_policy.h"
#include <stdint.h>
#include <sys/types.h>
/* Optional nonsecret terminal telemetry, never a command or admission proof.
 * A sends once with MSG_DONTWAIT; a missing/partial report cannot hold exit. */
#define BH_A2C_STATUS_TERMINAL 0xa2c10020U
struct bh_a2c_status {
    uint32_t kind, reason, cancelled, bound, fd6_open, parent_open, node_known;
};
enum bh_a2c_command { BH_A2C_PROCEED = 1, BH_A2C_CANCEL = 2 };
struct bh_a2c_command_frame { uint32_t epoch, checkpoint, command; };
struct bh_a2c_control {
    int terminal;
    int reason;
    int64_t deadline_ms;
};
enum bh_a2c_reason { BH_A2C_NONE, BH_A2C_LOST, BH_A2C_PROTOCOL,
                     BH_A2C_DEADLINE, BH_A2C_IO, BH_A2C_CANCELLED };
int bh_a2c_signals_match(void);
int bh_a2c_phase2(struct bh_a2c_control *control, struct bh_a2a_root *root);
int64_t bh_a2c_now(void);
int bh_a2c_channel_init(int fd);
int bh_a2c_send(int fd, const void *data, size_t size, int64_t deadline);
int bh_a2c_receive(int fd, void *data, size_t size, int64_t deadline);
int bh_a2c_check_alive(struct bh_a2c_control *control, struct bh_a2a_root *root);
int bh_a2c_guard(struct bh_a2c_control *control, struct bh_a2a_root *root,
                 uint32_t checkpoint);
int bh_a2c_spawn(const char *fixed_image, int management_peer, pid_t *child);
#endif
