#ifndef BH_A2C_PHASE3_IO_H
#define BH_A2C_PHASE3_IO_H
#include "launch_control.h"
/* NULL control/root only in F: it observes its own channels and deadline. */
struct bh_a2c_phase3_io {
    int fd;
    int64_t deadline;
    struct bh_a2c_control *control;
    struct bh_a2a_root *root;
};
int bh_a2c_phase3_write(struct bh_a2c_phase3_io *io, const void *bytes, size_t length);
int bh_a2c_phase3_read_eof(struct bh_a2c_phase3_io *io, void *bytes, size_t length);
int bh_a2c_phase3_shutdown(struct bh_a2c_phase3_io *io);
#endif
