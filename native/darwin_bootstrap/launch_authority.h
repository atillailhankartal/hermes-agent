#ifndef BH_A2C_LAUNCH_AUTHORITY_H
#define BH_A2C_LAUNCH_AUTHORITY_H
#include "abi_v1.h"
void bh_a2c_frame_encode(const struct bh_a2a_close_frame *frame, unsigned char wire[152]);
void bh_a2c_frame_decode(const unsigned char wire[152], struct bh_a2a_close_frame *frame);
int bh_a2c_retire(struct bh_a2a_child_map *map, struct bh_a2a_root *root,
                  const int *remaining, size_t count, struct bh_a2a_inventory *inventory);
#endif
