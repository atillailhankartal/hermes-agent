#ifndef BH_DARWIN_BOOTSTRAP_ABI_V1_H
#define BH_DARWIN_BOOTSTRAP_ABI_V1_H

#include <stddef.h>
#include <stdint.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Dormant A2a primitives. BH_A2A_OK is local progress, never admission. */
enum bh_a2a_result { BH_A2A_PAUSED = 0, BH_A2A_OK = 1 };
#define BH_A2A_FD6 6
#define BH_A2A_TEMP_FLOOR 64
#define BH_A2A_MAX_FDS 512
#define BH_A2A_DIGEST_BYTES 32
#define BH_A2A_FRAME_VERSION 1
#define BH_A2A_FRAME_ROOT_CLOSED 1

struct bh_a2a_manifest_v1 {
    uint32_t version;
    char parent_path[104];
    char leaf[104];
    char stage0_path[1024];
    uid_t parent_uid;
    gid_t parent_gid;
    mode_t parent_mode;
    dev_t parent_device;
    ino_t parent_inode;
    uid_t broker_uid;
    gid_t broker_gid;
    unsigned char release_digest[BH_A2A_DIGEST_BYTES];
};

struct bh_a2a_inventory {
    size_t count;
    unsigned char digest[BH_A2A_DIGEST_BYTES];
};

struct bh_a2a_child_map {
    int original[4];
    int temporary[4];
    int prepared;
};

/* Fixed-width wire image: all multi-byte fields are network byte order. */
struct bh_a2a_close_frame {
    uint32_t version;
    uint32_t type;
    uint64_t sequence;
    unsigned char launch_nonce[32];
    unsigned char incarnation[32];
    uint64_t generation;
    unsigned char inventory_digest[BH_A2A_DIGEST_BYTES];
    unsigned char mac[BH_A2A_DIGEST_BYTES];
};

struct bh_a2a_root {
    int socket_fd;
    int parent_fd;
    int socket_owned;
    int bound;
    int cancelled;
    struct stat socket_object;
    struct stat node;
    char leaf[104];
};

/* source_floor is a fixed caller policy; 0 uses the kernel's next free slot. */
enum bh_a2a_result bh_a2a_root_prepare_fd6(struct bh_a2a_root *root,
                                            int source_floor);
enum bh_a2a_result bh_a2a_manifest_validate(const struct bh_a2a_manifest_v1 *manifest);
enum bh_a2a_result bh_a2a_root_bind_observe(struct bh_a2a_root *root,
                                            int parent_fd,
                                            const struct bh_a2a_manifest_v1 *manifest);
enum bh_a2a_result bh_a2a_inventory_check(const int *allowed, size_t allowed_count,
                                          struct bh_a2a_inventory *out);
enum bh_a2a_result bh_a2a_child_map_prepare(struct bh_a2a_child_map *map,
                                            const int source[4]);
enum bh_a2a_result bh_a2a_child_actions(posix_spawn_file_actions_t *actions,
                                         const struct bh_a2a_child_map *map);
enum bh_a2a_result bh_a2a_stage0_validate(void);
enum bh_a2a_result bh_a2a_stage0_drop(uid_t uid, gid_t gid);
enum bh_a2a_result bh_a2a_frame_sign(struct bh_a2a_close_frame *frame,
                                     const unsigned char key[32]);
enum bh_a2a_result bh_a2a_frame_verify(const struct bh_a2a_close_frame *frame,
                                       const unsigned char key[32],
                                       uint64_t expected_sequence);
/* Call only after a successful fixed posix_spawn of the recorded child. */
enum bh_a2a_result bh_a2a_root_retire_and_signal(struct bh_a2a_child_map *map,
                                                struct bh_a2a_root *root,
                                                pid_t spawned_child,
                                                int control_fd,
                                                const int *remaining_fds,
                                                size_t remaining_count,
                                                struct bh_a2a_close_frame *frame,
                                                const unsigned char key[32]);
enum bh_a2a_result bh_a2a_root_cleanup_leaf(struct bh_a2a_root *root);
void bh_a2a_root_cancel(struct bh_a2a_root *root);

#endif
