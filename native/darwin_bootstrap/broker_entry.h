#ifndef BH_BROKER_ENTRY_H
#define BH_BROKER_ENTRY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#define BH_A2B_PATH_MAX 1024
#define BH_A2B_MAX_FDS 512
#define BH_A2B_MAX_ANCESTORS 64
#define BH_A2B_MAX_CLEANUP 130

enum bh_a2b_result { BH_A2B_PAUSED = 0, BH_A2B_FD7_OBSERVED_UNTRUSTED = 1 };
struct bh_a2b_fd {
    int number;
    int descriptor_flags;
    int status_flags;
    struct stat metadata;
    uint64_t socket_identity; /* Untrusted kernel observation, never release proof. */
};
struct bh_a2b_inventory {
    size_t count;
    int complete;
    struct bh_a2b_fd descriptors[BH_A2B_MAX_FDS];
};
struct bh_a2b_candidate {
    char path[BH_A2B_PATH_MAX];
    size_t path_length; /* Exact bytes excluding the sole terminating NUL. */
    struct stat parent;
    struct bh_a2b_fd inherited[3]; /* Candidate observations of 3, 4, 6. */
};
struct bh_a2b_ancestor {
    char path[BH_A2B_PATH_MAX];
    struct stat metadata;
};
enum bh_a2b_cleanup_decision {
    BH_A2B_CLOSED = 1, BH_A2B_RETAINED_UNKNOWN = 2, BH_A2B_CLOSE_FAILED = 3
};
struct bh_a2b_cleanup {
    int number;
    enum bh_a2b_cleanup_decision decision;
};
struct bh_a2b_observation {
    enum bh_a2b_result result;
    struct bh_a2b_inventory initial;
    struct bh_a2b_inventory final;
    size_t ancestor_count;
    struct bh_a2b_ancestor ancestors[BH_A2B_MAX_ANCESTORS];
    size_t cleanup_count;
    struct bh_a2b_cleanup cleanup[BH_A2B_MAX_CLEANUP];
    int source_fd;
    int fd7_installed;
    int acl_policy_verified; /* Always zero in this slice. */
};
/* Dormant only. Caller must own a sealed single-threaded FD interval: no other
 * thread, signal handler or callback may mutate the descriptor table. Candidate
 * metadata is not authenticated. No authority or ABA/lifetime proof is returned.
 * On observed success the caller owns FD7; on PAUSED inspect cleanup decisions.
 * Inputs and output must be disjoint valid objects. Never closes inherited FDs.
 */
enum bh_a2b_result bh_a2b_observe_fd7(const struct bh_a2b_candidate *candidate,
                                      struct bh_a2b_observation *out);
#endif
