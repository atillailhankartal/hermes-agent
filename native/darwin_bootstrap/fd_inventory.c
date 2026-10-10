#include "abi_v1.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <unistd.h>

static int integer_compare(const void *left, const void *right) {
    int a = *(const int *)left;
    int b = *(const int *)right;
    return (a > b) - (a < b);
}

static int included(int fd, const int *allowed, size_t count) {
    size_t index;
    for (index = 0; index < count; index++) if (allowed[index] == fd) return 1;
    return 0;
}

enum bh_a2a_result bh_a2a_inventory_check(const int *allowed, size_t allowed_count,
                                          struct bh_a2a_inventory *out) {
    struct proc_fdinfo entries[BH_A2A_MAX_FDS];
    int descriptors[BH_A2A_MAX_FDS];
    CC_SHA256_CTX digest;
    int bytes;
    size_t count;
    size_t index;
    if (allowed == NULL || out == NULL || allowed_count > BH_A2A_MAX_FDS)
        return BH_A2A_PAUSED;
    memset(out, 0, sizeof(*out));
    bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, entries, (int)sizeof(entries));
    if (bytes <= 0 || (size_t)bytes >= sizeof(entries) ||
        (size_t)bytes % sizeof(entries[0]) != 0) return BH_A2A_PAUSED;
    count = (size_t)bytes / sizeof(entries[0]);
    for (index = 0; index < count; index++) {
        descriptors[index] = entries[index].proc_fd;
        if (descriptors[index] < 0 || !included(descriptors[index], allowed, allowed_count))
            return BH_A2A_PAUSED;
    }
    qsort(descriptors, count, sizeof(descriptors[0]), integer_compare);
    if (CC_SHA256_Init(&digest) != 1) return BH_A2A_PAUSED;
    for (index = 0; index < count; index++) {
        int flags;
        struct stat info;
        if (index != 0 && descriptors[index] == descriptors[index - 1])
            return BH_A2A_PAUSED;
        flags = fcntl(descriptors[index], F_GETFD);
        if (flags < 0 || fstat(descriptors[index], &info) != 0 ||
            CC_SHA256_Update(&digest, &descriptors[index],
                                         (CC_LONG)sizeof(descriptors[index])) != 1 ||
            CC_SHA256_Update(&digest, &flags, (CC_LONG)sizeof(flags)) != 1 ||
            CC_SHA256_Update(&digest, &info.st_dev, (CC_LONG)sizeof(info.st_dev)) != 1 ||
            CC_SHA256_Update(&digest, &info.st_ino, (CC_LONG)sizeof(info.st_ino)) != 1 ||
            CC_SHA256_Update(&digest, &info.st_mode, (CC_LONG)sizeof(info.st_mode)) != 1)
            return BH_A2A_PAUSED;
    }
    if (CC_SHA256_Final(out->digest, &digest) != 1) return BH_A2A_PAUSED;
    out->count = count;
    return BH_A2A_OK;
}

enum bh_a2a_result bh_a2a_child_map_prepare(struct bh_a2a_child_map *map,
                                            const int source[4]) {
    size_t index;
    size_t other;
    if (map == NULL || source == NULL || map->prepared) return BH_A2A_PAUSED;
    for (index = 0; index < 4; index++) {
        map->original[index] = -1;
        map->temporary[index] = -1;
    }
    for (index = 0; index < 4; index++) {
        if (source[index] < 3 || fcntl(source[index], F_GETFD) < 0)
            goto fail;
        for (other = 0; other < index; other++)
            if (source[index] == source[other]) goto fail;
        map->original[index] = source[index];
        map->temporary[index] = fcntl(source[index], F_DUPFD_CLOEXEC,
                                      BH_A2A_TEMP_FLOOR);
        if (map->temporary[index] < BH_A2A_TEMP_FLOOR ||
            (fcntl(map->temporary[index], F_GETFD) & FD_CLOEXEC) == 0)
            goto fail;
    }
    map->prepared = 1;
    return BH_A2A_OK;
fail:
    for (index = 0; index < 4; index++) {
        if (map->temporary[index] >= 0) {
            (void)close(map->temporary[index]);
            map->temporary[index] = -1;
        }
    }
    return BH_A2A_PAUSED;
}

enum bh_a2a_result bh_a2a_child_actions(posix_spawn_file_actions_t *actions,
                                         const struct bh_a2a_child_map *map) {
    size_t index;
    if (actions == NULL || map == NULL || !map->prepared) return BH_A2A_PAUSED;
    for (index = 0; index < 4; index++) {
        int flags = fcntl(map->temporary[index], F_GETFD);
        if (map->original[index] < 3 || map->temporary[index] < BH_A2A_TEMP_FLOOR ||
            fcntl(map->original[index], F_GETFD) < 0 ||
            flags < 0 || (flags & FD_CLOEXEC) == 0)
            return BH_A2A_PAUSED;
    }
    /* All originals close before any destination is installed. */
    for (index = 0; index < 4; index++)
        if (posix_spawn_file_actions_addclose(actions, map->original[index]) != 0)
            return BH_A2A_PAUSED;
    for (index = 0; index < 4; index++)
        if (posix_spawn_file_actions_adddup2(actions, map->temporary[index],
                                            (int)index + 3) != 0)
            return BH_A2A_PAUSED;
    /* The temporary numbers are disjoint from 3–6. No post-install close of 6. */
    for (index = 0; index < 4; index++)
        if (posix_spawn_file_actions_addclose(actions, map->temporary[index]) != 0)
            return BH_A2A_PAUSED;
    return BH_A2A_OK;
}

enum bh_a2a_result bh_a2a_child_map_retire(struct bh_a2a_child_map *map,
                                           struct bh_a2a_root *root) {
    size_t index;
    int clean = 1;
    struct stat subject;
    if (map == NULL || root == NULL || !map->prepared || !root->bound ||
        !root->socket_owned || map->original[3] != BH_A2A_FD6 ||
        fstat(BH_A2A_FD6, &subject) != 0 ||
        subject.st_dev != root->socket_object.st_dev ||
        subject.st_ino != root->socket_object.st_ino)
        return BH_A2A_PAUSED;
    /* Caller has confirmed a single owned child was spawned. Each numeric FD is
     * retired exactly once; a failed close is ambiguous and is never retried. */
    for (index = 0; index < 4; index++) {
        if (close(map->original[index]) != 0) clean = 0;
        if (index == 3) {
            root->socket_owned = 0;
            root->socket_fd = -1;
        }
        map->original[index] = -1;
    }
    for (index = 0; index < 4; index++) {
        if (close(map->temporary[index]) != 0) clean = 0;
        map->temporary[index] = -1;
    }
    map->prepared = 0;
    if (!clean) root->cancelled = 1;
    return clean ? BH_A2A_OK : BH_A2A_PAUSED;
}
