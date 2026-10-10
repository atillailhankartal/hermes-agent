#include "abi_v1.h"
#include "../trusted_inbound/darwin/socket_observer.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int parent_matches(int fd, const struct bh_a2a_manifest_v1 *manifest) {
    struct stat info;
    char path[1024];
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) == 0 ||
        fstat(fd, &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_dev != manifest->parent_device ||
        info.st_ino != manifest->parent_inode ||
        info.st_uid != manifest->parent_uid ||
        info.st_gid != manifest->parent_gid ||
        (info.st_mode & 07777) != manifest->parent_mode ||
        fcntl(fd, F_GETPATH, path) != 0 ||
        strcmp(path, manifest->parent_path) != 0) return 0;
    return 1;
}

enum bh_a2a_result bh_a2a_root_bind_observe(struct bh_a2a_root *root,
                                            int parent_fd,
                                            const struct bh_a2a_manifest_v1 *manifest) {
    struct sockaddr_un address;
    struct sockaddr_un observed;
    struct bh_socket_expectation expected;
    struct bh_socket_observation result;
    struct stat subject;
    socklen_t observed_length = (socklen_t)sizeof(observed);
    size_t path_length;
    int length;
    if (root == NULL || manifest == NULL || root->cancelled || root->bound ||
        !root->socket_owned || root->socket_fd != BH_A2A_FD6 ||
        parent_fd == BH_A2A_FD6 ||
        bh_a2a_manifest_validate(manifest) != BH_A2A_OK ||
        fstat(BH_A2A_FD6, &subject) != 0 ||
        subject.st_dev != root->socket_object.st_dev ||
        subject.st_ino != root->socket_object.st_ino ||
        !parent_matches(parent_fd, manifest)) return BH_A2A_PAUSED;
    errno = 0;
    if (fstatat(parent_fd, manifest->leaf, &root->node, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) return BH_A2A_PAUSED;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    length = snprintf(address.sun_path, sizeof(address.sun_path), "%s/%s",
                      manifest->parent_path, manifest->leaf);
    if (length <= 0 || (size_t)length >= sizeof(address.sun_path))
        return BH_A2A_PAUSED;
    path_length = (size_t)length;
    if (bind(BH_A2A_FD6, (struct sockaddr *)&address,
             (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length + 1)) != 0)
        return BH_A2A_PAUSED;
    root->bound = 1;
    root->parent_fd = parent_fd; /* transfer: retain for no-follow cleanup */
    memcpy(root->leaf, manifest->leaf, strlen(manifest->leaf) + 1);
    memset(&observed, 0, sizeof(observed));
    if (getsockname(BH_A2A_FD6, (struct sockaddr *)&observed, &observed_length) != 0 ||
        observed.sun_family != AF_UNIX ||
        observed_length < offsetof(struct sockaddr_un, sun_path) + path_length + 1 ||
        memcmp(observed.sun_path, address.sun_path, path_length + 1) != 0 ||
        fstatat(parent_fd, root->leaf, &root->node, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISSOCK(root->node.st_mode)) return BH_A2A_PAUSED;
    expected.directory_fd = parent_fd;
    expected.basename = root->leaf;
    expected.pathname = address.sun_path;
    expected.pathname_length = path_length;
    expected.node = root->node;
    result = bh_darwin_observe_fd6(&expected);
    return result.state == BH_BOUND_OBSERVED ? BH_A2A_OK : BH_A2A_PAUSED;
}

enum bh_a2a_result bh_a2a_root_cleanup_leaf(struct bh_a2a_root *root) {
    struct stat current;
    int parent_fd;
    if (root == NULL || !root->cancelled || !root->bound || root->parent_fd < 0)
        return BH_A2A_PAUSED;
    if (fstatat(root->parent_fd, root->leaf, &current, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISSOCK(current.st_mode) || current.st_dev != root->node.st_dev ||
        current.st_ino != root->node.st_ino || current.st_uid != root->node.st_uid ||
        current.st_gid != root->node.st_gid) return BH_A2A_PAUSED;
    if (unlinkat(root->parent_fd, root->leaf, 0) != 0) return BH_A2A_PAUSED;
    errno = 0;
    if (fstatat(root->parent_fd, root->leaf, &current, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) return BH_A2A_PAUSED;
    parent_fd = root->parent_fd;
    root->parent_fd = -1;
    root->bound = 0;
    return close(parent_fd) == 0 ? BH_A2A_OK : BH_A2A_PAUSED;
}
