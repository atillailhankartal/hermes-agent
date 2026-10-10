#include "abi_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* Internal close-only helper. The public caller must use retire_and_signal. */
enum bh_a2a_result bh_a2a_child_map_retire(struct bh_a2a_child_map *map,
                                           struct bh_a2a_root *root);

static int fd_is_absent(int fd) {
    errno = 0;
    return fcntl(fd, F_GETFD) == -1 && errno == EBADF;
}

static int set_and_check_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) return 0;
    return (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0;
}

static int is_fresh_unbound_stream(int fd) {
    struct sockaddr_un address;
    struct stat info;
    socklen_t length = (socklen_t)sizeof(address);
    int type = -1;
    socklen_t type_length = (socklen_t)sizeof(type);
    if (fstat(fd, &info) != 0 || !S_ISSOCK(info.st_mode)) return 0;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_length) != 0 ||
        type_length != sizeof(type) || type != SOCK_STREAM) return 0;
    memset(&address, 0, sizeof(address));
    if (getsockname(fd, (struct sockaddr *)&address, &length) != 0 ||
        address.sun_family != AF_UNIX || length > sizeof(address)) return 0;
    if (length > offsetof(struct sockaddr_un, sun_path) && address.sun_path[0] != '\0')
        return 0;
    length = (socklen_t)sizeof(address);
    if (getpeername(fd, (struct sockaddr *)&address, &length) == 0 || errno != ENOTCONN)
        return 0;
    return 1;
}

enum bh_a2a_result bh_a2a_root_prepare_fd6(struct bh_a2a_root *root,
                                            int source_floor) {
    int source = -1;
    int duplicate = -1;
    if (root == NULL || root->socket_owned || root->bound || root->cancelled ||
        (source_floor != 0 && source_floor < BH_A2A_TEMP_FLOOR) ||
        !fd_is_absent(BH_A2A_FD6)) return BH_A2A_PAUSED;
    root->socket_fd = -1;
    root->parent_fd = -1;
    source = socket(AF_UNIX, SOCK_STREAM, 0);
    if (source < 0 || !set_and_check_cloexec(source)) goto fail;
    if (source_floor != 0) {
        duplicate = fcntl(source, F_DUPFD_CLOEXEC, source_floor);
        if (duplicate < source_floor) goto fail;
        if (close(source) != 0) goto fail_ambiguous;
        source = duplicate;
        duplicate = -1;
    }
    if (!is_fresh_unbound_stream(source)) goto fail;
    if (source != BH_A2A_FD6) {
        if (!fd_is_absent(BH_A2A_FD6) || dup2(source, BH_A2A_FD6) != BH_A2A_FD6)
            goto fail;
        root->socket_fd = BH_A2A_FD6;
        root->socket_owned = 1;
        if (!set_and_check_cloexec(BH_A2A_FD6)) goto fail;
        if (close(source) != 0) goto fail_ambiguous;
        source = -1;
    } else {
        root->socket_fd = BH_A2A_FD6;
        root->socket_owned = 1;
        source = -1;
    }
    if (!is_fresh_unbound_stream(BH_A2A_FD6) ||
        fstat(BH_A2A_FD6, &root->socket_object) != 0) goto fail;
    return BH_A2A_OK;

fail:
    if (duplicate >= 0) (void)close(duplicate);
    if (source >= 0 && (!root->socket_owned || source != root->socket_fd))
        (void)close(source);
    bh_a2a_root_cancel(root);
    return BH_A2A_PAUSED;
fail_ambiguous:
    /* POSIX close error may mean the numeric slot was already released. Never retry. */
    root->cancelled = 1;
    if (duplicate >= 0) (void)close(duplicate);
    if (root->socket_owned) {
        (void)close(root->socket_fd);
        root->socket_owned = 0;
    }
    return BH_A2A_PAUSED;
}

void bh_a2a_root_cancel(struct bh_a2a_root *root) {
    if (root == NULL) return;
    root->cancelled = 1;
    if (root->socket_owned) {
        int fd = root->socket_fd;
        root->socket_owned = 0;
        root->socket_fd = -1;
        (void)close(fd);
    }
    if (root->parent_fd >= 0 && !root->bound) {
        int fd = root->parent_fd;
        root->parent_fd = -1;
        (void)close(fd);
    }
}
#include "abi_v1.h"

#include <CommonCrypto/CommonHMAC.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

enum { BH_A2A_FRAME_PREFIX = 120, BH_A2A_FRAME_WIRE = 152 };

static void put32(unsigned char *out, uint32_t value) {
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static void put64(unsigned char *out, uint64_t value) {
    int index;
    for (index = 7; index >= 0; index--) {
        out[index] = (unsigned char)value;
        value >>= 8;
    }
}

static int nonzero(const unsigned char *input, size_t count) {
    unsigned char total = 0;
    size_t index;
    for (index = 0; index < count; index++) total |= input[index];
    return total != 0;
}

static void prefix(const struct bh_a2a_close_frame *frame,
                   unsigned char out[BH_A2A_FRAME_WIRE]) {
    put32(out, frame->version);
    put32(out + 4, frame->type);
    put64(out + 8, frame->sequence);
    memcpy(out + 16, frame->launch_nonce, 32);
    memcpy(out + 48, frame->incarnation, 32);
    put64(out + 80, frame->generation);
    memcpy(out + 88, frame->inventory_digest, 32);
}

enum bh_a2a_result bh_a2a_frame_sign(struct bh_a2a_close_frame *frame,
                                     const unsigned char key[32]) {
    unsigned char wire[BH_A2A_FRAME_WIRE];
    if (frame == NULL || key == NULL || frame->version != BH_A2A_FRAME_VERSION ||
        frame->type != BH_A2A_FRAME_ROOT_CLOSED || frame->sequence != 1 ||
        frame->generation == 0 || !nonzero(key, 32) ||
        !nonzero(frame->launch_nonce, 32) || !nonzero(frame->incarnation, 32) ||
        !nonzero(frame->inventory_digest, 32)) return BH_A2A_PAUSED;
    prefix(frame, wire);
    CCHmac(kCCHmacAlgSHA256, key, 32, wire, BH_A2A_FRAME_PREFIX, frame->mac);
    return BH_A2A_OK;
}

enum bh_a2a_result bh_a2a_frame_verify(const struct bh_a2a_close_frame *frame,
                                       const unsigned char key[32],
                                       uint64_t expected_sequence) {
    unsigned char wire[BH_A2A_FRAME_WIRE];
    unsigned char expected[32];
    unsigned char difference = 0;
    size_t index;
    if (frame == NULL || key == NULL || expected_sequence != 1 ||
        frame->sequence != expected_sequence || frame->version != BH_A2A_FRAME_VERSION ||
        frame->type != BH_A2A_FRAME_ROOT_CLOSED || frame->generation == 0 ||
        !nonzero(key, 32) || !nonzero(frame->launch_nonce, 32) ||
        !nonzero(frame->incarnation, 32) || !nonzero(frame->inventory_digest, 32))
        return BH_A2A_PAUSED;
    prefix(frame, wire);
    CCHmac(kCCHmacAlgSHA256, key, 32, wire, BH_A2A_FRAME_PREFIX, expected);
    for (index = 0; index < 32; index++) difference |= expected[index] ^ frame->mac[index];
    memset(expected, 0, sizeof(expected));
    return difference == 0 ? BH_A2A_OK : BH_A2A_PAUSED;
}

static enum bh_a2a_result frame_send(int control_fd,
                                    const struct bh_a2a_close_frame *frame,
                                    const unsigned char key[32]) {
    unsigned char wire[BH_A2A_FRAME_WIRE];
    size_t written = 0;
    if (control_fd < 0 || bh_a2a_frame_verify(frame, key, 1) != BH_A2A_OK)
        return BH_A2A_PAUSED;
    prefix(frame, wire);
    memcpy(wire + BH_A2A_FRAME_PREFIX, frame->mac, 32);
    while (written < sizeof(wire)) {
        ssize_t count = send(control_fd, wire + written, sizeof(wire) - written,
                             MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return BH_A2A_PAUSED;
        written += (size_t)count;
    }
    return BH_A2A_OK;
}

enum bh_a2a_result bh_a2a_root_retire_and_signal(struct bh_a2a_child_map *map,
                                                struct bh_a2a_root *root,
                                                pid_t spawned_child,
                                                int control_fd,
                                                const int *remaining_fds,
                                                size_t remaining_count,
                                                struct bh_a2a_close_frame *frame,
                                                const unsigned char key[32]) {
    struct bh_a2a_inventory inventory;
    struct stat remaining;
    size_t index;
    int type = -1;
    socklen_t length = (socklen_t)sizeof(type);
    if (root == NULL) return BH_A2A_PAUSED;
    if (map == NULL || frame == NULL || key == NULL ||
        remaining_fds == NULL || spawned_child <= 0 || control_fd < 0 ||
        control_fd == root->socket_fd ||
        getsockopt(control_fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0 ||
        length != sizeof(type) || type != SOCK_STREAM ||
        kill(spawned_child, 0) != 0) {
        root->cancelled = 1;
        return BH_A2A_PAUSED;
    }
    if (bh_a2a_child_map_retire(map, root) != BH_A2A_OK ||
        bh_a2a_inventory_check(remaining_fds, remaining_count, &inventory) != BH_A2A_OK ||
        inventory.count != remaining_count) {
        root->cancelled = 1;
        return BH_A2A_PAUSED;
    }
    for (index = 0; index < remaining_count; index++) {
        if (fstat(remaining_fds[index], &remaining) != 0 ||
            (S_ISSOCK(remaining.st_mode) &&
             remaining.st_dev == root->socket_object.st_dev &&
             remaining.st_ino == root->socket_object.st_ino)) {
            root->cancelled = 1;
            return BH_A2A_PAUSED;
        }
    }
    memcpy(frame->inventory_digest, inventory.digest, BH_A2A_DIGEST_BYTES);
    if (bh_a2a_frame_sign(frame, key) != BH_A2A_OK ||
        frame_send(control_fd, frame, key) != BH_A2A_OK) {
        root->cancelled = 1;
        return BH_A2A_PAUSED;
    }
    return BH_A2A_OK;
}
