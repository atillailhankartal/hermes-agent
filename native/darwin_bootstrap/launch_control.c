#include "launch_control.h"
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int64_t bh_a2c_now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}
static int wait_fd(int fd, short events, int64_t deadline) {
    struct pollfd item = { .fd = fd, .events = events };
    for (;;) {
        int64_t now = bh_a2c_now();
        if (now < 0 || now >= deadline) return 0;
        int timeout = deadline - now > BH_A2C_TIMEOUT_MS ? BH_A2C_TIMEOUT_MS : (int)(deadline - now);
        int result = poll(&item, 1, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0 || (item.revents & (POLLERR | POLLNVAL))) return 0;
        return (item.revents & (events | POLLHUP)) != 0;
    }
}
int bh_a2c_channel_init(int fd) {
    int flags = fcntl(fd, F_GETFL);
    int descriptor = fcntl(fd, F_GETFD);
    int type = 0;
    socklen_t length = sizeof(type);
    return flags >= 0 && descriptor >= 0 &&
        !getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) && type == SOCK_STREAM &&
        !fcntl(fd, F_SETFL, flags | O_NONBLOCK) &&
        !fcntl(fd, F_SETFD, descriptor | FD_CLOEXEC);
}
int bh_a2c_send(int fd, const void *data, size_t size, int64_t deadline) {
    const unsigned char *bytes = data;
    size_t offset = 0;
    while (offset < size) {
        if (!wait_fd(fd, POLLOUT, deadline)) return 0;
        ssize_t count = send(fd, bytes + offset, size - offset, MSG_NOSIGNAL);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) return 0;
        offset += (size_t)count;
    }
    return 1;
}
int bh_a2c_receive(int fd, void *data, size_t size, int64_t deadline) {
    unsigned char *bytes = data;
    size_t offset = 0;
    while (offset < size) {
        if (!wait_fd(fd, POLLIN, deadline)) return 0;
        ssize_t count = recv(fd, bytes + offset, size - offset, 0);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) return 0;
        offset += (size_t)count;
    }
    return 1;
}
static int stop(struct bh_a2c_control *control, struct bh_a2a_root *root, int reason) {
    control->terminal = 1;
    control->reason = reason;
    root->cancelled = 1;
    return 0;
}
int bh_a2c_guard(struct bh_a2c_control *control, struct bh_a2a_root *root,
                 uint32_t checkpoint) {
    struct bh_a2c_command_frame frame;
    if (control->terminal || root->cancelled) return stop(control, root, BH_A2C_CANCELLED);
    if (!bh_a2c_receive(3, &frame, sizeof(frame), control->deadline_ms)) {
        return stop(control, root, bh_a2c_now() >= control->deadline_ms ?
                    BH_A2C_DEADLINE : BH_A2C_LOST);
    }
    if (frame.epoch != BH_A2C_EPOCH || frame.checkpoint != checkpoint ||
        (frame.command != BH_A2C_PROCEED && frame.command != BH_A2C_CANCEL))
        return stop(control, root, BH_A2C_PROTOCOL);
    if (frame.command == BH_A2C_CANCEL) return stop(control, root, BH_A2C_CANCELLED);
    return bh_a2c_check_alive(control, root);
}
int bh_a2c_check_alive(struct bh_a2c_control *control, struct bh_a2a_root *root) {
    /* No queued input is permission here; EOF/error/cancel cannot advance. */
    unsigned char extra;
    if (control->terminal || root->cancelled) return stop(control, root, BH_A2C_CANCELLED);
    ssize_t count = recv(3, &extra, 1, MSG_PEEK);
    if (count == 0) return stop(control, root, BH_A2C_LOST);
    if (count > 0) return stop(control, root, BH_A2C_PROTOCOL);
    if (errno != EAGAIN && errno != EWOULDBLOCK) return stop(control, root, BH_A2C_IO);
    int64_t now = bh_a2c_now();
    if (now < 0 || now >= control->deadline_ms) return stop(control, root, BH_A2C_DEADLINE);
    return 1;
}

int bh_a2c_spawn(const char *fixed_image, int management_peer, pid_t *child) {
    struct proc_fdinfo entries[BH_A2A_MAX_FDS];
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    sigset_t mask, defaults;
    int saved = -1, okay = 0, actions_ready = 0, attributes_ready = 0;
    int bytes;
    if (!fixed_image || fixed_image[0] != '/' || !child) return 0;
    saved = fcntl(management_peer, F_DUPFD_CLOEXEC, BH_A2A_TEMP_FLOOR);
    if (saved < BH_A2A_TEMP_FLOOR) goto done;
    bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, entries, sizeof(entries));
    if (bytes <= 0 || (size_t)bytes >= sizeof(entries) || bytes % sizeof(entries[0])) goto done;
    if (posix_spawn_file_actions_init(&actions)) goto done;
    actions_ready = 1;
    /* Complete snapshot under the caller's single-thread/no-FD-writer interval. */
    for (size_t i = 0; i < (size_t)bytes / sizeof(entries[0]); i++) {
        int fd = entries[i].proc_fd;
        if (fd > 2 && fd != saved && posix_spawn_file_actions_addclose(&actions, fd)) goto done;
    }
    if (posix_spawn_file_actions_adddup2(&actions, saved, 3) ||
        posix_spawn_file_actions_addclose(&actions, saved)) goto done;
    if (posix_spawnattr_init(&attributes)) goto done;
    attributes_ready = 1;
    if (sigfillset(&mask) || sigdelset(&mask, SIGKILL) || sigdelset(&mask, SIGSTOP) ||
        sigfillset(&defaults) || sigdelset(&defaults, SIGKILL) || sigdelset(&defaults, SIGSTOP) ||
        posix_spawnattr_setsigmask(&attributes, &mask) ||
        posix_spawnattr_setsigdefault(&attributes, &defaults) ||
        posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF)) goto done;
    char *const argv[] = { (char *)fixed_image, NULL };
    char *const environment[] = { NULL };
    okay = posix_spawn(child, fixed_image, &actions, &attributes, argv, environment) == 0;
done:
    if (actions_ready) (void)posix_spawn_file_actions_destroy(&actions);
    if (attributes_ready) (void)posix_spawnattr_destroy(&attributes);
    if (saved >= 0) (void)close(saved);
    return okay;
}
