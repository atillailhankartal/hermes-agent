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


int bh_a2c_signals_match(void) {
    sigset_t mask;
    struct sigaction disposition;
    if (sigprocmask(SIG_SETMASK, NULL, &mask)) return 0;
    for (int number = 1; number < NSIG; number++) {
        if (number == SIGKILL || number == SIGSTOP) continue;
        if (sigismember(&mask, number) != 1 || sigaction(number, NULL, &disposition) ||
            disposition.sa_handler != SIG_DFL) return 0;
    }
    return 1;
}

#ifdef BH_A2C_PHASE2
#include <sys/wait.h>
#ifndef BH_A2C_STAGE0_IMAGE
#define BH_A2C_STAGE0_IMAGE "/uninstalled/a2c/stage0"
#endif
#ifdef BH_A2C_TEST_AUDIT
void bh_a2c_test_audit(const char *event, pid_t child, int status);
#define AUDIT(event, child, status) bh_a2c_test_audit(event, child, status)
#else
#define AUDIT(event, child, status) ((void)0)
#endif
static int spawn_stage(const int source[4], pid_t *child) {
    struct bh_a2a_child_map map = {0};
    struct proc_fdinfo entries[BH_A2A_MAX_FDS];
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    sigset_t mask, defaults;
    int actions_ready = 0, attr_ready = 0, okay = 0;
    for (size_t i = 0; i < 4; i++) if (source[i] == 3) return 0;
    if (bh_a2a_child_map_prepare(&map, source) != BH_A2A_OK) return 0;
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, entries, sizeof(entries));
    if (bytes <= 0 || (size_t)bytes >= sizeof(entries) || bytes % sizeof(entries[0])) return 0;
    if (posix_spawn_file_actions_init(&actions)) return 0;
    actions_ready = 1;
    for (size_t i = 0; i < (size_t)bytes / sizeof(entries[0]); i++) {
        int fd = entries[i].proc_fd, temporary = 0;
        for (size_t j = 0; j < 4; j++) if (fd == map.temporary[j]) temporary = 1;
#ifdef BH_A2C_TEST_LEAK_CHILD
        if (fd == 150) continue;
#endif
        if (fd > 2 && !temporary && posix_spawn_file_actions_addclose(&actions, fd)) goto done;
    }
    for (size_t i = 0; i < 4; i++) {
        if (posix_spawn_file_actions_adddup2(&actions, map.temporary[i], (int)i + 3)) goto done;
    }
    for (size_t i = 0; i < 4; i++) {
        if (posix_spawn_file_actions_addclose(&actions, map.temporary[i])) goto done;
    }
    if (posix_spawnattr_init(&attr)) goto done;
    attr_ready = 1;
    if (sigfillset(&mask) || sigdelset(&mask, SIGKILL) || sigdelset(&mask, SIGSTOP) ||
        sigfillset(&defaults) || sigdelset(&defaults, SIGKILL) || sigdelset(&defaults, SIGSTOP) ||
        posix_spawnattr_setsigmask(&attr, &mask) || posix_spawnattr_setsigdefault(&attr, &defaults)) goto done;
    short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
#ifdef BH_A2C_TEST_NO_SIGMASK
    flags &= ~POSIX_SPAWN_SETSIGMASK;
#endif
#ifdef BH_A2C_TEST_NO_SIGDEF
    flags &= ~POSIX_SPAWN_SETSIGDEF;
#endif
    if (posix_spawnattr_setflags(&attr, flags)) goto done;
    char *const argv[] = { (char *)BH_A2C_STAGE0_IMAGE, NULL };
    char *const env[] = { NULL };
    okay = posix_spawn(child, BH_A2C_STAGE0_IMAGE, &actions, &attr, argv, env) == 0;
done:
    if (actions_ready) (void)posix_spawn_file_actions_destroy(&actions);
    if (attr_ready) (void)posix_spawnattr_destroy(&attr);
    /* No root-close/alias-retirement assertion in phase2. A exits after its child. */
    return okay;
}
static int reap_child(pid_t child, int *status) {
    int64_t now = bh_a2c_now();
    if (now < 0) { AUDIT("UNCERTAIN", child, 0); return 0; }
    int64_t deadline = now + 500;
    for (;;) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) { AUDIT("REAP", child, *status); return 1; }
        if (result < 0 && errno != EINTR) { AUDIT("UNCERTAIN", child, errno); return 0; }
        now = bh_a2c_now();
        if (now < 0) { AUDIT("UNCERTAIN", child, 0); return 0; }
        if (now >= deadline) break;
        struct timespec pause = { .tv_nsec = 1000000 };
        (void)nanosleep(&pause, NULL);
    }
    /* Still our unreaped child; do not rediscover/reuse a PID after ECHILD. */
    if (kill(child, SIGKILL)) { AUDIT("UNCERTAIN", child, errno); return 0; }
    now = bh_a2c_now();
    if (now < 0) { AUDIT("UNCERTAIN", child, 0); return 0; }
    deadline = now + 500;
    while ((now = bh_a2c_now()) >= 0 && now < deadline) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) { AUDIT("REAP_KILLED", child, *status); return 1; }
        if (result < 0 && errno != EINTR) { AUDIT("UNCERTAIN", child, errno); return 0; }
        struct timespec pause = { .tv_nsec = 1000000 };
        (void)nanosleep(&pause, NULL);
    }
    AUDIT("UNCERTAIN", child, 0);
    return 0;
}
static int phase2_receive(struct bh_a2c_control *control, struct bh_a2a_root *root,
                          int fd, unsigned char *message) {
    struct pollfd item = { .fd = fd, .events = POLLIN };
    while (bh_a2c_check_alive(control, root)) {
        int ready = poll(&item, 1, 10);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (item.revents & (POLLERR | POLLNVAL))) return 0;
        if (!ready) continue;
        ssize_t count = recv(fd, message, 1, 0);
        if (count == 1) return 1;
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        return 0;
    }
    return 0;
}
int bh_a2c_phase2(struct bh_a2c_control *control, struct bh_a2a_root *root) {
    int bootstrap[2], transport[2], status_pipe[2];
    int status = 0, okay = 0;
    pid_t child = -1;
    unsigned char message;
    if (!bh_a2c_check_alive(control, root) ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, bootstrap) ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, transport) || pipe(status_pipe) ||
        !bh_a2c_channel_init(transport[0])) return 0;
#ifdef BH_A2C_TEST_DIRTY_SIGNALS
    sigset_t empty;
    (void)sigemptyset(&empty);
    (void)sigprocmask(SIG_SETMASK, &empty, NULL);
    (void)signal(SIGUSR1, SIG_IGN);
#endif
#ifdef BH_A2C_TEST_LEAK_PARENT
    if (fcntl(root->parent_fd, F_DUPFD, 150) != 150) return 0;
#endif
#ifdef BH_A2C_TEST_FULL_STATUS
    if (fcntl(status_pipe[1], F_SETFL, O_NONBLOCK)) return 0;
    unsigned char fill[1024] = {0};
    while (write(status_pipe[1], fill, sizeof(fill)) > 0) {}
    if (errno != EAGAIN) return 0;
#endif
#ifdef BH_A2C_TEST_COLLISION
    /* bootstrap[0] is an unused owned endpoint, normally FD5. */
    if (dup2(bootstrap[1], bootstrap[0]) != bootstrap[0]) return 0;
    bootstrap[1] = bootstrap[0];
#endif
    int source[4] = { bootstrap[1], transport[1], status_pipe[1], 6 };
#ifdef BH_A2C_TEST_BAD_SOURCE
    source[0] = 3;
#endif
#ifdef BH_A2C_TEST_PARK_BEFORE_SPAWN
    AUDIT("PRESPAWN", getpid(), 0);
    (void)raise(SIGSTOP);
#endif
    if (!bh_a2c_check_alive(control, root) || !spawn_stage(source, &child)) return 0;
    /* Ownership is recorded before test synchronization or any progress. */
    AUDIT("OWN", child, 0);
#ifdef BH_A2C_TEST_PARK_AFTER_SPAWN
    (void)raise(SIGSTOP);
#endif
    if (!bh_a2c_check_alive(control, root)) goto done;
    uint32_t progress[2] = {3, (uint32_t)child};
    if (!bh_a2c_send(3, progress, sizeof(progress), control->deadline_ms) ||
        !bh_a2c_guard(control, root, 3)) goto done;
    if (!phase2_receive(control, root, transport[0], &message) || message != 'S') goto done;
    message = 'E';
    if (!bh_a2c_check_alive(control, root) ||
        !bh_a2c_send(transport[0], &message, 1, control->deadline_ms)) goto done;
    AUDIT("FORWARD", child, message);
    if (!phase2_receive(control, root, transport[0], &message) || message != 'F') goto done;
    progress[0] = 4;
    if (!bh_a2c_send(3, progress, sizeof(progress), control->deadline_ms) ||
        !bh_a2c_guard(control, root, 4)) goto done;
    message = 'X';
    if (!bh_a2c_send(transport[0], &message, 1, control->deadline_ms)) goto done;
    AUDIT("FORWARD", child, message);
    okay = 1;
done:
    if (!okay) { control->terminal = 1; root->cancelled = 1; }
    (void)close(transport[0]);
#ifdef BH_A2C_TEST_AUTO_REAP
    /* Negative fixture: kernel auto-reap makes real waitpid return ECHILD. */
    (void)signal(SIGCHLD, SIG_IGN);
#endif
    if (!reap_child(child, &status)) return 0;
    return okay && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif
