#include "a2c_phase3_io.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef BH_A2C_TEST_AUDIT
void bh_a2c_test_audit(const char *event, pid_t child, int status);
#define IO_AUDIT(event, value, status) bh_a2c_test_audit(event, (pid_t)(value), (int)(status))
#else
#define IO_AUDIT(event, value, status) ((void)0)
#endif
static int alive(struct bh_a2c_phase3_io *io) {
    int64_t now = bh_a2c_now();
    if (io->control && !bh_a2c_check_alive(io->control, io->root)) return 0;
    return now >= 0 && now < io->deadline;
}
static int ready(struct bh_a2c_phase3_io *io, short event) {
    struct pollfd item = { .fd = io->fd, .events = event };
    while (alive(io)) {
        int64_t remaining = io->deadline - bh_a2c_now();
        if (remaining <= 0) return 0;
        int result = poll(&item, 1, remaining > 10 ? 10 : (int)remaining);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0 || (item.revents & (POLLERR | POLLNVAL))) return 0;
        if (result && (item.revents & (event | POLLHUP))) return alive(io);
    }
    return 0;
}
int bh_a2c_phase3_write(struct bh_a2c_phase3_io *io, const void *bytes, size_t length) {
    size_t offset = 0;
#ifdef BH_A2C_TEST_ERRNO
    int injected = 0;
#endif
    while (offset < length) {
        size_t request = length - offset;
#ifdef BH_A2C_TEST_SEND_CHUNK
        if (io->control && request > BH_A2C_TEST_SEND_CHUNK) request = BH_A2C_TEST_SEND_CHUNK;
#endif
        if (!ready(io, POLLOUT) || !alive(io)) return 0;
        IO_AUDIT("WRITE_GUARD", offset, request);
        ssize_t count;
#ifdef BH_A2C_TEST_ERRNO
        if (io->control && !injected) {
            injected = 1; errno = BH_A2C_TEST_ERRNO; count = -1;
            IO_AUDIT("SIMULATED_ERRNO", offset, errno);
        } else
#endif
        count = send(io->fd, (const unsigned char *)bytes + offset, request, MSG_DONTWAIT | MSG_NOSIGNAL);
        int saved = errno;
        IO_AUDIT("WRITE_RETURN", offset, count);
        if (count < 0 && (saved == EINTR || saved == EAGAIN || saved == EWOULDBLOCK)) continue;
        if (count <= 0) return 0;
        offset += (size_t)count;
#ifdef BH_A2C_TEST_PARK_WRITE
        if (io->control && offset == BH_A2C_TEST_PARK_WRITE) {
            IO_AUDIT("WRITE_PARK", offset, count);
            (void)raise(SIGSTOP);
        }
#endif
        /* Includes every positive partial write and completion, before any next syscall. */
        if (!alive(io)) return 0;
        IO_AUDIT("WRITE_CHECKED", offset, count);
    }
    return alive(io);
}
int bh_a2c_phase3_read_eof(struct bh_a2c_phase3_io *io, void *bytes, size_t length) {
    size_t offset = 0;
    unsigned char extra;
    for (;;) {
        if (!ready(io, POLLIN) || !alive(io)) return 0;
        ssize_t count = recv(io->fd, offset < length ? (unsigned char *)bytes + offset : &extra,
                             offset < length ? length - offset : 1, MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (!count) return offset == length && alive(io);
        if (count < 0 || offset == length) return 0;
        offset += (size_t)count;
        if (offset == length) IO_AUDIT("WAIT_EOF", io->fd, offset);
    }
}
int bh_a2c_phase3_shutdown(struct bh_a2c_phase3_io *io) {
    if (!alive(io) || shutdown(io->fd, SHUT_WR)) return 0;
    IO_AUDIT("HALF_CLOSE", io->fd, 0);
#ifdef BH_A2C_TEST_PARK_HALF_CLOSE
    if (io->control) { IO_AUDIT("HALF_CLOSE_PARK", io->fd, 0); (void)raise(SIGSTOP); }
#endif
    return alive(io);
}
