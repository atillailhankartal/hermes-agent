/* Disposable P fixture; fixed compiled attempt image, never a product launcher. */
#include "../../../native/darwin_bootstrap/launch_control.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifndef BH_A2C_ATTEMPT_IMAGE
#error "The test runner must pin the exact attempt binary at compile time"
#endif
static void writer(int number) { (void)number; (void)close(3); }
int main(int argc, char **argv) {
    struct bh_a2c_config config = { .version = BH_A2C_VERSION, .epoch = BH_A2C_EPOCH };
    int pair[2], directory_fd, status = 0;
    pid_t child = -1;
    uint32_t checkpoint;
    int64_t deadline = bh_a2c_now() + BH_A2C_TIMEOUT_MS;
    if (argc != 3 || strlen(argv[1]) >= sizeof(config.parent)) return 70;
    memcpy(config.parent, argv[1], strlen(argv[1]) + 1);
    directory_fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0 || !bh_a2c_pending(directory_fd)) {
        (void)dprintf(1, "P_RESTART_DENIED\n");
        return 30;
    }
    (void)dprintf(1, "P_PENDING_READBACK before_spawn=1\n");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 71;
    /* Deliberately inherited extra FD and signal settings must not reach A. */
    if (fcntl(directory_fd, F_DUPFD, 150) < 150 || signal(SIGUSR1, writer) == SIG_ERR ||
        signal(SIGUSR2, SIG_IGN) == SIG_ERR) return 72;
    if (!bh_a2c_spawn(BH_A2C_ATTEMPT_IMAGE, pair[1], &child)) return 73;
    (void)close(pair[1]); /* Only P owns the surviving peer of A's management3. */
    (void)dprintf(1, "P_SPAWN child=%ld\n", (long)child);
    if (!bh_a2c_channel_init(pair[0]) ||
        !bh_a2c_send(pair[0], &config, sizeof(config), deadline)) return 74;
    for (uint32_t expected = 1; expected <= 2; expected++) {
        if (!bh_a2c_receive(pair[0], &checkpoint, sizeof(checkpoint), deadline)) break;
        if (checkpoint != expected) return 75;
        if ((expected == 1 && !strcmp(argv[2], "loss_prebind")) ||
            (expected == 2 && !strcmp(argv[2], "loss_postbind"))) {
            (void)dprintf(1, "P_DEATH checkpoint=%u\n", expected);
            _exit(31); /* Actual parent process death, not a simulated F timeout. */
        }
        struct bh_a2c_command_frame command = {
            .epoch = BH_A2C_EPOCH, .checkpoint = expected, .command = BH_A2C_PROCEED
        };
        if (expected == 1 && !strcmp(argv[2], "cancel")) command.command = BH_A2C_CANCEL;
        if (expected == 1 && !strcmp(argv[2], "stale")) command.epoch++;
        if (expected == 1 && !strcmp(argv[2], "shutdown")) {
            (void)shutdown(pair[0], SHUT_RDWR);
            break;
        }
        if (expected == 1 && !strcmp(argv[2], "queued_cancel")) {
            struct bh_a2c_command_frame batch[2] = { command, command };
            batch[1].command = BH_A2C_CANCEL;
            (void)bh_a2c_send(pair[0], batch, sizeof(batch), deadline);
            break;
        }
        if (expected == 1 && !strcmp(argv[2], "partial")) {
            (void)bh_a2c_send(pair[0], &command, 1, deadline);
            break;
        }
        if (expected == 1 && !strcmp(argv[2], "timeout")) break;
        if (!bh_a2c_send(pair[0], &command, sizeof(command), deadline)) break;
    }
    /* Keep peer open in timeout/partial tests; A must honor its own deadline. */
    int64_t reap_deadline = bh_a2c_now() + 4000;
    for (;;) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) break;
        if (result < 0 && errno != EINTR) return 76;
        if (bh_a2c_now() >= reap_deadline) {
            (void)kill(child, SIGKILL);
            (void)waitpid(child, &status, 0);
            return 77;
        }
        struct timespec pause = { .tv_nsec = 10000000 };
        (void)nanosleep(&pause, NULL);
    }
    (void)dprintf(1, "P_REAP exited=%d code=%d pending_unchanged=1\n",
                  WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return WIFEXITED(status) ? 0 : 78;
}
