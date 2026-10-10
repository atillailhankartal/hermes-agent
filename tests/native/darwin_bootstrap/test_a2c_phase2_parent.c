#include "../../../native/darwin_bootstrap/launch_control.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef BH_A2C_ATTEMPT_IMAGE
#error "fixed test policy required"
#endif
int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) >= 104) return 70;
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0 || !bh_a2c_pending(directory)) { (void)dprintf(1, "DENIED\n"); return 30; }
    int channel[2], status = 0;
    pid_t child = -1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, channel) ||
        fcntl(channel[0], F_DUPFD, 151) != 151 ||
        !bh_a2c_spawn(BH_A2C_ATTEMPT_IMAGE, channel[1], &child)) return 71;
    (void)close(channel[1]);
    (void)dprintf(1, "ATTEMPT %ld\n", (long)child);
    if (!bh_a2c_channel_init(channel[0])) return 72;
    struct bh_a2c_config config = { .version = BH_A2C_VERSION, .epoch = BH_A2C_EPOCH };
    memcpy(config.parent, argv[1], strlen(argv[1]) + 1);
    int64_t deadline = bh_a2c_now() + BH_A2C_TIMEOUT_MS;
    if (!bh_a2c_send(channel[0], &config, sizeof(config), deadline)) return 73;
    for (uint32_t expected = 1; expected <= 4; expected++) {
        uint32_t event = 0, owned = 0;
        if (!bh_a2c_receive(channel[0], &event, sizeof(event), deadline)) break;
        if (event == BH_A2C_STATUS_TERMINAL) break;
        if (event != expected) return 74;
        if (expected >= 3) {
            if (!bh_a2c_receive(channel[0], &owned, sizeof(owned), deadline)) return 75;
            (void)dprintf(1, "BARRIER %u %u\n", expected, owned);
            char release;
            if (read(0, &release, 1) != 1 || release != 'G') {
                (void)shutdown(channel[0], SHUT_RDWR);
                break;
            }
        }
        struct bh_a2c_command_frame command = {BH_A2C_EPOCH, expected, BH_A2C_PROCEED};
        if (!bh_a2c_send(channel[0], &command, sizeof(command), deadline)) break;
    }
    /* Exact A ownership. Outer harness supplies process-group timeout cleanup. */
    while (waitpid(child, &status, 0) != child) if (errno != EINTR) return 76;
    (void)close(channel[0]);
    (void)dprintf(1, "ATTEMPT_REAP %ld %d\n", (long)child, status);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 20;
}
