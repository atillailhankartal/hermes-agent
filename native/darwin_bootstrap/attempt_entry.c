#include "launch_control.h"
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void terminal(struct bh_a2a_root *root, int reason, int parent_fd) {
    root->cancelled = 1;
    /* No root_cancel, unlink, per-slot cleanup, retry or exit callbacks. */
    (void)dprintf(1, "A_TERMINAL reason=%d cancelled=%d bound=%d fd6=%d parent=%d node_known=%d\n",
                  reason, root->cancelled, root->bound, fcntl(6, F_GETFD) >= 0,
                  parent_fd >= 0 && fcntl(parent_fd, F_GETFD) >= 0,
                  S_ISSOCK(root->node.st_mode) != 0);
    _exit(20);
}
static int signals_match(void) {
    sigset_t mask;
    struct sigaction disposition;
    if (sigprocmask(SIG_SETMASK, NULL, &mask)) return 0;
    for (int signal_number = 1; signal_number < NSIG; signal_number++) {
        if (signal_number == SIGKILL || signal_number == SIGSTOP) continue;
        if (sigismember(&mask, signal_number) != 1 ||
            sigaction(signal_number, NULL, &disposition) ||
            disposition.sa_handler != SIG_DFL) return 0;
    }
    return 1;
}
int main(void) {
    const int allowed[] = {0, 1, 2, 3};
    struct bh_a2a_inventory inventory;
    struct bh_a2a_root root = { .socket_fd = -1, .parent_fd = -1 };
    struct bh_a2c_config config;
    struct bh_a2a_manifest_v1 manifest;
    struct bh_a2c_control control = { .deadline_ms = bh_a2c_now() + BH_A2C_TIMEOUT_MS };
    uint32_t checkpoint = 1;
    int parent_fd = -1;
    if (bh_a2a_inventory_check(allowed, 4, &inventory) != BH_A2A_OK || inventory.count != 4 ||
        !signals_match() || !bh_a2c_channel_init(3)) terminal(&root, 100, parent_fd);
    (void)dprintf(1, "A_ENTRY exact_fds=0,1,2,3 signal_policy=checked pid=%ld\n", (long)getpid());
    if (!bh_a2c_receive(3, &config, sizeof(config), control.deadline_ms) ||
        config.version != BH_A2C_VERSION || config.epoch != BH_A2C_EPOCH ||
        strnlen(config.parent, sizeof(config.parent)) == sizeof(config.parent))
        terminal(&root, 101, parent_fd);
    if (!bh_a2c_send(3, &checkpoint, sizeof(checkpoint), control.deadline_ms) ||
        !bh_a2c_guard(&control, &root, checkpoint)) terminal(&root, control.reason, parent_fd);
    /* Guard-to-syscall race is bounded by a post-bind guard, not made atomic. */
    if (bh_a2a_root_prepare_fd6(&root, 0) != BH_A2A_OK) terminal(&root, 102, parent_fd);
    parent_fd = open(config.parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent_fd < 0 || !bh_a2c_candidate(&config, parent_fd, &manifest)) terminal(&root, 103, parent_fd);
    if (!bh_a2c_check_alive(&control, &root)) terminal(&root, control.reason, parent_fd);
    if (bh_a2a_root_bind_observe(&root, parent_fd, &manifest) != BH_A2A_OK)
        terminal(&root, 104, parent_fd);
    checkpoint = 2;
    if (!bh_a2c_send(3, &checkpoint, sizeof(checkpoint), control.deadline_ms) ||
        !bh_a2c_guard(&control, &root, checkpoint)) terminal(&root, control.reason, parent_fd);
    (void)dprintf(1, "BOUND_OBSERVED_SOURCE_ONLY fd6=%d parent=%d children=0\n",
                  fcntl(6, F_GETFD) >= 0, fcntl(parent_fd, F_GETFD) >= 0);
    /* Successful measurement also terminates; P never clears pending. */
    _exit(0);
}
