#include "launch_control.h"
#ifdef BH_A2C_PHASE3
#include "a2c_phase3_policy.h"
#ifndef BH_A2C_STAGE0_IMAGE
#define BH_A2C_STAGE0_IMAGE "/uninstalled/a2c/stage0"
#endif
#endif
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

static void terminal(struct bh_a2a_root *root, int reason, int parent_fd) {
    root->cancelled = 1;
    /* No root_cancel, unlink, per-slot cleanup, retry or exit callbacks. */
    struct bh_a2c_status status = {
        .kind = BH_A2C_STATUS_TERMINAL, .reason = (uint32_t)reason,
        .cancelled = 1, .bound = (uint32_t)root->bound,
        .fd6_open = fcntl(6, F_GETFD) >= 0,
        .parent_open = parent_fd >= 0 && fcntl(parent_fd, F_GETFD) >= 0,
        .node_known = S_ISSOCK(root->node.st_mode) != 0
    };
    /* One nonblocking attempt even if FD3 setup failed. No retry, stdio, poll,
     * acknowledgement or send-success dependency can defer process teardown. */
    (void)send(3, &status, sizeof(status), MSG_DONTWAIT | MSG_NOSIGNAL);
    _exit(20);
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
        !bh_a2c_signals_match() || !bh_a2c_channel_init(3)) terminal(&root, 100, parent_fd);
    if (!bh_a2c_receive(3, &config, sizeof(config), control.deadline_ms) ||
        config.version != BH_A2C_VERSION || config.epoch != BH_A2C_EPOCH ||
        strnlen(config.parent, sizeof(config.parent)) == sizeof(config.parent))
        terminal(&root, 101, parent_fd);
    if (!bh_a2c_send(3, &checkpoint, sizeof(checkpoint), control.deadline_ms) ||
        !bh_a2c_guard(&control, &root, checkpoint)) terminal(&root, control.reason, parent_fd);
#ifdef BH_A2C_PHASE3
    const struct bh_a2c_phase3_manifest *release = bh_a2c_phase3_manifest();
    if (!bh_a2c_phase3_manifest_valid(bh_a2c_phase3_core(), release) ||
        strcmp(release->stage, BH_A2C_STAGE0_IMAGE) || !bh_a2c_phase3_images(release))
        terminal(&root, 106, parent_fd);
#endif
    if (!bh_a2c_check_alive(&control, &root)) terminal(&root, control.reason, parent_fd);
    /* Guard-to-syscall race is bounded by a post-bind guard, not made atomic. */
    if (bh_a2a_root_prepare_fd6(&root, 0) != BH_A2A_OK) terminal(&root, 102, parent_fd);
    parent_fd = open(config.parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent_fd < 0 || !bh_a2c_candidate(&config, parent_fd, &manifest)) terminal(&root, 103, parent_fd);
#ifdef BH_A2C_PHASE3
    if (!bh_a2c_phase3_check_pending(parent_fd, &control.journal_identity, 0))
        terminal(&root, 107, parent_fd);
#endif
    if (!bh_a2c_check_alive(&control, &root)) terminal(&root, control.reason, parent_fd);
    if (bh_a2a_root_bind_observe(&root, parent_fd, &manifest) != BH_A2A_OK)
        terminal(&root, 104, parent_fd);
    checkpoint = 2;
    if (!bh_a2c_send(3, &checkpoint, sizeof(checkpoint), control.deadline_ms) ||
        !bh_a2c_guard(&control, &root, checkpoint)) terminal(&root, control.reason, parent_fd);
#if defined(BH_A2C_PHASE2) || defined(BH_A2C_PHASE3)
    if (!bh_a2c_phase2(&control, &root)) terminal(&root, 105, parent_fd);
#endif
    /* Successful measurement also terminates; P never clears pending. */
    _exit(0);
}
