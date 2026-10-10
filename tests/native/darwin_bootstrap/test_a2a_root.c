#include "../../../native/darwin_bootstrap/abi_v1.h"
#include "../../../native/trusted_inbound/darwin/socket_observer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int checks;
static int failures;
static const char *child_fixture;

#ifdef BH_A2A_TEST_OBSERVER_FAULT
static int observer_fault_calls;

/* Link-time fault fixture: production socket_lineage.c executes the same path. */
struct bh_socket_observation bh_darwin_observe_fd6(const struct bh_socket_expectation *expected) {
    (void)expected;
    observer_fault_calls++;
    return (struct bh_socket_observation){BH_UNKNOWN, BH_RUNTIME};
}
#endif

static void check(int condition, const char *name) {
    checks++;
    if (!condition) { fprintf(stderr, "ASSERT %s\n", name); failures++; }
}

static void clean_child_table(void) {
    int fd;
    for (fd = 3; fd < 256; fd++) (void)close(fd);
}

static void source_case(int desired) {
    struct bh_a2a_root root = { .socket_fd = -1, .parent_fd = -1 };
    int filler[3];
    int count = desired <= 6 ? desired - 3 : 0;
    int index;
    clean_child_table();
    for (index = 0; index < count; index++) {
        filler[index] = open("/dev/null", O_RDONLY);
        check(filler[index] == index + 3, "source_filler_exact_slot");
    }
    check(fcntl(6, F_GETFD) == -1 && errno == EBADF, "initial_fd6_absent");
    check(bh_a2a_root_prepare_fd6(&root, desired >= 64 ? desired : 0) == BH_A2A_OK,
          "root_prepare_local_progress");
    check(root.socket_fd == 6 && root.socket_owned, "root_socket_must_be_fd6_before_bind");
    check((fcntl(6, F_GETFD) & FD_CLOEXEC) != 0, "root_fd6_cloexec");
    if (desired != 6) {
        check(fcntl(desired, F_GETFD) == -1 && errno == EBADF,
              "owned_source_alias_closed_after_install");
    }
    bh_a2a_root_cancel(&root);
    check(fcntl(6, F_GETFD) == -1 && errno == EBADF,
          "root_fd6_closed_on_cancel");
    for (index = 0; index < count; index++) {
        check(fcntl(filler[index], F_GETFD) != -1, "unrelated_filler_preserved");
        (void)close(filler[index]);
    }
}

static void sentinel_case(void) {
    struct bh_a2a_root root = { .socket_fd = -1, .parent_fd = -1 };
    struct stat before;
    struct stat after;
    int sentinel;
    clean_child_table();
    sentinel = open("/dev/null", O_RDONLY);
    check(sentinel == 3, "sentinel_source_3");
    check(dup2(sentinel, 6) == 6, "sentinel_installed_6");
    check(fstat(6, &before) == 0, "sentinel_before_stat");
    check(bh_a2a_root_prepare_fd6(&root, 0) == BH_A2A_PAUSED,
          "preoccupied_fd6_pauses_without_close");
    check(fstat(6, &after) == 0 && before.st_dev == after.st_dev &&
          before.st_ino == after.st_ino, "preoccupied_fd6_unchanged");
    check(root.socket_owned == 0, "sentinel_never_adopted");
    (void)close(6);
    (void)close(sentinel);
}

static void zero_cancel_case(void) {
    struct bh_a2a_root root = {0};
    struct stat before;
    struct stat after;
    clean_child_table();
    check(fstat(0, &before) == 0, "stdio_before_zero_cancel");
    bh_a2a_root_cancel(&root);
    check(fstat(0, &after) == 0 && before.st_dev == after.st_dev &&
          before.st_ino == after.st_ino, "zero_context_cancel_preserves_stdio");
}

static void inventory_case(void) {
    const int allowed[] = {0, 1, 2};
    struct bh_a2a_inventory snapshot;
    int extra;
    clean_child_table();
    check(bh_a2a_inventory_check(allowed, 3, &snapshot) == BH_A2A_OK &&
          snapshot.count == 3, "exact_initial_inventory");
    extra = open("/dev/null", O_RDONLY);
    check(extra == 3, "extra_fd_opened");
    check(bh_a2a_inventory_check(allowed, 3, &snapshot) == BH_A2A_PAUSED,
          "unexpected_inherited_fd_pauses");
    (void)close(extra);
}

static void bound_case(void) {
    struct bh_a2a_root root = { .socket_fd = -1, .parent_fd = -1 };
    struct bh_a2a_manifest_v1 manifest;
    struct stat directory;
    char parent[] = "/private/tmp/bee-a2a-root-XXXXXX";
    int parent_fd;
    int occupied;
    clean_child_table();
    check(mkdtemp(parent) != NULL, "fixture_parent_created");
    check(bh_a2a_root_prepare_fd6(&root, 0) == BH_A2A_OK,
          "fresh_root6_before_directory_open");
    parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    check(parent_fd >= 0 && parent_fd != 6, "root_parent_separate_fd");
    check(fstat(parent_fd, &directory) == 0, "root_parent_stat");
    memset(&manifest, 0, sizeof(manifest));
    manifest.version = 1;
    (void)snprintf(manifest.parent_path, sizeof(manifest.parent_path), "%s", parent);
    (void)snprintf(manifest.leaf, sizeof(manifest.leaf), "%s", "protected.sock");
    (void)snprintf(manifest.stage0_path, sizeof(manifest.stage0_path), "%s", "/usr/bin/true");
    manifest.parent_uid = directory.st_uid;
    manifest.parent_gid = directory.st_gid;
    manifest.parent_mode = directory.st_mode & 07777;
    manifest.parent_device = directory.st_dev;
    manifest.parent_inode = directory.st_ino;
    manifest.broker_uid = getuid();
    manifest.broker_gid = getgid();
    manifest.release_digest[0] = 1;
    check(bh_a2a_manifest_validate(&manifest) == BH_A2A_OK,
          "manifest_local_syntax_only");
    manifest.parent_inode++;
    check(bh_a2a_root_bind_observe(&root, parent_fd, &manifest) == BH_A2A_PAUSED,
          "changed_root_record_rejected_before_bind");
    manifest.parent_inode--;
    occupied = openat(parent_fd, manifest.leaf, O_CREAT | O_EXCL | O_RDONLY, 0600);
    check(occupied >= 0, "preexisting_leaf_created");
    check(bh_a2a_root_bind_observe(&root, parent_fd, &manifest) == BH_A2A_PAUSED,
          "preexisting_leaf_never_unlinked");
    check(fcntl(occupied, F_GETFD) >= 0, "preexisting_leaf_preserved");
    (void)close(occupied);
    check(unlinkat(parent_fd, manifest.leaf, 0) == 0, "fixture_leaf_removed_by_owner");
    check(bh_a2a_root_bind_observe(&root, parent_fd, &manifest) == BH_A2A_OK,
          "actual_root_fd6_bound_a1_observed");
    check(root.bound && root.parent_fd == parent_fd, "root_retained_parent_separate");
    bh_a2a_root_cancel(&root);
    check(bh_a2a_root_cleanup_leaf(&root) == BH_A2A_OK,
          "owned_nofollow_leaf_cleanup");
    check(rmdir(parent) == 0, "fixture_parent_removed");
}

static void replaced_leaf_case(void) {
    struct bh_a2a_root root = { .socket_fd = -1, .parent_fd = -1 };
    struct bh_a2a_manifest_v1 manifest;
    struct stat directory;
    struct stat replacement;
    char parent[] = "/private/tmp/bee-a2a-replace-XXXXXX";
    int parent_fd;
    int file;
    clean_child_table();
    check(mkdtemp(parent) != NULL, "replace_parent_created");
    check(bh_a2a_root_prepare_fd6(&root, 0) == BH_A2A_OK,
          "replace_root6_prepared");
    parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    check(parent_fd >= 0 && fstat(parent_fd, &directory) == 0,
          "replace_parent_verified");
    memset(&manifest, 0, sizeof(manifest));
    manifest.version = 1;
    (void)snprintf(manifest.parent_path, sizeof(manifest.parent_path), "%s", parent);
    (void)snprintf(manifest.leaf, sizeof(manifest.leaf), "%s", "protected.sock");
    (void)snprintf(manifest.stage0_path, sizeof(manifest.stage0_path), "%s", "/usr/bin/true");
    manifest.parent_uid = directory.st_uid;
    manifest.parent_gid = directory.st_gid;
    manifest.parent_mode = directory.st_mode & 07777;
    manifest.parent_device = directory.st_dev;
    manifest.parent_inode = directory.st_ino;
    manifest.broker_uid = getuid();
    manifest.broker_gid = getgid();
    manifest.release_digest[0] = 1;
    check(bh_a2a_root_bind_observe(&root, parent_fd, &manifest) == BH_A2A_OK,
          "replace_original_bound");
    bh_a2a_root_cancel(&root);
    check(unlinkat(parent_fd, manifest.leaf, 0) == 0,
          "fixture_removes_original_owned_leaf");
    file = openat(parent_fd, manifest.leaf, O_CREAT | O_EXCL | O_RDONLY, 0600);
    check(file >= 0, "replacement_created");
    (void)close(file);
    check(bh_a2a_root_cleanup_leaf(&root) == BH_A2A_PAUSED,
          "replacement_cleanup_refused");
    check(fstatat(parent_fd, manifest.leaf, &replacement, AT_SYMLINK_NOFOLLOW) == 0 &&
          S_ISREG(replacement.st_mode), "replacement_preserved");
    check(unlinkat(parent_fd, manifest.leaf, 0) == 0,
          "fixture_removes_own_replacement");
    (void)close(parent_fd);
    check(rmdir(parent) == 0, "replace_parent_removed");
}

static void map_and_frame_case(void) {
    struct bh_a2a_root root = { .socket_fd = -1, .parent_fd = -1 };
    struct bh_a2a_child_map map = {0};
    struct bh_a2a_close_frame frame = {0};
    posix_spawn_file_actions_t actions;
    unsigned char key[32] = {0};
    int source[] = {3, 4, 5, 6};
    int pair[2];
    int index;
    int sockets[3];
    clean_child_table();
    for (index = 0; index < 3; index++) {
        sockets[index] = open("/dev/null", O_RDONLY);
        check(sockets[index] == index + 3, "map_source_slot");
    }
    check(bh_a2a_root_prepare_fd6(&root, 0) == BH_A2A_OK,
          "map_root_source6");
    check(bh_a2a_child_map_prepare(&map, source) == BH_A2A_OK,
          "child_map_temps_prepared");
    for (index = 0; index < 4; index++) {
        check(map.temporary[index] >= 64, "child_temp_high_slot");
        check((fcntl(map.temporary[index], F_GETFD) & FD_CLOEXEC) != 0,
              "child_temp_cloexec");
    }
    check(posix_spawn_file_actions_init(&actions) == 0, "child_actions_init");
    check(bh_a2a_child_actions(&actions, &map) == BH_A2A_OK,
          "child_close_then_dup_then_close_actions");
    check(posix_spawn_file_actions_destroy(&actions) == 0, "child_actions_destroy");
    frame.version = BH_A2A_FRAME_VERSION;
    frame.type = BH_A2A_FRAME_ROOT_CLOSED;
    frame.sequence = 1;
    frame.generation = 4;
    frame.launch_nonce[0] = 1;
    frame.incarnation[0] = 2;
    frame.inventory_digest[0] = 3;
    key[0] = 4;
    check(bh_a2a_frame_sign(&frame, key) == BH_A2A_OK, "close_frame_signed");
    check(bh_a2a_frame_verify(&frame, key, 1) == BH_A2A_OK,
          "close_frame_verified");
    frame.generation++;
    check(bh_a2a_frame_verify(&frame, key, 1) == BH_A2A_PAUSED,
          "changed_generation_rejected");
    frame.generation--;
    check(bh_a2a_frame_verify(&frame, key, 2) == BH_A2A_PAUSED,
          "reordered_sequence_rejected");
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "control_pair_created");
    key[0]++;
    check(bh_a2a_frame_verify(&frame, key, 1) == BH_A2A_PAUSED,
          "wrong_control_key_rejected");
    key[0]--;
    check(bh_a2a_frame_verify(&frame, key, 1) == BH_A2A_OK,
          "original_control_key_restored");
    (void)close(pair[0]);
    (void)close(pair[1]);
    for (index = 0; index < 4; index++) (void)close(map.temporary[index]);
    for (index = 0; index < 3; index++) (void)close(sockets[index]);
    bh_a2a_root_cancel(&root);
}

static int set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static void actual_spawn_map_case(int cancel_first) {
    struct bh_a2a_root root = { .socket_fd = -1, .parent_fd = -1 };
    struct bh_a2a_manifest_v1 manifest;
    struct bh_a2a_child_map map = {0};
    posix_spawn_file_actions_t actions;
    struct stat directory;
    char parent[] = "/private/tmp/bee-a2a-spawn-XXXXXX";
    char *argv[2];
    char *envp[] = {"LANG=C", NULL};
    char response = '?';
    int bootstrap[2];
    int control[2];
    int status_pipe[2];
    int sources[4];
    int remaining[7];
    unsigned char key[32] = {0};
    struct bh_a2a_close_frame frame = {0};
    int parent_fd;
    int child_status = -1;
    int index;
    pid_t child = -1;
    clean_child_table();
    check(child_fixture != NULL, "fixture_path_supplied");
    check(mkdtemp(parent) != NULL, "spawn_parent_created");
    check(bh_a2a_root_prepare_fd6(&root, 0) == BH_A2A_OK,
          "spawn_root6_prepared");
    parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    check(parent_fd >= 0 && parent_fd != 6, "spawn_parent_fd_distinct");
    check(fstat(parent_fd, &directory) == 0, "spawn_parent_stat");
    memset(&manifest, 0, sizeof(manifest));
    manifest.version = 1;
    (void)snprintf(manifest.parent_path, sizeof(manifest.parent_path), "%s", parent);
    (void)snprintf(manifest.leaf, sizeof(manifest.leaf), "%s", "protected.sock");
    (void)snprintf(manifest.stage0_path, sizeof(manifest.stage0_path), "%s", "/usr/bin/true");
    manifest.parent_uid = directory.st_uid;
    manifest.parent_gid = directory.st_gid;
    manifest.parent_mode = directory.st_mode & 07777;
    manifest.parent_device = directory.st_dev;
    manifest.parent_inode = directory.st_ino;
    manifest.broker_uid = getuid();
    manifest.broker_gid = getgid();
    manifest.release_digest[0] = 1;
    check(bh_a2a_root_bind_observe(&root, parent_fd, &manifest) == BH_A2A_OK,
          "spawn_root6_bound_a1");
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, bootstrap) == 0,
          "bootstrap_pair_created");
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, control) == 0,
          "control_pair_created");
    check(pipe(status_pipe) == 0, "exec_status_pipe_created");
    check(set_cloexec(bootstrap[1]) && set_cloexec(control[1]) &&
          set_cloexec(status_pipe[0]), "root_endpoints_cloexec");
    sources[0] = bootstrap[0];
    sources[1] = control[0];
    sources[2] = status_pipe[1];
    sources[3] = 6;
    check(bh_a2a_child_map_prepare(&map, sources) == BH_A2A_OK,
          "spawn_child_temps_prepared");
    check(posix_spawn_file_actions_init(&actions) == 0, "spawn_actions_init");
    check(bh_a2a_child_actions(&actions, &map) == BH_A2A_OK,
          "spawn_actions_ordered");
    {
        pid_t absent_child = -1;
        char *absent_argv[] = {"/absent-bee-a2a-stage0", NULL};
        int result = posix_spawn(&absent_child, absent_argv[0], &actions,
                                 NULL, absent_argv, envp);
        check(result == ENOENT && absent_child == -1,
              "spawn_failure_no_child_no_root_retirement");
        check(fcntl(6, F_GETFD) >= 0, "spawn_failure_root6_retained");
    }
    argv[0] = (char *)child_fixture;
    argv[1] = NULL;
    check(posix_spawn(&child, child_fixture, &actions, NULL, argv, envp) == 0,
          "fixed_fixture_spawned");
    check(posix_spawn_file_actions_destroy(&actions) == 0,
          "spawn_actions_destroyed");
    remaining[0] = 0;
    remaining[1] = 1;
    remaining[2] = 2;
    remaining[3] = parent_fd;
    remaining[4] = bootstrap[1];
    remaining[5] = control[1];
    remaining[6] = status_pipe[0];
    frame.version = BH_A2A_FRAME_VERSION;
    frame.type = BH_A2A_FRAME_ROOT_CLOSED;
    frame.sequence = 1;
    frame.generation = 4;
    frame.launch_nonce[0] = 1;
    frame.incarnation[0] = 2;
    key[0] = 4;
    if (cancel_first) {
        check(bh_a2a_root_retire_and_signal(&map, &root, 0, control[1],
                                             remaining, 7, &frame, key) == BH_A2A_PAUSED,
              "invalid_child_latches_cancel");
        check(root.cancelled == 1, "cancel_is_irreversible_for_launch");
        check(bh_a2a_root_retire_and_signal(&map, &root, child, control[1],
                                             remaining, 7, &frame, key) == BH_A2A_PAUSED,
              "cancel_blocks_later_real_child_frame");
        check(fcntl(6, F_GETFD) >= 0 && map.prepared,
              "cancel_preserves_root6_and_child_aliases");
        check(recv(control[1], &response, 1, MSG_DONTWAIT) == -1 &&
              (errno == EAGAIN || errno == EWOULDBLOCK),
              "cancel_emits_no_frame_or_child_ack");
        for (index = 0; index < 4; index++)
            if (map.temporary[index] >= 64) (void)close(map.temporary[index]);
        (void)close(sources[0]);
        (void)close(sources[1]);
        (void)close(sources[2]);
        (void)close(control[1]);
        check(waitpid(child, &child_status, 0) == child && WIFEXITED(child_status) &&
              WEXITSTATUS(child_status) == 42, "cancelled_child_saw_control_eof");
    } else {
        check(bh_a2a_root_retire_and_signal(&map, &root, child, control[1],
                                             remaining, 7, &frame, key) == BH_A2A_OK,
              "root_alias_retirement_precedes_authenticated_frame");
        check(fcntl(6, F_GETFD) == -1 && errno == EBADF,
              "root_fd6_absent_after_retirement");
        check(read(control[1], &response, 1) == 1 && response == 'K',
              "child_real_map_and_close_frame_validated");
        check(waitpid(child, &child_status, 0) == child && WIFEXITED(child_status) &&
              WEXITSTATUS(child_status) == 0, "owned_child_reaped_successfully");
    }
    (void)close(bootstrap[1]);
    if (!cancel_first) (void)close(control[1]);
    (void)close(status_pipe[0]);
    bh_a2a_root_cancel(&root);
    check(bh_a2a_root_cleanup_leaf(&root) == BH_A2A_OK,
          "spawn_leaf_cleanup_after_reap");
    check(rmdir(parent) == 0, "spawn_parent_removed");
}

static void actual_spawn_success(void) { actual_spawn_map_case(0); }
static void actual_spawn_cancel(void) { actual_spawn_map_case(1); }

#ifdef BH_A2A_TEST_OBSERVER_FAULT
static void observer_fault_case(int replace_leaf) {
    struct bh_a2a_root root = { .socket_fd = -1, .parent_fd = -1 };
    struct bh_a2a_manifest_v1 manifest = {0};
    struct bh_a2a_child_map map = {0};
    struct bh_a2a_close_frame frame = {0};
    struct stat directory, original, current;
    char parent[] = "/private/tmp/bee-a2a-fault-XXXXXX";
    unsigned char key[32] = {0};
    int sources[] = {3, 4, 5, 6};
    int remaining[6];
    int pair[2];
    int parent_fd;
    int index;
    char received;
    clean_child_table();
    check(mkdtemp(parent) != NULL, "fault_parent_created");
    for (index = 0; index < 3; index++)
        check(open("/dev/null", O_RDONLY) == index + 3, "fault_source_slots");
    check(bh_a2a_root_prepare_fd6(&root, 0) == BH_A2A_OK, "fault_root6_prepared");
    parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    check(parent_fd >= 0 && parent_fd != 6 && fstat(parent_fd, &directory) == 0,
          "fault_parent_distinct");
    manifest.version = 1;
    (void)snprintf(manifest.parent_path, sizeof(manifest.parent_path), "%s", parent);
    (void)snprintf(manifest.leaf, sizeof(manifest.leaf), "%s", "protected.sock");
    (void)snprintf(manifest.stage0_path, sizeof(manifest.stage0_path), "%s", "/usr/bin/true");
    manifest.parent_uid = directory.st_uid;
    manifest.parent_gid = directory.st_gid;
    manifest.parent_mode = directory.st_mode & 07777;
    manifest.parent_device = directory.st_dev;
    manifest.parent_inode = directory.st_ino;
    manifest.broker_uid = getuid();
    manifest.broker_gid = getgid();
    manifest.release_digest[0] = 1;
    check(bh_a2a_root_bind_observe(&root, parent_fd, &manifest) == BH_A2A_PAUSED,
          "post_bind_observer_failure_paused");
    check(observer_fault_calls == 1 && root.bound && root.parent_fd == parent_fd,
          "post_bind_failure_retains_cleanup_parent");
    check(root.cancelled, "post_bind_observer_failure_latches_cancel");
    check(fstatat(parent_fd, manifest.leaf, &original, AT_SYMLINK_NOFOLLOW) == 0 &&
          S_ISSOCK(original.st_mode) && original.st_dev == root.node.st_dev &&
          original.st_ino == root.node.st_ino, "post_bind_original_node_recorded");
    if (!replace_leaf) {
        check(bh_a2a_child_map_prepare(&map, sources) == BH_A2A_OK,
              "fault_child_map_prepared");
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0,
              "fault_control_pair_created");
        remaining[0] = 0; remaining[1] = 1; remaining[2] = 2;
        remaining[3] = parent_fd; remaining[4] = pair[0]; remaining[5] = pair[1];
        frame.version = BH_A2A_FRAME_VERSION;
        frame.type = BH_A2A_FRAME_ROOT_CLOSED;
        frame.sequence = 1;
        frame.generation = 4;
        frame.launch_nonce[0] = 1;
        frame.incarnation[0] = 2;
        key[0] = 4;
        check(bh_a2a_root_retire_and_signal(&map, &root, getpid(), pair[0],
                                             remaining, 6, &frame, key) == BH_A2A_PAUSED,
              "post_bind_failure_blocks_close_frame");
        check(fcntl(6, F_GETFD) >= 0, "post_bind_failure_preserves_fd6");
        check(recv(pair[1], &received, 1, MSG_DONTWAIT) == -1 &&
              (errno == EAGAIN || errno == EWOULDBLOCK),
              "post_bind_failure_emits_no_frame");
        for (index = 0; index < 4; index++)
            if (map.temporary[index] >= 64) (void)close(map.temporary[index]);
        (void)close(pair[0]);
        (void)close(pair[1]);
    } else {
        int replacement;
        check(unlinkat(parent_fd, manifest.leaf, 0) == 0,
              "fault_fixture_removed_original");
        replacement = openat(parent_fd, manifest.leaf,
                             O_CREAT | O_EXCL | O_RDONLY, 0600);
        check(replacement >= 0, "fault_replacement_created");
        (void)close(replacement);
        bh_a2a_root_cancel(&root);
        check(bh_a2a_root_cleanup_leaf(&root) == BH_A2A_PAUSED,
              "fault_replacement_cleanup_refused");
        check(fstatat(parent_fd, manifest.leaf, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
              S_ISREG(current.st_mode), "fault_replacement_preserved");
        check(unlinkat(parent_fd, manifest.leaf, 0) == 0,
              "fault_fixture_removed_replacement");
    }
    bh_a2a_root_cancel(&root);
    if (!replace_leaf)
        check(bh_a2a_root_cleanup_leaf(&root) == BH_A2A_OK,
              "post_bind_failure_exact_leaf_cleanup");
    else (void)close(parent_fd);
    check(rmdir(parent) == 0, "fault_parent_removed");
}

static void observer_fault_exact(void) { observer_fault_case(0); }
static void observer_fault_replaced(void) { observer_fault_case(1); }
#endif

static int run(void (*operation)(void), const char *name) {
    int status;
    pid_t child = fork();
    if (child < 0) return 0;
    if (child == 0) {
        (void)alarm(8);
        checks = 0;
        failures = 0;
        operation();
        fprintf(stdout, "%s checks=%d failures=%d\n", name, checks, failures);
        fflush(stdout);
        _exit(failures ? 1 : 0);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "CASE %s failed\n", name);
        return 0;
    }
    return 1;
}

static void source3(void) { source_case(3); }
static void source4(void) { source_case(4); }
static void source5(void) { source_case(5); }
static void source6(void) { source_case(6); }
static void source64(void) { source_case(64); }

int main(int argc, char **argv) {
    int passed = 0;
#ifdef BH_A2A_TEST_OBSERVER_FAULT
    if (argc == 3 && strcmp(argv[2], "observer_fault") == 0) {
        child_fixture = argv[1];
        passed += run(observer_fault_exact, "observer_fault_exact");
        passed += run(observer_fault_replaced, "observer_fault_replaced");
        fprintf(stdout, "cases=%d failures=%d\n", 2, 2 - passed);
        return passed == 2 ? 0 : 1;
    }
#endif
    if (argc != 2) return 2;
    child_fixture = argv[1];
    passed += run(source3, "source3");
    passed += run(source4, "source4");
    passed += run(source5, "source5");
    passed += run(source6, "source6");
    passed += run(source64, "source64");
    passed += run(sentinel_case, "sentinel6");
    passed += run(zero_cancel_case, "zero_cancel");
    passed += run(inventory_case, "inventory");
    passed += run(bound_case, "bound");
    passed += run(replaced_leaf_case, "replaced_leaf");
    passed += run(map_and_frame_case, "map_frame");
    passed += run(actual_spawn_success, "actual_spawn_map");
    passed += run(actual_spawn_cancel, "actual_spawn_cancel");
    fprintf(stdout, "cases=%d failures=%d\n", 13, 13 - passed);
    return passed == 13 ? 0 : 1;
}
