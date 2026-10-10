#include "../../../native/darwin_bootstrap/broker_entry.h"
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __func__, __LINE__, #x); return 1; } } while (0)

#ifdef BH_A2B_FAULTS
static int open_count, stat_count, path_count, fail_open, fail_stat, fail_path;
static int replace_final, occupy7, preserve_unrelated, unrelated = -1;
static int intercepted_openat(int fd, const char *path, int flags, ...) {
    if (++open_count == fail_open) {
        if (preserve_unrelated) unrelated = fcntl(1, F_DUPFD_CLOEXEC, 100);
        errno = EACCES;
        return -1;
    }
    return openat(fd, path, flags);
}
static int intercepted_fstat(int fd, struct stat *info) {
    if (++stat_count == fail_stat) { errno = EIO; return -1; }
    return fstat(fd, info);
}
static int intercepted_fcntl(int fd, int command, ...) {
    va_list args;
    int result;
    if (command == F_GETFD || command == F_GETFL) return fcntl(fd, command);
    if (command == F_DUPFD_CLOEXEC && occupy7) {
        int foreign = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (foreign != 7) _exit(91);
    }
    va_start(args, command);
    if (command == F_GETPATH) {
        char *path = va_arg(args, char *);
        if (++path_count == fail_path) {
            if (replace_final) {
                int foreign;
                (void)close(7);
                foreign = open("/dev/null", O_RDONLY | O_CLOEXEC);
                if (foreign < 0 || dup2(foreign, 7) != 7) _exit(90);
                if (foreign != 7) (void)close(foreign);
                (void)fcntl(7, F_SETFD, FD_CLOEXEC);
            }
            errno = EIO;
            result = -1;
        } else result = fcntl(fd, command, path);
    } else result = fcntl(fd, command, va_arg(args, int));
    va_end(args);
    return result;
}
#define openat intercepted_openat
#define fstat intercepted_fstat
#define fcntl intercepted_fcntl
#include "../../../native/darwin_bootstrap/broker_entry.c"
#undef openat
#undef fstat
#undef fcntl
#endif

static int capture(int fd, struct bh_a2b_fd *out) {
    struct socket_fdinfo socket_info;
    memset(out, 0, sizeof(*out));
    out->number = fd;
    out->descriptor_flags = fcntl(fd, F_GETFD);
    out->status_flags = fcntl(fd, F_GETFL);
    CHECK(out->descriptor_flags >= 0 && out->status_flags >= 0);
    CHECK(fstat(fd, &out->metadata) == 0);
    CHECK(proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &socket_info, sizeof(socket_info)) == sizeof(socket_info));
    out->socket_identity = socket_info.psi.soi_so;
    return 0;
}

static int setup(struct bh_a2b_candidate *candidate, const char *path) {
    const int inherited[] = {3, 4, 6};
    size_t i;
    int fd;
    for (fd = 3; fd < 1024; fd++) (void)close(fd);
    memset(candidate, 0, sizeof(*candidate));
    for (i = 0; i < 3; i++) {
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        CHECK(fd >= 0);
        if (fd != inherited[i]) { CHECK(dup2(fd, inherited[i]) == inherited[i]); CHECK(close(fd) == 0); }
        CHECK(fcntl(inherited[i], F_SETFD, FD_CLOEXEC) == 0);
        CHECK(capture(inherited[i], &candidate->inherited[i]) == 0);
    }
    strcpy(candidate->path, path);
    candidate->path_length = strlen(candidate->path);
    CHECK(stat(candidate->path, &candidate->parent) == 0);
    return 0;
}

static int exercise(const char *name) {
    struct bh_a2b_candidate candidate;
    struct bh_a2b_observation *out = calloc(1, sizeof(*out));
    struct bh_a2b_fd socket_before, socket_after;
    struct stat fd6_before, fd6_after;
    int fd6_flags = fcntl(6, F_GETFD);
    int success = strncmp(name, "success", 7) == 0;
    int extra = -1;
    size_t i;
    const char *path = strcmp(name, "success_source7") == 0 ? "/private" : "/private/tmp";
    CHECK(out != NULL);
    CHECK(setup(&candidate, path) == 0);
    if (strcmp(name, "success_root") == 0) {
        strcpy(candidate.path, "/"); candidate.path_length = 1;
        CHECK(stat("/", &candidate.parent) == 0);
    }
    if (strcmp(name, "extra5") == 0) extra = fcntl(1, F_DUPFD_CLOEXEC, 5);
    if (strcmp(name, "extra7") == 0) extra = fcntl(1, F_DUPFD_CLOEXEC, 7);
    if (strcmp(name, "extra_high") == 0) extra = fcntl(1, F_DUPFD_CLOEXEC, 200);
    if (strncmp(name, "missing", 7) == 0) CHECK(close(atoi(name + 7)) == 0);
    if (strncmp(name, "cloexec", 7) == 0) CHECK(fcntl(atoi(name + 7), F_SETFD, 0) == 0);
    if (strncmp(name, "wrong_type", 10) == 0) {
        int fd = atoi(name + 10), replacement = open("/dev/null", O_RDONLY | O_CLOEXEC);
        CHECK(replacement >= 0 && dup2(replacement, fd) == fd);
        CHECK(close(replacement) == 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
    }
    if (strcmp(name, "aliased_inherited") == 0) {
        CHECK(dup2(3, 4) == 4 && fcntl(4, F_SETFD, FD_CLOEXEC) == 0);
        CHECK(capture(4, &candidate.inherited[1]) == 0);
    }
    if (strcmp(name, "reused3") == 0) {
        int replacement = socket(AF_UNIX, SOCK_STREAM, 0);
        CHECK(replacement >= 0 && dup2(replacement, 3) == 3);
        CHECK(close(replacement) == 0 && fcntl(3, F_SETFD, FD_CLOEXEC) == 0);
    }
    if (strcmp(name, "relative") == 0) strcpy(candidate.path, "private/tmp");
    if (strcmp(name, "empty") == 0) strcpy(candidate.path, "");
    if (strcmp(name, "dot") == 0) strcpy(candidate.path, "/private/./tmp");
    if (strcmp(name, "dotdot") == 0) strcpy(candidate.path, "/private/../private/tmp");
    if (strcmp(name, "empty_component") == 0) strcpy(candidate.path, "/private//tmp");
    if (strcmp(name, "terminal_slash") == 0) strcpy(candidate.path, "/private/tmp/");
    if (strcmp(name, "symlink") == 0) strcpy(candidate.path, "/tmp");
    if (strcmp(name, "alias") == 0) strcpy(candidate.path, "/private/TMP");
    if (strcmp(name, "missing_path") == 0) strcpy(candidate.path, "/private/tmp/bee-a2b-no-such-parent-88f7d6");
    candidate.path_length = strlen(candidate.path);
    if (strcmp(name, "nul_ambiguity") == 0) candidate.path_length++;
    if (strcmp(name, "overlong") == 0) candidate.path_length = sizeof(candidate.path);
    if (strcmp(name, "wrong_parent") == 0) CHECK(stat("/private", &candidate.parent) == 0);
    if (strcmp(name, "wrong_uid") == 0) candidate.parent.st_uid++;
    if (strcmp(name, "wrong_gid") == 0) candidate.parent.st_gid++;
    if (strcmp(name, "wrong_mode") == 0) candidate.parent.st_mode ^= 0001;
    if (strcmp(name, "wrong_device") == 0) candidate.parent.st_dev++;
    if (strcmp(name, "wrong_inode") == 0) candidate.parent.st_ino++;
    fd6_flags = fcntl(6, F_GETFD);
    if (fd6_flags >= 0) CHECK(fstat(6, &fd6_before) == 0);
    /* Capture FD6 after intentional initial-map corruption, before helper. */
    if (strcmp(name, "missing6") != 0 && strcmp(name, "wrong_type6") != 0)
        CHECK(capture(6, &socket_before) == 0);
#ifdef BH_A2B_FAULTS
    if (strcmp(name, "open_root_failure") == 0) fail_open = 1;
    if (strcmp(name, "open_component_failure") == 0) fail_open = 3;
    if (strcmp(name, "fstat_inventory_failure") == 0) fail_stat = 1;
    if (strcmp(name, "fstat_open_failure") == 0) fail_stat = 7;
    if (strcmp(name, "fstat_final_failure") == 0) fail_stat = 13;
    if (strcmp(name, "occupied7_at_move") == 0) occupy7 = 1;
    if (strcmp(name, "getpath_failure") == 0) fail_path = 2;
    if (strcmp(name, "final_getpath_failure") == 0) fail_path = 4;
    if (strcmp(name, "replaced7") == 0) { fail_path = 4; replace_final = 1; }
    if (strcmp(name, "preserve_unrelated") == 0) { fail_open = 3; preserve_unrelated = 1; }
#endif
    CHECK(bh_a2b_observe_fd7(&candidate, out) == (success ? BH_A2B_FD7_OBSERVED_UNTRUSTED : BH_A2B_PAUSED));
    CHECK(out->result == (success ? BH_A2B_FD7_OBSERVED_UNTRUSTED : BH_A2B_PAUSED));
    CHECK(out->acl_policy_verified == 0);
    CHECK(fcntl(6, F_GETFD) == fd6_flags);
    if (fd6_flags >= 0) {
        CHECK(fstat(6, &fd6_after) == 0);
        CHECK(fd6_before.st_dev == fd6_after.st_dev && fd6_before.st_ino == fd6_after.st_ino &&
              fd6_before.st_mode == fd6_after.st_mode);
    }
    if (strcmp(name, "missing6") != 0 && strcmp(name, "wrong_type6") != 0) {
        CHECK(capture(6, &socket_after) == 0);
        CHECK(socket_before.socket_identity == socket_after.socket_identity);
        CHECK(socket_before.descriptor_flags == socket_after.descriptor_flags);
        CHECK(socket_before.status_flags == socket_after.status_flags);
    }
    if (extra >= 0) CHECK(fcntl(extra, F_GETFD) >= 0);
    if (success) {
        CHECK(out->initial.complete && out->initial.count == 6);
        CHECK(out->final.complete && out->final.count == 7);
        CHECK(fcntl(5, F_GETFD) == -1 && fcntl(7, F_GETFD) == FD_CLOEXEC);
        CHECK(out->fd7_installed);
        CHECK(out->source_fd == (strcmp(name, "success_source7") == 0 ? 7 : 5));
        CHECK(out->ancestor_count >= 1 && strcmp(out->ancestors[0].path, "/") == 0);
        CHECK(strcmp(out->ancestors[out->ancestor_count - 1].path, candidate.path) == 0);
        for (i = 0; i < out->cleanup_count; i++) CHECK(out->cleanup[i].decision == BH_A2B_CLOSED);
    } else {
        CHECK(fcntl(5, F_GETFD) == -1 || extra == 5);
        CHECK(fcntl(7, F_GETFD) == -1 || extra == 7 || strcmp(name, "replaced7") == 0 || strcmp(name, "occupied7_at_move") == 0);
    }
#ifdef BH_A2B_FAULTS
    if (replace_final) {
        struct stat foreign;
        int retained = 0;
        CHECK(fstat(7, &foreign) == 0 && S_ISCHR(foreign.st_mode));
        for (i = 0; i < out->cleanup_count; i++)
            if (out->cleanup[i].number == 7 && out->cleanup[i].decision == BH_A2B_RETAINED_UNKNOWN) retained++;
        CHECK(retained == 1);
    }
    if (occupy7) {
        struct stat foreign;
        CHECK(fstat(7, &foreign) == 0 && S_ISCHR(foreign.st_mode));
        CHECK(fcntl(8, F_GETFD) == -1);
    }
    if (preserve_unrelated) CHECK(unrelated == 100 && fcntl(unrelated, F_GETFD) == FD_CLOEXEC);
#endif
    free(out);
    return 0;
}

int main(void) {
    const char *cases[] = {
#ifdef BH_A2B_FAULTS
        "open_root_failure", "open_component_failure", "fstat_inventory_failure",
        "fstat_open_failure", "fstat_final_failure", "occupied7_at_move", "getpath_failure", "final_getpath_failure", "replaced7", "preserve_unrelated"
#else
        "success", "success_source7", "success_root", "extra5", "extra7", "extra_high",
        "missing3", "missing4", "missing6", "cloexec3", "cloexec4", "cloexec6",
        "wrong_type3", "wrong_type4", "wrong_type6", "reused3", "aliased_inherited", "relative", "empty", "dot", "dotdot",
        "empty_component", "terminal_slash", "symlink", "alias", "missing_path",
        "nul_ambiguity", "overlong", "wrong_parent", "wrong_uid", "wrong_gid", "wrong_mode",
        "wrong_device", "wrong_inode"
#endif
    };
    size_t i;
    int failures = 0;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pid_t pid = fork();
        int status;
        if (pid == 0) _exit(exercise(cases[i]));
        if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
            fprintf(stderr, "FAIL case=%s\n", cases[i]); failures++;
        } else printf("PASS case=%s\n", cases[i]);
    }
    printf("A2b cases=%zu failures=%d synthetic_same_uid=1 acl_policy=UNAVAILABLE\n", sizeof(cases) / sizeof(cases[0]), failures);
    return failures != 0;
}
