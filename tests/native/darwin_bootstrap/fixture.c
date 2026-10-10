/* Disposable Darwin experiment. Never a protected launcher or broker. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/proc_info.h>
#include "socket_observer.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LIMIT 256
#define DEADLINE_MS 3000
struct observation {
    int phase, open_mask, cloexec_mask, unexpected_fds;
    int acceptconn, path_matches, denial_errno, option_errno;
    uid_t uid;
};
static char directory[] = "/tmp/hermes-fd6-XXXXXX";
static char pathname[sizeof(((struct sockaddr_un *)0)->sun_path)];
static int parent_dir = -1;
static pid_t owned_child = -1;
static bool reaped = true, recorded = false;
static struct stat node, socket_metadata;
static int root_source_cloexec;
static const char *observation_mode = "strict";

static void require(bool condition, const char *operation)
{
    if (!condition) { perror(operation); exit(1); }
}

static bool same_node(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           (a->st_mode & S_IFMT) == (b->st_mode & S_IFMT);
}

static bool remove_recorded_node(const struct stat *expected)
{
    struct stat actual;
    return reaped && fstatat(parent_dir, "socket", &actual, AT_SYMLINK_NOFOLLOW) == 0 &&
           same_node(expected, &actual) && unlinkat(parent_dir, "socket", 0) == 0;
}

/* Failure cleanup never removes an unknown node or a live child's pathname. */
static void cleanup(void)
{
    if (parent_dir < 0) return;
    if (reaped) {
        (void)fchmod(parent_dir, 0700);
        if (recorded) (void)remove_recorded_node(&node);
        (void)rmdir(directory); /* Refuses nonempty directories. */
    }
    (void)close(parent_dir);
}

static struct sockaddr_un address(const char *path)
{
    struct sockaddr_un result = {0};
    require(strlen(path) < sizeof(result.sun_path), "path length");
    result.sun_family = AF_UNIX;
    result.sun_len = (uint8_t)sizeof(result);
    memcpy(result.sun_path, path, strlen(path) + 1);
    return result;
}

static int high_copy(int fd)
{
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 64);
    require(copy >= 64 && copy < LIMIT, "reserve high fd");
    return copy;
}

static int high_move(int fd)
{
    int copy = high_copy(fd);
    require(close(fd) == 0, "close original");
    return copy;
}

static void channel(int pair[2], bool duplex)
{
    int raw[2];
    require((duplex ? socketpair(AF_UNIX, SOCK_STREAM, 0, raw) : pipe(raw)) == 0,
            "channel");
    pair[0] = high_move(raw[0]);
    pair[1] = high_move(raw[1]);
}

static bool transfer(int fd, void *buffer, size_t length, bool writing)
{
    unsigned char *bytes = buffer;
    while (length) {
        struct pollfd item = {fd, writing ? POLLOUT : POLLIN, 0};
        int available = poll(&item, 1, DEADLINE_MS);
        if (available < 0 && errno == EINTR) continue;
        if (available <= 0) return false;
        ssize_t count = writing ? write(fd, bytes, length) : read(fd, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        bytes += count;
        length -= (size_t)count;
    }
    return true;
}

static struct observation observe(int phase, const char *path)
{
    struct observation result = {.phase = phase, .acceptconn = -1, .uid = geteuid()};
    for (int fd = 0; fd < LIMIT; fd++) {
        int flags = fcntl(fd, F_GETFD);
        if (flags < 0) continue;
        if (fd < 7) {
            result.open_mask |= 1 << fd;
            if (flags & FD_CLOEXEC) result.cloexec_mask |= 1 << fd;
        } else result.unexpected_fds++;
    }
    socklen_t size = sizeof(result.acceptconn);
    if (getsockopt(6, SOL_SOCKET, SO_ACCEPTCONN, &result.acceptconn, &size) != 0)
        result.option_errno = errno;
    if (strcmp(observation_mode, "libproc-observational") == 0) {
        /* Disposable consumer owns the directory FD only during observation.
         * This does not establish protected namespace or launch provenance. */
        char parent[sizeof(pathname)];
        require(strlen(path) < sizeof(parent), "observer path");
        memcpy(parent, path, strlen(path) + 1);
        char *leaf = strrchr(parent, '/');
        require(leaf != NULL, "observer basename");
        *leaf++ = '\0';
        int directory_fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct bh_socket_expectation expected = {.directory_fd = directory_fd,
            .basename = leaf, .pathname = path, .pathname_length = strlen(path)};
        result.acceptconn = -1;
        if (directory_fd >= 0) {
            if (fstatat(directory_fd, leaf, &expected.node, AT_SYMLINK_NOFOLLOW) == 0) {
                struct bh_socket_observation measured = bh_darwin_observe_fd6(&expected);
                if (measured.state == BH_BOUND_OBSERVED) result.acceptconn = 0;
                if (measured.state == BH_LISTENER_OBSERVED) result.acceptconn = 1;
            }
            require(close(directory_fd) == 0, "close observer directory");
        }
    }
    struct sockaddr_un name = {0};
    size = sizeof(name);
    int type = 0;
    socklen_t type_size = sizeof(type);
    struct sockaddr_un expected = address(path);
    if (getsockname(6, (struct sockaddr *)&name, &size) == 0 &&
        name.sun_family == AF_UNIX && size >= offsetof(struct sockaddr_un, sun_path) + strlen(path) &&
        memcmp(name.sun_path, expected.sun_path, sizeof(name.sun_path)) == 0 &&
        getsockopt(6, SOL_SOCKET, SO_TYPE, &type, &type_size) == 0 && type == SOCK_STREAM)
        result.path_matches = 1;
    return result;
}

static bool report(struct observation *item)
{
    return transfer(4, item, sizeof(*item), true);
}

static bool valid(struct observation *item, int open_mask, int cloexec_mask)
{
    return item->open_mask == open_mask && item->cloexec_mask == cloexec_mask &&
           item->unexpected_fds == 0 && item->path_matches == 1 && item->acceptconn == 0;
}

static int child(const char *self, const char *path, const char *fault, bool final)
{
    struct observation initial = observe(final ? 3 : 1, path);
    if (!report(&initial) || !valid(&initial, final ? 95 : 127, 0)) return 40;
    if (!final) {
        require(fcntl(5, F_SETFD, FD_CLOEXEC) == 0, "status CLOEXEC");
        struct observation before = observe(2, path);
        if (!report(&before) || !valid(&before, 127, 32)) return 41;
        char gate = 0;
        if (!transfer(4, &gate, 1, false) || gate != 'G') return 42;
        char *args[] = {(char *)self, "--final", (char *)path, (char *)fault, (char *)observation_mode, NULL};
        char *env[] = {"PATH=/usr/bin:/bin", NULL};
        execve(strcmp(fault, "exec") == 0 ? "/__hermes_fixture_missing__" : self, args, env);
        int error = errno;
        (void)transfer(5, &error, sizeof(error), true);
        return 43;
    }
    for (int fd = 3; fd <= 6; fd++) {
        if (fd != 5) require(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, "final CLOEXEC");
    }
    struct observation after = observe(4, path);
    if (!report(&after) || !valid(&after, 95, 88)) return 44;
    if (strcmp(fault, "early-exit") == 0) return 23;
    char bootstrap = 0;
    if (!transfer(3, &bootstrap, 1, false) || bootstrap != 'B') return 45;
    char denied[sizeof(pathname)];
    require(snprintf(denied, sizeof(denied), "%s.denied", path) < (int)sizeof(denied), "denied path");
    int probe = socket(AF_UNIX, SOCK_STREAM, 0);
    require(probe >= 0, "denied socket");
    struct sockaddr_un denied_address = address(denied);
    int result = bind(probe, (struct sockaddr *)&denied_address, sizeof(denied_address));
    int denial = result == 0 ? 0 : errno;
    require(close(probe) == 0, "close probe");
    if (denial != EACCES) return 46;
    if (listen(6, 1) != 0) return 47;
    struct observation ready = {.phase = 5, .denial_errno = denial};
    if (!report(&ready)) return 48;
    struct pollfd pending = {6, POLLIN, 0};
    if (poll(&pending, 1, DEADLINE_MS) != 1) return 49;
    int accepted = accept(6, NULL, NULL);
    if (accepted < 0 || fcntl(accepted, F_SETFD, FD_CLOEXEC) != 0) return 50;
    uid_t uid = (uid_t)-1;
    gid_t gid;
    if (getpeereid(accepted, &uid, &gid) != 0) return 51;
    struct observation peer = {.phase = 6, .uid = uid};
    if (!report(&peer)) return 52;
    require(close(accepted) == 0 && close(6) == 0, "close child socket");
    return 0;
}

static bool wait_owned(int *status)
{
    for (int i = 0; i < 300; i++) {
        pid_t result = waitpid(owned_child, status, WNOHANG);
        if (result == owned_child) { reaped = true; return true; }
        if (result < 0 && errno != EINTR) return false;
        usleep(10000);
    }
    if (kill(owned_child, SIGTERM) != 0) return false;
    for (int i = 0; i < 300; i++) {
        if (waitpid(owned_child, status, WNOHANG) == owned_child) { reaped = true; return false; }
        usleep(10000);
    }
    return false; /* Unknown lifetime retains pathname. */
}

static int launch(const char *self, int source, const char *fault, int channels[3][2])
{
    int socket_fd = high_move(socket(AF_UNIX, SOCK_STREAM, 0));
    struct sockaddr_un name = address(pathname);
    require(bind(socket_fd, (struct sockaddr *)&name, sizeof(name)) == 0, "bind");
    require(fstatat(parent_dir, "socket", &node, AT_SYMLINK_NOFOLLOW) == 0, "record inode");
    recorded = true;
    require(fstat(socket_fd, &socket_metadata) == 0, "socket descriptor stat");
    require(fchmod(parent_dir, 0500) == 0, "protect parent");
    if (strcmp(fault, "prelisten") == 0) require(listen(socket_fd, 1) == 0, "negative prelisten");
    /* First arrange actual original source collisions. All backing sources are high. */
    int originals[4] = {3, 4, 5, source};
    for (int i = 0; i < 3; i++) if (originals[i] == source) originals[i] = 6;
    int backing[4] = {channels[0][1], channels[1][1], channels[2][1], socket_fd};
    for (int i = 0; i < 4; i++) {
        require(dup2(backing[i], originals[i]) == originals[i], "arrange original");
        require(fcntl(originals[i], F_SETFD, FD_CLOEXEC) == 0, "original CLOEXEC");
    }
    for (int i = 0; i < 4; i++) require(close(backing[i]) == 0, "close backing");
    root_source_cloexec = fcntl(originals[3], F_GETFD);
    require(root_source_cloexec == FD_CLOEXEC, "root socket CLOEXEC");
    int saved[4];
    for (int i = 0; i < 4; i++) saved[i] = high_copy(originals[i]);
    posix_spawn_file_actions_t actions;
    require(posix_spawn_file_actions_init(&actions) == 0, "actions init");
    for (int fd = 3; fd < LIMIT; fd++) {
        bool keep = false;
        for (int i = 0; i < 4; i++) if (fd == saved[i]) keep = true;
        if (!keep && fcntl(fd, F_GETFD) >= 0)
            require(posix_spawn_file_actions_addclose(&actions, fd) == 0, "action close original");
    }
    for (int i = 0; i < 4; i++) {
        require(posix_spawn_file_actions_adddup2(&actions, saved[i], i + 3) == 0, "action dup");
        require(posix_spawn_file_actions_addclose(&actions, saved[i]) == 0, "action close temp");
    }
    if (strcmp(fault, "bad-close") == 0)
        require(posix_spawn_file_actions_addclose(&actions, 6) == 0, "negative close");
    if (strcmp(fault, "leak") == 0)
        require(posix_spawn_file_actions_adddup2(&actions, 6, 200) == 0, "negative leak");
    char *args[] = {(char *)self, "--stage0", pathname, (char *)fault, (char *)observation_mode, NULL};
    char *env[] = {"PATH=/usr/bin:/bin", NULL};
    pid_t pid = -1;
    int result = posix_spawn(&pid, strcmp(fault, "spawn") == 0 ? "/__hermes_fixture_missing__" : self,
                             &actions, NULL, args, env);
    require(posix_spawn_file_actions_destroy(&actions) == 0, "actions destroy");
    if (result == 0) { owned_child = pid; reaped = false; }
    for (int i = 0; i < 4; i++) {
        require(close(originals[i]) == 0, "parent close original");
        require(close(saved[i]) == 0, "parent close temp");
    }
    return result;
}

static void print_observation(const struct observation *item)
{
    printf("{\"phase\":%d,\"open_mask\":%d,\"cloexec_mask\":%d,"
           "\"unexpected_fds\":%d,\"acceptconn\":%d,\"path_matches\":%d,\"getsockopt_errno\":%d,\"uid\":%u}",
           item->phase, item->open_mask, item->cloexec_mask, item->unexpected_fds,
           item->acceptconn, item->path_matches, item->option_errno, item->uid);
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    if (argc == 5 && (strcmp(argv[1], "--stage0") == 0 || strcmp(argv[1], "--final") == 0))
    {
        observation_mode = argv[4];
        return child(argv[0], argv[2], argv[3], strcmp(argv[1], "--final") == 0);
    }
    require(argc == 4 && geteuid() != 0, "unprivileged fixture arguments");
    observation_mode = argv[3];
    require(strcmp(observation_mode, "strict") == 0 || strcmp(observation_mode, "libproc-observational") == 0, "observation mode");
    char *end;
    long slot = strtol(argv[1], &end, 10);
    require(*end == '\0' && (slot == 3 || slot == 4 || slot == 5 || slot == 6 || slot == 17 || slot == 129), "source slot");
    const char *fault = argv[2];
    const char *allowed[] = {"none", "spawn", "exec", "early-exit", "bad-close", "leak", "prelisten", "replace"};
    bool known = false;
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) if (strcmp(fault, allowed[i]) == 0) known = true;
    require(known, "fault selector");
    /* Single-threaded fixed inventory: reject any inherited descriptor outside the bound. */
    long maximum = sysconf(_SC_OPEN_MAX);
    require(maximum > 0 && maximum <= 1048576, "descriptor limit");
    for (int fd = 3; fd < maximum; fd++) {
        require(fcntl(fd, F_GETFD) < 0 && errno == EBADF, "unexpected inherited descriptor");
    }
    require(mkdtemp(directory) != NULL, "temporary parent");
    parent_dir = high_move(open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW));
    require(atexit(cleanup) == 0, "cleanup registration");
    require(snprintf(pathname, sizeof(pathname), "%s/socket", directory) < (int)sizeof(pathname), "socket path");
    int channels[3][2];
    channel(channels[0], true); channel(channels[1], true); channel(channels[2], false);
    int spawn_error = launch(argv[0], (int)slot, fault, channels);
    bool parent_closed = true;
    for (int fd = 3; fd < LIMIT; fd++) {
        struct sockaddr_un current = {0}; socklen_t size = sizeof(current);
        if (getsockname(fd, (struct sockaddr *)&current, &size) == 0 &&
            strcmp(current.sun_path, pathname) == 0) parent_closed = false;
    }
    struct observation stages[4], item;
    int count = 0, denial = -1, exit_code = -1, exec_error = 0;
    uid_t client_peer = (uid_t)-1, server_peer = (uid_t)-1;
    bool ready = false;
    if (spawn_error == 0) {
        char gate = 'G', bootstrap = 'B';
        (void)transfer(channels[1][0], &gate, 1, true);
        (void)transfer(channels[0][0], &bootstrap, 1, true);
        while (transfer(channels[1][0], &item, sizeof(item), false)) {
            if (item.phase >= 1 && item.phase <= 4 && count < 4) stages[count++] = item;
            else if (item.phase == 5) {
                ready = true; denial = item.denial_errno;
                int client = socket(AF_UNIX, SOCK_STREAM, 0);
                struct sockaddr_un target = address(pathname); gid_t gid;
                require(connect(client, (struct sockaddr *)&target, sizeof(target)) == 0, "client connect");
                require(getpeereid(client, &client_peer, &gid) == 0, "client peer");
                require(close(client) == 0, "client close");
            } else if (item.phase == 6) server_peer = item.uid;
            else require(false, "unexpected observation");
        }
        int status = 0;
        require(wait_owned(&status), "child deadline/reap");
        exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    }
    ssize_t status_bytes = read(channels[2][0], &exec_error, sizeof(exec_error));
    require(status_bytes >= 0, "exec status read");
    for (int i = 0; i < 3; i++) require(close(channels[i][0]) == 0, "close parent channel");
    bool preserved = false;
    require(fchmod(parent_dir, 0700) == 0, "restore owned parent");
    if (strcmp(fault, "replace") == 0) {
        require(unlinkat(parent_dir, "socket", 0) == 0, "replace owned socket");
        int replacement = openat(parent_dir, "socket", O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
        require(replacement >= 0, "create replacement");
        struct stat replacement_node, after;
        require(fstat(replacement, &replacement_node) == 0 && close(replacement) == 0, "record replacement");
        preserved = !remove_recorded_node(&node) && fstatat(parent_dir, "socket", &after, AT_SYMLINK_NOFOLLOW) == 0 && same_node(&replacement_node, &after);
        require(preserved && remove_recorded_node(&replacement_node), "separate fixture replacement cleanup");
    } else require(remove_recorded_node(&node), "inode checked cleanup");
    recorded = false;
    require(rmdir(directory) == 0, "remove empty parent");
    printf("{\"path_stat\":{\"dev\":%llu,\"ino\":%llu,\"mode\":%u},"
           "\"fd_stat\":{\"dev\":%llu,\"ino\":%llu,\"mode\":%u},"
           "\"root_source_cloexec\":%d,\"child_pid\":%d,",
           (unsigned long long)node.st_dev, (unsigned long long)node.st_ino, (unsigned)node.st_mode,
           (unsigned long long)socket_metadata.st_dev, (unsigned long long)socket_metadata.st_ino,
           (unsigned)socket_metadata.st_mode, root_source_cloexec, owned_child);
    printf("\"candidate_only\":true,\"mode\":\"%s\",\"case\":\"%s\",\"source_fd\":%ld,\"directory\":\"%s\",\"expected_uid\":%u,"
           "\"parent_socket_closed\":%s,\"child_reaped\":%s,\"cleanup\":\"removed\","
           "\"ready\":%s,\"bind_denial_errno\":%d,\"client_peer_uid\":%u,\"server_peer_uid\":%u,"
           "\"spawn_error\":%d,\"exit_code\":%d,\"status_bytes\":%zd,\"exec_error\":%d,"
           "\"replacement_preserved\":%s,\"cross_uid_root_bind\":\"UNAVAILABLE\","
           "\"root_listen_credential_negative\":\"UNAVAILABLE\",\"stages\":[",
           observation_mode, fault, slot, directory, geteuid(), parent_closed ? "true" : "false", reaped ? "true" : "false",
           ready ? "true" : "false", denial, client_peer, server_peer, spawn_error, exit_code,
           status_bytes, exec_error, preserved ? "true" : "false");
    for (int i = 0; i < count; i++) { if (i) printf(","); print_observation(&stages[i]); }
    printf("]}\n");
    return 0;
}
