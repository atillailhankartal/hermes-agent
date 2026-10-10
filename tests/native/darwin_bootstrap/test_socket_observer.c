/* Include the implementation to test its PRIVATE pure validator. No syscall overrides. */
#include "socket_observer.c"
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned checks, failures;
static void check(bool pass, const char *name)
{
    checks++;
    if (!pass) { failures++; fprintf(stderr, "FAIL %s\n", name); }
}
static void require(bool pass, const char *name)
{
    if (!pass) { perror(name); exit(2); }
}
static void install(int fd)
{
    require(fd >= 0 && dup2(fd, 6) == 6, "install owned FD6");
    if (fd != 6) require(close(fd) == 0, "close source");
}
static void state(const struct bh_socket_expectation *e, enum bh_socket_state expected, const char *name)
{
    int flags = fcntl(6, F_GETFL), slot = fcntl(6, F_GETFD);
    struct bh_socket_observation result = bh_darwin_observe_fd6(e);
    check(result.state == expected, name);
    check(flags == fcntl(6, F_GETFL) && slot == fcntl(6, F_GETFD), "unchanged flags");
}
static void pure_matrix(const struct bh_socket_expectation *e)
{
    struct socket_sample good[2] = {0};
    for (unsigned k = 0; k < 2; k++) {
        good[k].before = read_direct(e);
        good[k].bytes = query_socket_info(&good[k].record);
        good[k].after = read_direct(e);
    }
    check(validate_samples(good, e).state == BH_BOUND_OBSERVED, "pure bound seed");
    /* Fully initialized native records: scalar size is independently adversarial. */
    int sizes[] = {0, -1, 1, 791, 793, 2147483647};
    for (unsigned k = 0; k < 2; k++) {
        for (size_t n = 0; n < sizeof(sizes) / sizeof(sizes[0]); n++) {
            struct socket_sample bad[2]; memcpy(bad, good, sizeof(bad));
            bad[k].bytes = sizes[n];
            check(validate_samples(bad, e).state == BH_UNKNOWN, "invalid returned size");
        }
    }
#define REJECT(change) do { struct socket_sample bad[2]; memcpy(bad, good, sizeof(bad)); \
    change; check(validate_samples(bad, e).state == BH_UNKNOWN, #change); } while (0)
    REJECT(bad[0].record.psi.soi_family = AF_INET);
    REJECT(bad[1].record.psi.soi_type = SOCK_DGRAM);
    REJECT(bad[0].record.psi.soi_kind = SOCKINFO_TCP);
    REJECT(bad[1].record.psi.soi_protocol = 1);
    REJECT(bad[0].record.psi.soi_so = 0);
    REJECT(bad[1].record.psi.soi_pcb = 0);
    REJECT(bad[1].record.psi.soi_so++);
    REJECT(bad[1].record.psi.soi_pcb++);
    REJECT(bad[1].record.psi.soi_options ^= SO_ACCEPTCONN);
    REJECT(bad[0].record.psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_path[0] = '?');
    REJECT(bad[1].record.psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_len = 255);
    REJECT(bad[1].record.psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_len = 0);
    REJECT(bad[0].record.psi.soi_state |= SOI_S_ISCONNECTED);
    REJECT(bad[0].record.psi.soi_proto.pri_un.unsi_conn_so = 1);
    REJECT(bad[1].record.psi.soi_proto.pri_un.unsi_conn_pcb = 1);
    REJECT(bad[0].before.complete = false);
    REJECT(bad[1].after.complete = false);
    REJECT(bad[1].after.type = SOCK_DGRAM);
    REJECT(bad[1].before.address.sun_family = AF_INET);
    REJECT(bad[0].after.address_length = 255);
    REJECT(bad[1].after.address.sun_path[0] = '?');
    REJECT(bad[1].after.descriptor.st_ino++);
    REJECT(bad[0].after.descriptor.st_dev++);
    REJECT(bad[1].after.descriptor.st_mode = S_IFREG);
    REJECT(bad[0].after.directory.st_ino++);
    REJECT(bad[1].before.directory.st_dev++);
    REJECT(bad[1].after.directory.st_mode = S_IFREG);
    REJECT(bad[1].after.node.st_ino++);
    REJECT(bad[1].after.node.st_dev++);
    REJECT(bad[1].after.node.st_mode ^= 0400);
    REJECT(bad[1].after.node.st_uid++);
    REJECT(bad[1].after.node.st_gid++);
    REJECT(bad[1].after.descriptor_flags ^= FD_CLOEXEC);
    REJECT(bad[1].after.status_flags ^= O_NONBLOCK);
#undef REJECT
    good[0].record.psi.soi_qlen++;
    good[1].record.psi.soi_rcv.sbi_cc++;
    check(validate_samples(good, e).state == BH_BOUND_OBSERVED, "counters are not identity");
}
int main(int argc, char **argv)
{
    require(geteuid() != 0 && fcntl(6, F_GETFD) < 0 && errno == EBADF, "unprivileged unused FD6");
    char directory[] = "/tmp/hermes-observer-XXXXXX";
    require(mkdtemp(directory) != NULL, "owned directory");
    int dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    require(dir >= 0 && dir != 6, "retained directory");
    struct sockaddr_un address = {.sun_family = AF_UNIX, .sun_len = sizeof(address)};
    require(snprintf(address.sun_path, sizeof(address.sun_path), "%s/socket", directory) < (int)sizeof(address.sun_path), "address");
    install(socket(AF_UNIX, SOCK_STREAM, 0));
    require(bind(6, (struct sockaddr *)&address, sizeof(address)) == 0, "bind");
    struct bh_socket_expectation e = {.directory_fd = dir, .basename = "socket",
        .pathname = address.sun_path, .pathname_length = strlen(address.sun_path)};
    require(fstatat(dir, "socket", &e.node, AT_SYMLINK_NOFOLLOW) == 0, "node");
    if (argc == 2 && !strcmp(argv[1], "runtime-negative")) {
        state(&e, BH_UNKNOWN, "runtime mismatch");
        check(bh_darwin_observe_fd6(&e).reason == BH_RUNTIME, "runtime reason");
    } else {
        state(&e, BH_BOUND_OBSERVED, "actual bound FD6");
        pure_matrix(&e);
        struct bh_socket_expectation bad = e; bad.directory_fd = -1;
        state(&bad, BH_UNKNOWN, "missing directory");
        bad = e; bad.node.st_ino++; state(&bad, BH_UNKNOWN, "wrong expected inode");
        bad = e; bad.basename = "../socket"; state(&bad, BH_UNKNOWN, "traversal");
        bad = e; bad.pathname = "/wrong/socket"; bad.pathname_length = strlen(bad.pathname);
        state(&bad, BH_UNKNOWN, "wrong pathname");
        state(NULL, BH_UNKNOWN, "null expectation");
        bad = e; bad.directory_fd = 999999; state(&bad, BH_UNKNOWN, "closed directory");
        char alias[sizeof(address.sun_path)];
        require(snprintf(alias, sizeof(alias), "%s/alias", directory) < (int)sizeof(alias), "alias path");
        bad = e; bad.basename = "alias"; bad.pathname = alias; bad.pathname_length = strlen(alias);
        state(&bad, BH_UNKNOWN, "missing metadata");
        require(symlinkat("socket", dir, "alias") == 0, "owned symlink");
        struct stat link; require(fstatat(dir, "alias", &link, AT_SYMLINK_NOFOLLOW) == 0, "record symlink");
        state(&bad, BH_UNKNOWN, "no follow symlink");
        struct stat link_after;
        require(fstatat(dir, "alias", &link_after, AT_SYMLINK_NOFOLLOW) == 0 &&
                same_node(&link, &link_after) && unlinkat(dir, "alias", 0) == 0, "remove owned symlink");
        require(fchmod(dir, 0000) == 0, "deny directory lookup");
        state(&e, BH_UNKNOWN, "denied metadata");
        require(fchmod(dir, 0700) == 0, "restore directory");
        require(listen(6, 1) == 0, "listen");
        state(&e, BH_LISTENER_OBSERVED, "empty listener");
        int client = socket(AF_UNIX, SOCK_STREAM, 0);
        require(client >= 0 && connect(client, (struct sockaddr *)&address, sizeof(address)) == 0, "queue client");
        state(&e, BH_LISTENER_OBSERVED, "queued listener");
        struct pollfd pending = {6, POLLIN, 0};
        check(poll(&pending, 1, 1000) == 1 && (pending.revents & POLLIN), "queue was not consumed");
        require(close(client) == 0 && close(6) == 0, "close listener");
        state(&e, BH_UNKNOWN, "closed FD6");
        install(open("/dev/null", O_RDONLY)); state(&e, BH_UNKNOWN, "non socket FD6");
        require(close(6) == 0, "close non socket");
        install(openat(dir, "file", O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0600));
        struct stat file; require(fstat(6, &file) == 0, "record file");
        state(&e, BH_UNKNOWN, "regular file FD6");
        require(close(6) == 0, "close file");
        struct stat actual; require(fstatat(dir, "file", &actual, AT_SYMLINK_NOFOLLOW) == 0 && same_node(&file, &actual) && unlinkat(dir, "file", 0) == 0, "remove file");
        install(socket(AF_UNIX, SOCK_DGRAM, 0)); state(&e, BH_UNKNOWN, "datagram FD6");
        require(close(6) == 0, "close datagram");
        install(socket(AF_UNIX, SOCK_STREAM, 0)); state(&e, BH_UNKNOWN, "unbound FD6");
        require(close(6) == 0, "close unbound");
        int pair[2]; require(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "connected pair");
        install(pair[0]); state(&e, BH_UNKNOWN, "connected FD6");
        require(close(pair[1]) == 0, "close peer");
    }
    require(close(6) == 0, "close subject");
    struct stat actual;
    require(fstatat(dir, "socket", &actual, AT_SYMLINK_NOFOLLOW) == 0 && same_node(&e.node, &actual) &&
            unlinkat(dir, "socket", 0) == 0 && rmdir(directory) == 0 && close(dir) == 0, "owned cleanup");
    check(access(directory, F_OK) == -1 && errno == ENOENT, "cleanup readback");
    printf("{\"checks\":%u,\"failures\":%u,\"cleanup\":true,\"directory\":\"%s\"}\n", checks, failures, directory);
    return failures ? 1 : 0;
}
