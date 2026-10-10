/* Independent public-libproc candidate probe, not an approved contract change. */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { SUBJECT_FD = 6 };
_Static_assert(SUBJECT_FD != PROC_PIDFDSOCKETINFO, "FD must differ from flavor");
_Static_assert(sizeof(struct socket_fdinfo) == 792, "Qualified candidate ABI");

static int state(int fd, int expected, const char *phase)
{
    struct socket_fdinfo info = {0};
    struct socket_fdinfo swapped = {0};
    int flags = fcntl(fd, F_GETFL);
    int value = -1;
    socklen_t length = sizeof(value);
    errno = 0;
    int option_result = getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &value, &length);
    int option_error = option_result == 0 ? 0 : errno;
    errno = 0;
    int bytes = proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info));
    int error = bytes > 0 ? 0 : errno;
    int observed = bytes == sizeof(info) ? !!(info.psi.soi_options & SO_ACCEPTCONN) : -1;
    /* Deliberate mutation: the kernel helper's order is NOT the public API. */
    int swapped_bytes = proc_pidfdinfo(getpid(), PROC_PIDFDSOCKETINFO, fd,
                                       &swapped, sizeof(swapped));
    int swapped_rejected = swapped_bytes != sizeof(swapped);
    int swapped_observed = swapped_rejected ? -1 : !!(swapped.psi.soi_options & SO_ACCEPTCONN);
    int flags_unchanged = flags >= 0 && fcntl(fd, F_GETFL) == flags;
    printf("{\"phase\":\"%s\",\"fd\":%d,\"flavor\":%d,"
           "\"swapped_bytes\":%d,\"swapped_rejected\":%s,\"swapped_acceptconn\":%d,"
           "\"flags_unchanged\":%s,\"expected\":%d,\"getsockopt_result\":%d,\"getsockopt_errno\":%d,"
           "\"proc_bytes\":%d,\"expected_bytes\":%zu,\"proc_errno\":%d,"
           "\"family\":%d,\"type\":%d,\"kind\":%d,\"acceptconn\":%d}",
           phase, fd, PROC_PIDFDSOCKETINFO, swapped_bytes, swapped_rejected ? "true" : "false",
           swapped_observed, flags_unchanged ? "true" : "false",
           expected, option_result, option_error, bytes, sizeof(info), error,
           info.psi.soi_family, info.psi.soi_type, info.psi.soi_kind, observed);
    return fd == SUBJECT_FD && swapped_rejected && flags_unchanged &&
           bytes == sizeof(info) && info.psi.soi_family == AF_UNIX &&
           info.psi.soi_type == SOCK_STREAM && info.psi.soi_kind == SOCKINFO_UN && observed == expected;
}

int main(void)
{
    char directory[] = "/tmp/hermes-state-XXXXXX";
    errno = 0;
    /* Do not overwrite a caller-owned FD: the subprocess must start with 6 free. */
    if (geteuid() == 0 || fcntl(SUBJECT_FD, F_GETFD) != -1 || errno != EBADF ||
        !mkdtemp(directory)) return 1;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    address.sun_len = sizeof(address);
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s/socket", directory) >= (int)sizeof(address.sun_path)) return 1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 1;
    if (fd != SUBJECT_FD) {
        if (dup2(fd, SUBJECT_FD) != SUBJECT_FD || close(fd) != 0) return 1;
        fd = SUBJECT_FD;
    }
    int parent = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    struct stat node;
    if (parent < 0 || fstatat(parent, "socket", &node, AT_SYMLINK_NOFOLLOW) != 0) return 1;
    printf("{\"candidate_only\":true,\"directory\":\"%s\",\"observations\":[", directory);
    int bound = state(fd, 0, "bound");
    int listening = listen(fd, 1);
    printf(",");
    int listener = state(fd, 1, "empty_listener");
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    int connected = client >= 0 && connect(client, (struct sockaddr *)&address, sizeof(address)) == 0;
    printf(",");
    int queued = state(fd, 1, "queued_listener");
    int client_closed = client >= 0 ? close(client) : -1;
    int closed = close(fd);
    struct stat current;
    if (fstatat(parent, "socket", &current, AT_SYMLINK_NOFOLLOW) != 0 ||
        current.st_dev != node.st_dev || current.st_ino != node.st_ino ||
        !S_ISSOCK(current.st_mode)) return 1;
    int removed = unlinkat(parent, "socket", 0);
    int parent_closed = close(parent), parent_removed = rmdir(directory);
    int cleanup = closed == 0 && client_closed == 0 && removed == 0 && parent_closed == 0 && parent_removed == 0;
    printf("],\"cleanup\":%s}\n", cleanup ? "true" : "false");
    return bound && listener && queued && connected && listening == 0 && cleanup ? 0 : 1;
}
