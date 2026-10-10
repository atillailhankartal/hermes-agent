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

static int state(int fd, int expected)
{
    struct socket_fdinfo info = {0};
    int value = -1;
    socklen_t length = sizeof(value);
    errno = 0;
    int option_result = getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &value, &length);
    int option_error = option_result == 0 ? 0 : errno;
    errno = 0;
    int bytes = proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info));
    int error = bytes > 0 ? 0 : errno;
    int observed = bytes == sizeof(info) ? !!(info.psi.soi_options & SO_ACCEPTCONN) : -1;
    printf("{\"expected\":%d,\"getsockopt_result\":%d,\"getsockopt_errno\":%d,"
           "\"proc_bytes\":%d,\"expected_bytes\":%zu,\"proc_errno\":%d,"
           "\"family\":%d,\"type\":%d,\"kind\":%d,\"acceptconn\":%d}",
           expected, option_result, option_error, bytes, sizeof(info), error,
           info.psi.soi_family, info.psi.soi_type, info.psi.soi_kind, observed);
    return bytes == sizeof(info) && info.psi.soi_family == AF_UNIX &&
           info.psi.soi_type == SOCK_STREAM && info.psi.soi_kind == SOCKINFO_UN && observed == expected;
}

int main(void)
{
    char directory[] = "/tmp/hermes-state-XXXXXX";
    if (geteuid() == 0 || !mkdtemp(directory)) return 1;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    address.sun_len = sizeof(address);
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s/socket", directory) >= (int)sizeof(address.sun_path)) return 1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 1;
    int parent = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    struct stat node;
    if (parent < 0 || fstatat(parent, "socket", &node, AT_SYMLINK_NOFOLLOW) != 0) return 1;
    printf("{\"candidate_only\":true,\"observations\":[");
    int bound = state(fd, 0);
    int listening = listen(fd, 1);
    printf(",");
    int listener = state(fd, 1);
    printf("]}\n");
    int closed = close(fd);
    struct stat current;
    if (fstatat(parent, "socket", &current, AT_SYMLINK_NOFOLLOW) != 0 ||
        current.st_dev != node.st_dev || current.st_ino != node.st_ino ||
        !S_ISSOCK(current.st_mode)) return 1;
    int removed = unlinkat(parent, "socket", 0);
    int parent_closed = close(parent), parent_removed = rmdir(directory);
    return bound && listener && listening == 0 && closed == 0 && removed == 0 && parent_closed == 0 && parent_removed == 0 ? 0 : 1;
}
