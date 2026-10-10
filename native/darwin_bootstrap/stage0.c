#include "abi_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

enum bh_a2a_result bh_a2a_stage0_validate(void) {
    const int allowed[] = {0, 1, 2, 3, 4, 5, 6};
    struct bh_a2a_inventory inventory;
    struct stat socket_info;
    struct stat channel_info;
    struct sockaddr_un address;
    socklen_t length = (socklen_t)sizeof(address);
    int type = -1;
    socklen_t type_length = (socklen_t)sizeof(type);
    int flags;
    if (bh_a2a_inventory_check(allowed, sizeof(allowed) / sizeof(allowed[0]),
                               &inventory) != BH_A2A_OK || inventory.count != 7 ||
        fstat(3, &channel_info) != 0 || !S_ISSOCK(channel_info.st_mode) ||
        fstat(4, &channel_info) != 0 || !S_ISSOCK(channel_info.st_mode) ||
        fstat(5, &channel_info) != 0 || !S_ISFIFO(channel_info.st_mode) ||
        fstat(BH_A2A_FD6, &socket_info) != 0 || !S_ISSOCK(socket_info.st_mode) ||
        getsockopt(BH_A2A_FD6, SOL_SOCKET, SO_TYPE, &type, &type_length) != 0 ||
        type_length != sizeof(type) || type != SOCK_STREAM ||
        getsockname(BH_A2A_FD6, (struct sockaddr *)&address, &length) != 0 ||
        address.sun_family != AF_UNIX ||
        length <= offsetof(struct sockaddr_un, sun_path) ||
        address.sun_path[0] == '\0') return BH_A2A_PAUSED;
    flags = fcntl(5, F_GETFD);
    if (flags < 0 || fcntl(5, F_SETFD, flags | FD_CLOEXEC) < 0 ||
        (fcntl(5, F_GETFD) & FD_CLOEXEC) == 0) return BH_A2A_PAUSED;
    return BH_A2A_OK;
}

enum bh_a2a_result bh_a2a_stage0_drop(uid_t uid, gid_t gid) {
    if (uid == 0 || gid == 0 || geteuid() != 0 ||
        setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0 ||
        getuid() != uid || geteuid() != uid ||
        getgid() != gid || getegid() != gid) return BH_A2A_PAUSED;
    errno = 0;
    if (seteuid(0) == 0 || errno != EPERM) return BH_A2A_PAUSED;
    return BH_A2A_OK;
}
