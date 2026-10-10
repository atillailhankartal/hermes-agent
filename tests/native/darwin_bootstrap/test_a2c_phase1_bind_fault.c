/* Compile-time fault solely at first post-bind fstatat; real bind/FDs remain. */
#include <errno.h>
#include <sys/stat.h>
static int first_readback(int fd, const char *path, struct stat *info, int flags) {
    static unsigned int calls;
    if (++calls == 2) { errno = EIO; return -1; }
    return fstatat(fd, path, info, flags);
}
#define fstatat first_readback
#include "../../../native/darwin_bootstrap/socket_lineage.c"
#undef fstatat
