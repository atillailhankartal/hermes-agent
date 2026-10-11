#include "path_observer_os_v1.h"

#include <fcntl.h>
#include <unistd.h>

int bh_po_os_dup_cloexec(int fd) { return fcntl(fd, F_DUPFD_CLOEXEC, 0); }
int bh_po_os_fstat(int fd, struct stat *out) { return fstat(fd, out); }
int bh_po_os_fstatat(int parent, const char *name, struct stat *out, int flags) {
    return fstatat(parent, name, out, flags);
}
int bh_po_os_openat(int parent, const char *name, int flags) {
    return openat(parent, name, flags);
}
acl_t bh_po_os_acl_get(int fd, acl_type_t type) { return acl_get_fd_np(fd, type); }
int bh_po_os_acl_valid(acl_t acl) { return acl_valid(acl); }
int bh_po_os_acl_first(acl_t acl, int entry_id, acl_entry_t *out) {
    return acl_get_entry(acl, entry_id, out);
}
int bh_po_os_acl_free(void *acl) { return acl_free(acl); }
int bh_po_os_close(int fd) { return close(fd); }
