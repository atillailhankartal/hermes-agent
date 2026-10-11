#ifndef BH_PATH_OBSERVER_OS_V1_H
#define BH_PATH_OBSERVER_OS_V1_H

#include <sys/acl.h>
#include <sys/stat.h>

/* Private link-time syscall boundary. Exactly one adapter is linked per image. */
int bh_po_os_dup_cloexec(int fd);
int bh_po_os_fstat(int fd, struct stat *out);
int bh_po_os_fstatat(int parent, const char *name, struct stat *out, int flags);
int bh_po_os_openat(int parent, const char *name, int flags);
acl_t bh_po_os_acl_get(int fd, acl_type_t type);
int bh_po_os_acl_valid(acl_t acl);
int bh_po_os_acl_first(acl_t acl, int entry_id, acl_entry_t *out);
int bh_po_os_acl_free(void *acl);
int bh_po_os_close(int fd);

#endif
