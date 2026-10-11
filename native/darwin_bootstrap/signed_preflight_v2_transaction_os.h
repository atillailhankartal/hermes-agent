#ifndef BH_TX_OS_H
#define BH_TX_OS_H
#include <stddef.h>
#include <sys/stat.h>
/* Private link-time seam. Exactly one adapter linked per binary.
 * No callbacks or fault controls in the public ABI. ACL observation is not
 * writer exclusion; a prepared result remains untrusted. */
int bh_tx_os_dup_cloexec(int fd);
int bh_tx_os_openat(int parent, const char *name, int flags);
int bh_tx_os_fstat(int fd, struct stat *out);
int bh_tx_os_fstatat(int parent, const char *name, struct stat *out, int flags);
int bh_tx_os_exact_name(int independent_enumeration_fd, const char *name);
void *bh_tx_os_acl_get(int fd);
int bh_tx_os_acl_empty(void *acl);
int bh_tx_os_acl_free(void *acl);
int bh_tx_os_flock(int fd, int operation);
int bh_tx_os_close(int fd);
void *bh_tx_os_alloc(size_t n);
void bh_tx_os_free(void *p);
#endif
