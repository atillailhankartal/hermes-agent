#ifndef BH_BUNDLE_READER_OS_H
#define BH_BUNDLE_READER_OS_H
#include <sys/acl.h>
#include <sys/stat.h>
#include <stddef.h>
/* Private link-time seam: exactly one OS adapter per image, no public callback. */
int bh_br_exact_name(int fd, const char *name);
int bh_br_dup(int fd);
int bh_br_stat(int fd, struct stat *out);
int bh_br_atstat(int fd, const char *name, struct stat *out, int flags);
int bh_br_open(int fd, const char *name, int flags);
ssize_t bh_br_pread(int fd, void *bytes, size_t count, off_t offset);
acl_t bh_br_acl_get(int fd);
int bh_br_acl_valid(acl_t acl);
int bh_br_acl_first(acl_t acl, acl_entry_t *entry);
int bh_br_acl_free(acl_t acl);
int bh_br_close(int fd);
void *bh_br_alloc(size_t count);
void bh_br_free(void *bytes);
#endif
