#include "bundle_reader_os.h"
#include "bundle_reader_darwin_name.h"
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
int bh_br_exact_name(int fd, const char *name) { return bh_br_darwin_exact_name(fd, name); }
int bh_br_dup(int fd) { return fcntl(fd, F_DUPFD_CLOEXEC, 0); }
int bh_br_stat(int fd, struct stat *s) { return fstat(fd, s); }
int bh_br_atstat(int fd, const char *name, struct stat *s, int flags) { return fstatat(fd, name, s, flags); }
int bh_br_open(int fd, const char *name, int flags) { return openat(fd, name, flags); }
ssize_t bh_br_pread(int fd, void *bytes, size_t count, off_t offset) { return pread(fd, bytes, count, offset); }
acl_t bh_br_acl_get(int fd) { return acl_get_fd_np(fd, ACL_TYPE_EXTENDED); }
int bh_br_acl_valid(acl_t acl) { return acl_valid(acl); }
int bh_br_acl_first(acl_t acl, acl_entry_t *entry) { return acl_get_entry(acl, ACL_FIRST_ENTRY, entry); }
int bh_br_acl_free(acl_t acl) { return acl_free(acl); }
int bh_br_close(int fd) { return close(fd); }
void *bh_br_alloc(size_t count) { return malloc(count); }
void bh_br_free(void *bytes) { free(bytes); }
