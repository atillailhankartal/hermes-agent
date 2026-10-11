#include "signed_preflight_v2_transaction_os.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/file.h>
#include <unistd.h>

int bh_tx_os_dup_cloexec(int fd) { return fcntl(fd,F_DUPFD_CLOEXEC,0); }
int bh_tx_os_openat(int parent, const char *name, int flags) { return openat(parent,name,flags); }
int bh_tx_os_fstat(int fd, struct stat *out) { return fstat(fd,out); }
int bh_tx_os_fstatat(int parent, const char *name, struct stat *out, int flags) { return fstatat(parent,name,out,flags); }
/* ATTR_CMN_NAME observes actual spelling even on a case-insensitive volume.
 * The independent directory description never changes caller enumeration state. */
int bh_tx_os_exact_name(int fd, const char *name) {
    struct attrlist request = {0};
    struct {
        uint32_t length;
        attribute_set_t returned;
        attrreference_t name;
        unsigned char storage[1024];
    } value = {0};
    request.bitmapcount = ATTR_BIT_MAP_COUNT;
    request.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME;
    if (getattrlistat(fd,name,&request,&value,sizeof(value),FSOPT_NOFOLLOW)) return -1;
    size_t base = (size_t)((unsigned char *)&value.name - (unsigned char *)&value);
    if (value.length < base+sizeof(value.name) || value.length > sizeof(value) ||
        !(value.returned.commonattr & ATTR_CMN_NAME) || value.name.attr_dataoffset < (int32_t)sizeof(value.name)) {
        errno = EIO; return -1;
    }
    size_t start = base+(uint32_t)value.name.attr_dataoffset, count = value.name.attr_length;
    if (start > value.length || count > value.length-start || !count) { errno = EIO; return -1; }
    return count == strlen(name)+1 && !memcmp((unsigned char *)&value+start,name,count);
}
void *bh_tx_os_acl_get(int fd) { return acl_get_fd_np(fd,ACL_TYPE_EXTENDED); }
int bh_tx_os_acl_empty(void *value) {
    acl_t acl = value;
    acl_entry_t entry = NULL;
    if (acl_valid(acl)) return -1;
    errno = 0;
    int found = acl_get_entry(acl,ACL_FIRST_ENTRY,&entry);
    if (found == 0) return 0;
    return found == -1 && errno == EINVAL && entry == NULL ? 1 : -1;
}
int bh_tx_os_acl_free(void *acl) { return acl_free(acl); }
int bh_tx_os_flock(int fd, int operation) { return flock(fd,operation); }
int bh_tx_os_close(int fd) { return close(fd); }
void *bh_tx_os_alloc(size_t n) { return malloc(n); }
void bh_tx_os_free(void *p) { free(p); }
