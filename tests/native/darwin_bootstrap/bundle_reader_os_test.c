#include "bundle_reader_os_test.h"
#include "bundle_reader_os.h"
#include "bundle_reader_darwin_name.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static const char *const names[3] = {"policy.v2.bin", "policy.v2.sig", "release.v2.bin"};
struct br_test_state br_test;
static int slot(int fd) {
    for (int i = 0; i < 4; ++i) if (br_test.fds[i] == fd) return i;
    return -1;
}
void br_test_reset(int scenario, int variant, int fd, const int writers[3]) {
    memset(&br_test, 0, sizeof(br_test));
    br_test.scenario = scenario; br_test.variant = variant;
    br_test.borrowed = fd; br_test.ambiguous = -1;
    for (int i = 0; i < 4; ++i) br_test.fds[i] = -1;
    for (int i = 0; i < 3; ++i) br_test.writer[i] = writers[i];
}
int bh_br_dup(int fd) {
    ++br_test.calls;
    int r = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (r >= 0) { br_test.fds[0] = r; ++br_test.owned; }
    return r;
}
int bh_br_stat(int fd, struct stat *out) {
    ++br_test.calls;
    int s = slot(fd), c = br_test.scenario;
    if (c == 58 && s > 0) { errno = EIO; return -1; }
    int r = fstat(fd, out);
    if (r != 0) return r;
    if (s == 0 && c == 54) ++out->st_gid;
    if (s == 0 && c == 56) out->st_mode |= S_ISUID;
    if (s == 0 && c == 44 && br_test.reads >= 6) out->st_ctimespec.tv_nsec ^= 1;
    if (s > 0 && c >= 39 && c <= 41) *out = br_test.original[s - 1];
    return 0;
}
int bh_br_atstat(int fd, const char *name, struct stat *out, int flags) {
    ++br_test.calls;
    if (flags != AT_SYMLINK_NOFOLLOW) br_test.failure = 1;
    int i;
    for (i = 0; i < 3 && strcmp(name, names[i]); ++i) {}
    if (i == 3) { br_test.failure = 1; errno = EINVAL; return -1; }
    if (br_test.scenario == 59 && br_test.reads >= 4) { errno = EIO; return -1; }
    int r = fstatat(fd, name, out, flags);
    if (r != 0) return r;
    if (br_test.scenario == 25) ++out->st_uid;
    if (br_test.scenario == 26) ++out->st_gid;
    if (br_test.scenario >= 39 && br_test.scenario <= 41) {
        if (br_test.reads < 3) br_test.original[i] = *out;
        else *out = br_test.original[i];
    }
    return 0;
}
int bh_br_open(int fd, const char *name, int flags) {
    ++br_test.calls;
    int n = br_test.opens++, c = br_test.scenario;
    if (n >= 3 || strcmp(name, names[n]) || fd != br_test.fds[0]) {
        br_test.failure = 1; errno = EINVAL; return -1;
    }
    br_test.flags[n] = flags;
    if ((flags & (O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK)) != (O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK)
        || (flags & O_ACCMODE) != O_RDONLY) br_test.failure = 1;
    if (c == 46 && n == 1) { errno = EIO; return -1; }
    if (c == 53 && n == 0) {
        if (fchmod(fd, 0700) || unlinkat(fd, name, 0) || mkfifoat(fd, name, 0400) ||
            fchmod(fd, 0500)) br_test.failure = 1;
        br_test.mutation = 1;
    }
    if (c == 62 && n == 0) {
        if (ftruncate(br_test.writer[0], 65585)) br_test.failure = 1;
        br_test.mutation = 1;
    }
    int r = openat(fd, name, flags);
    if (r >= 0) { br_test.fds[n + 1] = r; ++br_test.owned; }
    return r;
}
static void replace_path(int symlinked) {
    int d = br_test.fds[0];
    if (fchmod(d, 0700) || unlinkat(d, names[0], 0)) br_test.failure = 1;
    if (symlinked) {
        if (symlinkat("policy.v2.sig", d, names[0])) br_test.failure = 1;
    } else {
        int f = openat(d, names[0], O_CREAT|O_EXCL|O_RDWR, 0600);
        unsigned char bytes[391];
        if (f < 0 || pread(br_test.writer[0], bytes, sizeof(bytes), 0) != sizeof(bytes) ||
            write(f, bytes, sizeof(bytes)) != sizeof(bytes) || fchmod(f, 0400))
            br_test.failure = 1;
        if (f >= 0) close(f);
    }
    if (fchmod(d, 0500)) br_test.failure = 1;
    br_test.mutation = 1;
}
ssize_t bh_br_pread(int fd, void *bytes, size_t count, off_t offset) {
    ++br_test.calls; ++br_test.reads;
    int s = slot(fd), c = br_test.scenario;
    if (s < 1 || s > 3) { br_test.failure = 1; errno = EIO; return -1; }
    ++br_test.read_counts[s - 1];
    if (c == 37) return 0;
    if (c == 38) { errno = EIO; return -1; }
    if (br_test.reads == 4) {
        if (c >= 39 && c <= 41) {
            unsigned char byte;
            int w = br_test.writer[c - 39];
            if (pread(w, &byte, 1, 0) != 1) br_test.failure = 1;
            byte ^= 1;
            if (pwrite(w, &byte, 1, 0) != 1) br_test.failure = 1;
            br_test.mutation = 1;
        }
        if (c == 42 || c == 43) replace_path(c == 43);
    }
    return pread(fd, bytes, count, offset);
}
acl_t bh_br_acl_get(int fd) {
    ++br_test.calls; ++br_test.acl_gets;
    int c = br_test.scenario;
    if (c == 28) {
        errno = 0;
        acl_t a = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
        fprintf(stderr, "REAL_ACL fd_slot=%d nonnull=%d errno=%d\n", slot(fd), a != NULL, errno);
        if (a) ++br_test.acl_live;
        return a;
    }
    if (c == 29 && slot(fd) > 0 && br_test.variant < 2) {
        errno = br_test.variant == 0 ? ENOENT : EIO; return NULL;
    }
    ++br_test.acl_live;
    return (acl_t)(uintptr_t)(slot(fd) + 1);
}
int bh_br_acl_valid(acl_t a) {
    ++br_test.calls;
    if (br_test.scenario == 28) return acl_valid(a);
    if (br_test.scenario == 29 && br_test.variant == 2 && (uintptr_t)a > 1) {
        errno = EINVAL; return -1;
    }
    return 0;
}
int bh_br_acl_first(acl_t a, acl_entry_t *entry) {
    ++br_test.calls;
    int c = br_test.scenario, leaf = (uintptr_t)a > 1;
    if (c == 28) return acl_get_entry(a, ACL_FIRST_ENTRY, entry);
    if ((c == 27 && leaf) || (c == 57 && !leaf) ||
        (c == 45 && leaf && br_test.reads >= 4)) {
        *entry = (acl_entry_t)(uintptr_t)1; return 0;
    }
    errno = EINVAL; return -1;
}
int bh_br_acl_free(acl_t a) {
    ++br_test.calls; ++br_test.acl_frees; --br_test.acl_live;
    if (br_test.scenario == 28) return acl_free(a);
    if (br_test.scenario == 30 && (uintptr_t)a > 1) { errno = EIO; return -1; }
    return 0;
}
int bh_br_close(int fd) {
    ++br_test.calls; ++br_test.closes;
    int s = slot(fd);
    if (s < 0) { br_test.failure = 1; errno = EBADF; return -1; }
    br_test.fds[s] = -1; --br_test.owned;
    if (br_test.scenario == 48 && s > 0 && br_test.ambiguous < 0) {
        br_test.ambiguous = fd; errno = EIO; return -1;
    }
    return close(fd);
}
void *bh_br_alloc(size_t size) {
    ++br_test.allocs;
    if (br_test.scenario == 47) return NULL;
    void *p = malloc(size);
    if (p) ++br_test.live;
    return p;
}
void bh_br_free(void *p) {
    if (p) { ++br_test.frees; --br_test.live; free(p); }
}

int bh_br_exact_name(int fd, const char *name) {
    ++br_test.calls; return bh_br_darwin_exact_name(fd, name);
}
