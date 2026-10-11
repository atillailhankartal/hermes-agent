#include "signed_preflight_v2_bundle_reader.h"
#include "bundle_reader_os.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

static const char *const leaves[3] = {"policy.v2.bin", "policy.v2.sig", "release.v2.bin"};
static const size_t minimum[3] = {49, 64, 17};
static const size_t maximum[3] = {65584, 64, 65552};

static int overlap(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (x > UINTPTR_MAX - an || y > UINTPTR_MAX - bn) return 1;
    return x < y + bn && y < x + an;
}
static int metadata_ok(const struct stat *s, const struct bh_v2_bundle_expectation *e, int directory) {
    return (directory ? S_ISDIR(s->st_mode) && s->st_nlink >= 1 : S_ISREG(s->st_mode) && s->st_nlink == 1) &&
        s->st_uid == e->uid && s->st_gid == e->gid && !(s->st_mode & (0222 | 07000));
}
static int size_ok(const struct stat *s, int i) {
    return s->st_size >= 0 && (uintmax_t)s->st_size >= minimum[i] &&
        (uintmax_t)s->st_size <= maximum[i] && (uintmax_t)s->st_size <= SIZE_MAX;
}
static int same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
        a->st_size == b->st_size && a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
        a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec && a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec;
}
static enum bh_v2_bundle_status acl_observe(int fd) {
    acl_t acl = bh_br_acl_get(fd);
    if (!acl) return BH_V2_BUNDLE_UNAVAILABLE;
    enum bh_v2_bundle_status r = BH_V2_BUNDLE_UNAVAILABLE;
    if (bh_br_acl_valid(acl) == 0) {
        acl_entry_t entry = NULL;
        errno = 0;
        int observed = bh_br_acl_first(acl, &entry);
        if (observed == 0 && entry != NULL) r = BH_V2_BUNDLE_REJECTED;
        else if (observed == -1 && errno == EINVAL && entry == NULL) r = BH_V2_BUNDLE_OBSERVED_UNTRUSTED;
    }
    if (bh_br_acl_free(acl) != 0) r = BH_V2_BUNDLE_UNAVAILABLE;
    return r;
}
/* Bounds are <=65584, safely representable by Darwin off_t/ssize_t. A short
 * read, including interrupted I/O, fails closed rather than delivering a prefix. */
static int full_read(int fd, void *bytes, size_t n) {
    return bh_br_pread(fd, bytes, n, 0) == (ssize_t)n;
}
void bh_v2_bundle_result_dispose(struct bh_v2_bundle_result *out) {
    if (!out) return;
    bh_br_free(out->policy); bh_br_free(out->signature); bh_br_free(out->manifest);
    memset(out, 0, sizeof(*out));
}
enum bh_v2_bundle_status bh_v2_bundle_observe(int borrowed_version_dir_fd,
    const struct bh_v2_bundle_expectation *expected, struct bh_v2_bundle_result *out) {
    if (!out || !expected || overlap(expected, sizeof(*expected), out, sizeof(*out))) return BH_V2_BUNDLE_REJECTED;
    /* Do not read expected or mutate a previous owned/invalid result on reuse. */
    if (out->policy || out->signature || out->manifest || out->policy_len ||
        out->signature_len || out->manifest_len || out->status != BH_V2_BUNDLE_REJECTED) return BH_V2_BUNDLE_REJECTED;
    if (expected->abi_version != BH_V2_BUNDLE_ABI || expected->struct_size != sizeof(*expected) ||
        borrowed_version_dir_fd < 0) return BH_V2_BUNDLE_REJECTED;
    const struct bh_v2_bundle_expectation e = *expected;
    enum bh_v2_bundle_status result = BH_V2_BUNDLE_UNAVAILABLE;
    int dir = bh_br_dup(borrowed_version_dir_fd), fd[3] = {-1, -1, -1};
    uint8_t *bytes[3] = {NULL, NULL, NULL}, *again = NULL;
    size_t lengths[3] = {0, 0, 0};
    struct stat directory, paths[3], opened[3], repeated;
    if (dir < 0) { out->status = errno == EBADF ? BH_V2_BUNDLE_REJECTED : BH_V2_BUNDLE_UNAVAILABLE; return out->status; }
    if (bh_br_stat(dir, &directory)) goto done;
    if (!metadata_ok(&directory, &e, 1) || directory.st_dev != e.device || directory.st_ino != e.inode) {
        result = BH_V2_BUNDLE_REJECTED; goto done;
    }
    result = acl_observe(dir);
    if (result != BH_V2_BUNDLE_OBSERVED_UNTRUSTED) goto done;
    /* Complete BOTH bound checks for ALL leaves before ANY allocation. */
    for (int i = 0; i < 3; ++i) {
        result = BH_V2_BUNDLE_UNAVAILABLE;
        if (bh_br_exact_name(dir, leaves[i]) || bh_br_atstat(dir, leaves[i], &paths[i], AT_SYMLINK_NOFOLLOW)) goto done;
        if (!metadata_ok(&paths[i], &e, 0) || !size_ok(&paths[i], i)) { result = BH_V2_BUNDLE_REJECTED; goto done; }
        fd[i] = bh_br_open(dir, leaves[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (fd[i] < 0) { if (errno == ELOOP || errno == ENOTDIR) result = BH_V2_BUNDLE_REJECTED; goto done; }
        if (bh_br_stat(fd[i], &opened[i])) goto done;
        if (!metadata_ok(&opened[i], &e, 0) || !size_ok(&opened[i], i) || !same(&paths[i], &opened[i])) {
            result = BH_V2_BUNDLE_REJECTED; goto done;
        }
        result = acl_observe(fd[i]);
        if (result != BH_V2_BUNDLE_OBSERVED_UNTRUSTED) goto done;
        lengths[i] = (size_t)opened[i].st_size;
    }
    result = BH_V2_BUNDLE_UNAVAILABLE;
    for (int i = 0; i < 3; ++i) {
        bytes[i] = bh_br_alloc(lengths[i]);
        if (!bytes[i] || !full_read(fd[i], bytes[i], lengths[i])) goto done;
    }
    /* Full second snapshots use those SAME retained FDs, even if metadata is
     * identical. This detects persistent drift; transient ABA remains possible. */
    for (int i = 0; i < 3; ++i) {
        again = bh_br_alloc(lengths[i]);
        if (!again || !full_read(fd[i], again, lengths[i])) goto done;
        if (memcmp(bytes[i], again, lengths[i])) { result = BH_V2_BUNDLE_REJECTED; goto done; }
        bh_br_free(again); again = NULL;
    }
    for (int i = 0; i < 3; ++i) {
        result = BH_V2_BUNDLE_UNAVAILABLE;
        if (bh_br_stat(fd[i], &repeated)) goto done;
        if (!same(&opened[i], &repeated)) { result = BH_V2_BUNDLE_REJECTED; goto done; }
        result = acl_observe(fd[i]);
        if (result != BH_V2_BUNDLE_OBSERVED_UNTRUSTED) goto done;
        result = BH_V2_BUNDLE_UNAVAILABLE;
        if (bh_br_exact_name(dir, leaves[i]) || bh_br_atstat(dir, leaves[i], &repeated, AT_SYMLINK_NOFOLLOW)) goto done;
        if (!same(&paths[i], &repeated)) { result = BH_V2_BUNDLE_REJECTED; goto done; }
    }
    result = BH_V2_BUNDLE_UNAVAILABLE;
    if (bh_br_stat(dir, &repeated)) goto done;
    if (!same(&directory, &repeated)) { result = BH_V2_BUNDLE_REJECTED; goto done; }
    result = acl_observe(dir);
done:
    /* Never retry ambiguous close: no success snapshot survives uncertainty. */
    for (int i = 0; i < 3; ++i) if (fd[i] >= 0 && bh_br_close(fd[i])) result = BH_V2_BUNDLE_UNAVAILABLE;
    if (bh_br_close(dir)) result = BH_V2_BUNDLE_UNAVAILABLE;
    bh_br_free(again);
    if (result == BH_V2_BUNDLE_OBSERVED_UNTRUSTED) {
        out->policy = bytes[0]; out->policy_len = lengths[0];
        out->signature = bytes[1]; out->signature_len = lengths[1];
        out->manifest = bytes[2]; out->manifest_len = lengths[2];
    } else for (int i = 0; i < 3; ++i) bh_br_free(bytes[i]);
    out->status = result;
    return result;
}
