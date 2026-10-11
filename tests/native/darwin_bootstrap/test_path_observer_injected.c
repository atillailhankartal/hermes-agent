#include "../../../native/darwin_bootstrap/path_observer_v1.h"

#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

void bh_po_test_reset(void);
void bh_po_test_acl(int mode, int error);
int bh_po_test_mutate_before_open(int parent, const char *name, const char *saved);
int bh_po_test_mutation_done(void);
int bh_po_test_after_open_hook_count(void);
int bh_po_test_after_open_hook_fstat_count(void);
int bh_po_test_after_open_hook_acl_count(void);
int bh_po_test_after_open_hook_fstatat_count(void);
int bh_po_test_open_count(void);
int bh_po_test_open_success_count(void);
int bh_po_test_close_count(void);
int bh_po_test_live_owned(void);
int bh_po_test_max_owned(void);
int bh_po_test_case_max_owned(void);
int bh_po_test_acl_get_count(void);
int bh_po_test_set_replacement(int phase, int kind, int parent,
                               const char *name, const char *saved);
void bh_po_test_fail(int op, int ordinal, int error, int mode);
void bh_po_test_next_acl_eio_after_replacement(void);
void bh_po_test_change_after_open_fstat(void);
void bh_po_test_root_change_after_acl(void);
void bh_po_test_zero_link(int on_root, int on_leaf);
void bh_po_test_first_null_success(void);
int bh_po_test_next_call_count(void);
int bh_po_test_os_call_count(void);
int bh_po_test_op_count(int op);
int bh_po_test_acl_live(void);
int bh_po_test_acl_alloc_count(void);
int bh_po_test_acl_free_count(void);
int bh_po_test_resets_with_live_resources(void);

enum { TEST_ACL_REAL = 0, TEST_ACL_EMPTY = 1, TEST_ACL_NULL = 2,
       TEST_ACL_PRESENT = 3 };
enum { TEST_DUP = 1, TEST_FSTAT = 2, TEST_FSTATAT = 3, TEST_OPENAT = 4,
       TEST_ACL_GET = 5, TEST_ACL_VALID = 6, TEST_ACL_FIRST = 7,
       TEST_ACL_FREE = 8, TEST_CLOSE = 9 };
enum { TEST_BEFORE_OPEN = 1, TEST_AFTER_OPEN = 2, TEST_FINAL_SWEEP = 3 };
enum { TEST_REPLACE_FILE = 1, TEST_REPLACE_SYMLINK = 2,
       TEST_REPLACE_DIRECTORY = 3 };

struct fixture { char path[64]; int root_fd; };
static bh_po_result_v1 last_result;

static int make_fixture(struct fixture *fixture) {
    (void)memset(fixture, 0, sizeof(*fixture));
    fixture->root_fd = -1;
    (void)strcpy(fixture->path, "/private/tmp/bh-po-inject-XXXXXX");
    if (mkdtemp(fixture->path) == NULL) return 0;
    fixture->root_fd = open(fixture->path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fixture->root_fd < 0) return 0;
    int fd = openat(fixture->root_fd, "leaf", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    return close(fd) == 0;
}

static int clean_fixture(struct fixture *fixture) {
    int okay = 1;
    if (fixture->root_fd >= 0) {
        (void)fchmod(fixture->root_fd, 0700);
        (void)unlinkat(fixture->root_fd, "link", 0);
        (void)unlinkat(fixture->root_fd, "hard", 0);
        (void)unlinkat(fixture->root_fd, "fifo", 0);
        (void)unlinkat(fixture->root_fd, "sock", 0);
        (void)unlinkat(fixture->root_fd, "alias", 0);
        (void)unlinkat(fixture->root_fd, "saved/leaf", 0);
        if (unlinkat(fixture->root_fd, "saved", 0) != 0)
            (void)unlinkat(fixture->root_fd, "saved", AT_REMOVEDIR);
        if (unlinkat(fixture->root_fd, "leaf", 0) != 0 &&
            unlinkat(fixture->root_fd, "leaf", AT_REMOVEDIR) != 0)
            okay = 0;
        (void)unlinkat(fixture->root_fd, "dir/leaf", 0);
        if (unlinkat(fixture->root_fd, "dir", AT_REMOVEDIR) != 0)
            (void)unlinkat(fixture->root_fd, "dir", 0);
        if (close(fixture->root_fd) != 0) okay = 0;
    }
    if (fixture->path[0] != '\0' && rmdir(fixture->path) != 0) okay = 0;
    return okay;
}

static bh_po_request_v1 request_for(const struct fixture *fixture) {
    bh_po_request_v1 request = {0};
    struct stat root;
    if (fstat(fixture->root_fd, &root) != 0) return request;
    request.abi_version = BH_PO_ABI_V1;
    request.struct_size = (uint32_t)sizeof(request);
    request.component_count = 1;
    request.leaf_kind = BH_PO_LEAF_REGULAR;
    request.expected_uid = (uint32_t)root.st_uid;
    request.expected_gid = (uint32_t)root.st_gid;
    request.components[0].length = 4;
    (void)memcpy(request.components[0].bytes, "leaf", 4);
    return request;
}

static int observed(const bh_po_result_v1 *result, uint32_t outcome, uint32_t reason) {
    return result->abi_version == BH_PO_ABI_V1 &&
           result->struct_size == sizeof(*result) &&
           result->outcome == outcome && result->reason == reason &&
           result->installed_authority == 0 && result->ready == 0;
}

static int invoke(int fd, bh_po_request_v1 *request, bh_po_result_v1 *result,
                  uint32_t outcome, uint32_t reason) {
    uint32_t returned = bh_po_observe_v1(fd, request, result);
    last_result = *result;
    return returned == result->outcome && observed(result, outcome, reason);
}

static int invalid_without_os(int fd, bh_po_request_v1 *request,
                              uint32_t reason) {
    bh_po_result_v1 result;
    (void)memset(&result, 0xa5, sizeof(result));
    bh_po_test_reset();
    return invoke(fd, request, &result, BH_PO_REJECTED, reason) &&
           bh_po_test_os_call_count() == 0 && result.cleanup_failed == 0;
}

static int run_args(const struct fixture *fixture) {
    bh_po_request_v1 valid = request_for(fixture), request;
    int okay = 1;
    request = valid; request.component_count = 0;
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    request = valid; request.component_count = 17;
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    request = valid; request.components[0].length = 0;
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    request = valid; request.components[0].length = 256;
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    request = valid; request.component_count = 9;
    for (uint32_t i = 0; i < 9; ++i) {
        request.components[i].length = i == 8 ? 9 : 255;
        (void)memset(request.components[i].bytes, 'x',
                     request.components[i].length);
    }
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    request = valid; request.components[0].bytes[1] = '/';
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    request = valid; request.components[0].bytes[1] = 0;
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    request = valid; request.components[0].length = 1;
    request.components[0].bytes[0] = '.';
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    request = valid; request.components[0].length = 2;
    request.components[0].bytes[0] = '.'; request.components[0].bytes[1] = '.';
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    request = valid; request.leaf_kind = 3;
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    request = valid; request.abi_version = 2;
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_ABI);
    request = valid; request.struct_size--;
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_ABI);
    request = valid; request.reserved = 1;
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    request = valid; request.forbid_owner_write = 2;
    okay &= invalid_without_os(fixture->root_fd, &request, BH_PO_BAD_ARGUMENT);
    bh_po_test_reset();
    okay &= bh_po_observe_v1(fixture->root_fd, &valid, NULL) == BH_PO_REJECTED &&
            bh_po_test_os_call_count() == 0;
    bh_po_result_v1 result;
    bh_po_test_reset();
    okay &= bh_po_observe_v1(fixture->root_fd, NULL, &result) == BH_PO_REJECTED &&
            observed(&result, BH_PO_REJECTED, BH_PO_BAD_ARGUMENT) &&
            bh_po_test_os_call_count() == 0;
    return okay;
}

static int same_metadata(const bh_po_metadata_v1 *a, const bh_po_metadata_v1 *b) {
    return a->device == b->device && a->inode == b->inode &&
           a->link_count == b->link_count && a->uid == b->uid &&
           a->gid == b->gid && a->mode == b->mode &&
           a->file_type == b->file_type && a->acl_state == b->acl_state &&
           a->acl_errno == b->acl_errno;
}

static int same_result(const bh_po_result_v1 *a, const bh_po_result_v1 *b) {
    if (a->abi_version != b->abi_version || a->struct_size != b->struct_size ||
        a->outcome != b->outcome || a->reason != b->reason ||
        a->installed_authority != b->installed_authority || a->ready != b->ready ||
        a->completed_records != b->completed_records ||
        a->failed_index != b->failed_index || a->syscall_errno != b->syscall_errno ||
        a->cleanup_failed != b->cleanup_failed) return 0;
    for (size_t i = 0; i < 17; ++i)
        if (!same_metadata(&a->records[i], &b->records[i])) return 0;
    return 1;
}

static size_t common_alignment(void) {
    size_t a = _Alignof(bh_po_request_v1), b = _Alignof(bh_po_result_v1);
    size_t value = a > b ? a : b;
    while (value % a != 0 || value % b != 0) {
        if (value == SIZE_MAX) return 0;
        ++value;
    }
    return value;
}

static int run_alias(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 baseline = {0};
    bh_po_test_reset();
    if (!invoke(fixture->root_fd, &request, &baseline,
                BH_PO_OBSERVED_UNTRUSTED, BH_PO_NONE)) return 0;
    size_t offset = common_alignment();
    if (offset == 0 || offset >= sizeof(request) || offset >= sizeof(baseline)) return 0;
    const size_t req_offsets[] = {0, 0, offset};
    const size_t result_offsets[] = {0, offset, 0};
    for (size_t layout = 0; layout < 3; ++layout) {
        size_t request_offset = req_offsets[layout];
        size_t result_offset = result_offsets[layout];
        if (request_offset > SIZE_MAX - sizeof(request) ||
            result_offset > SIZE_MAX - sizeof(baseline)) return 0;
        size_t request_end = request_offset + sizeof(request);
        size_t result_end = result_offset + sizeof(baseline);
        size_t span = request_end > result_end ? request_end : result_end;
        unsigned char *storage = malloc(span);
        if (storage == NULL) return 0;
        int aligned = ((uintptr_t)(storage + request_offset) %
                       _Alignof(bh_po_request_v1) == 0) &&
                      ((uintptr_t)(storage + result_offset) %
                       _Alignof(bh_po_result_v1) == 0);
        int overlaps = request_offset < result_end && result_offset < request_end;
        (void)memcpy(storage + request_offset, &request, sizeof(request));
        bh_po_test_reset();
        uint32_t returned = bh_po_observe_v1(
            fixture->root_fd,
            (const bh_po_request_v1 *)(const void *)(storage + request_offset),
            (bh_po_result_v1 *)(void *)(storage + result_offset));
        bh_po_result_v1 actual;
        (void)memcpy(&actual, storage + result_offset, sizeof(actual));
        free(storage);
        if (!aligned || !overlaps || returned != baseline.outcome ||
            !same_result(&baseline, &actual) || bh_po_test_live_owned() != 0)
            return 0;
    }
    request.abi_version = BH_PO_ABI_V1 + 1;
    if (!invalid_without_os(fixture->root_fd, &request, BH_PO_ABI)) return 0;
    request.abi_version = BH_PO_ABI_V1;
    bh_po_test_reset();
    if (bh_po_observe_v1(fixture->root_fd, &request, NULL) != BH_PO_REJECTED ||
        bh_po_test_os_call_count() != 0) return 0;
    bh_po_result_v1 null_request;
    bh_po_test_reset();
    if (bh_po_observe_v1(fixture->root_fd, NULL, &null_request) != BH_PO_REJECTED ||
        !observed(&null_request, BH_PO_REJECTED, BH_PO_BAD_ARGUMENT) ||
        bh_po_test_os_call_count() != 0) return 0;
    last_result = baseline;
    return 1;
}

static int make_dir_leaf(const struct fixture *fixture) {
    if (mkdirat(fixture->root_fd, "dir", 0700) != 0) return 0;
    int fd = openat(fixture->root_fd, "dir/leaf",
                    O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    return close(fd) == 0;
}

static void use_dir_leaf(bh_po_request_v1 *request) {
    request->component_count = 2;
    request->components[0].length = 3;
    (void)memcpy(request->components[0].bytes, "dir", 3);
    request->components[1].length = 4;
    (void)memcpy(request->components[1].bytes, "leaf", 4);
}

static int check_stat_record(const bh_po_metadata_v1 *record,
                             const struct stat *actual) {
    return record->device == (uint64_t)actual->st_dev &&
           record->inode == (uint64_t)actual->st_ino &&
           record->link_count == (uint64_t)actual->st_nlink &&
           record->uid == (uint32_t)actual->st_uid &&
           record->gid == (uint32_t)actual->st_gid &&
           record->mode == (uint32_t)(actual->st_mode & 07777) &&
           record->file_type == (uint32_t)(actual->st_mode & S_IFMT);
}

static int run_raw_metadata(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    struct stat root, leaf;
    if (fstat(fixture->root_fd, &root) != 0 ||
        fstatat(fixture->root_fd, "leaf", &leaf, AT_SYMLINK_NOFOLLOW) != 0)
        return 0;
    bh_po_test_reset();
    return invoke(fixture->root_fd, &request, &result,
                  BH_PO_OBSERVED_UNTRUSTED, BH_PO_NONE) &&
           result.completed_records == 2 &&
           check_stat_record(&result.records[0], &root) &&
           check_stat_record(&result.records[1], &leaf);
}

static int run_owner_group(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    request.expected_uid = request.expected_uid == UINT32_MAX ?
        request.expected_uid - 1 : request.expected_uid + 1;
    bh_po_test_reset();
    int okay = invoke(fixture->root_fd, &request, &result,
                      BH_PO_REJECTED, BH_PO_OWNER);
    request = request_for(fixture);
    request.expected_gid = request.expected_gid == UINT32_MAX ?
        request.expected_gid - 1 : request.expected_gid + 1;
    bh_po_test_reset();
    return okay && invoke(fixture->root_fd, &request, &result,
                          BH_PO_REJECTED, BH_PO_GROUP);
}

static int run_writable(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    int okay = 1;
    const mode_t root_modes[] = {0720, 0702};
    for (size_t i = 0; i < 2; ++i) {
        if (fchmod(fixture->root_fd, root_modes[i]) != 0) return 0;
        bh_po_test_reset();
        okay &= invoke(fixture->root_fd, &request, &result,
                       BH_PO_REJECTED, BH_PO_WRITABLE);
    }
    if (fchmod(fixture->root_fd, 0700) != 0) return 0;
    request.forbid_owner_write = 1;
    bh_po_test_reset();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_WRITABLE);
    request.forbid_owner_write = 0;
    bh_po_test_reset();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_OBSERVED_UNTRUSTED, BH_PO_NONE);
    if (fchmod(fixture->root_fd, 01700) != 0) return 0;
    bh_po_test_reset();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_SPECIAL_MODE);
    if (fchmod(fixture->root_fd, 0700) != 0 || !make_dir_leaf(fixture)) return 0;
    use_dir_leaf(&request);
    int dirfd = openat(fixture->root_fd, "dir", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int leaffd = openat(fixture->root_fd, "dir/leaf", O_RDONLY | O_CLOEXEC);
    if (dirfd < 0 || leaffd < 0) {
        if (dirfd >= 0) (void)close(dirfd);
        if (leaffd >= 0) (void)close(leaffd);
        return 0;
    }
    const mode_t dirty_modes[] = {0720, 0702};
    for (size_t i = 0; i < 2; ++i) {
        if (fchmod(dirfd, dirty_modes[i]) != 0) okay = 0;
        bh_po_test_reset();
        okay &= invoke(fixture->root_fd, &request, &result,
                       BH_PO_REJECTED, BH_PO_WRITABLE);
        if (fchmod(dirfd, 0700) != 0) okay = 0;
        if (fchmod(leaffd, i == 0 ? 0620 : 0602) != 0) okay = 0;
        bh_po_test_reset();
        okay &= invoke(fixture->root_fd, &request, &result,
                       BH_PO_REJECTED, BH_PO_WRITABLE);
        if (fchmod(leaffd, 0600) != 0) okay = 0;
    }
    if (close(dirfd) != 0 || close(leaffd) != 0) okay = 0;
    return okay;
}

static int run_links(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    if (linkat(fixture->root_fd, "leaf", fixture->root_fd, "hard", 0) != 0)
        return 0;
    struct stat root, linked_leaf;
    if (fstat(fixture->root_fd, &root) != 0 || root.st_nlink < 1 ||
        fstatat(fixture->root_fd, "leaf", &linked_leaf,
                AT_SYMLINK_NOFOLLOW) != 0 || linked_leaf.st_nlink != 2)
        return 0;
    bh_po_test_reset();
    int okay = invoke(fixture->root_fd, &request, &result,
                      BH_PO_REJECTED, BH_PO_LINK_COUNT) &&
               result.records[0].link_count == (uint64_t)root.st_nlink &&
               result.records[1].link_count == (uint64_t)linked_leaf.st_nlink;
    if (unlinkat(fixture->root_fd, "hard", 0) != 0) return 0;
    bh_po_test_reset();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_OBSERVED_UNTRUSTED, BH_PO_NONE);
    bh_po_test_reset();
    bh_po_test_zero_link(0, 1);
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_LINK_COUNT);
    bh_po_test_reset();
    bh_po_test_zero_link(1, 0);
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_LINK_COUNT);
    return okay;
}

static int run_symlink_intermediate(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    if (!make_dir_leaf(fixture) ||
        symlinkat("dir", fixture->root_fd, "alias") != 0) return 0;
    use_dir_leaf(&request);
    request.components[0].length = 5;
    (void)memcpy(request.components[0].bytes, "alias", 5);
    bh_po_test_reset();
    return invoke(fixture->root_fd, &request, &result,
                  BH_PO_REJECTED, BH_PO_SYMLINK) &&
           bh_po_test_open_count() == 0;
}

static int retained_target_unchanged(const struct fixture *fixture,
                                     const struct stat *original,
                                     const char *expected, size_t expected_size) {
    struct stat retained, link, followed;
    char target[16] = {0};
    char content[64] = {0};
    if (expected_size > sizeof(content) ||
        fstatat(fixture->root_fd, "saved", &retained,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(fixture->root_fd, "leaf", &link,
                AT_SYMLINK_NOFOLLOW) != 0 || !S_ISLNK(link.st_mode) ||
        fstatat(fixture->root_fd, "leaf", &followed, 0) != 0 ||
        readlinkat(fixture->root_fd, "leaf", target, sizeof(target)) != 5 ||
        memcmp(target, "saved", 5) != 0) return 0;
    int reader = openat(fixture->root_fd, "saved", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (reader < 0) return 0;
    ssize_t read_count = pread(reader, content, expected_size, 0);
    int closed = close(reader);
    return read_count == (ssize_t)expected_size && closed == 0 &&
           memcmp(content, expected, expected_size) == 0 &&
           original->st_dev == retained.st_dev && original->st_ino == retained.st_ino &&
           original->st_uid == retained.st_uid && original->st_gid == retained.st_gid &&
           original->st_mode == retained.st_mode &&
           original->st_nlink == retained.st_nlink &&
           original->st_size == retained.st_size &&
           retained.st_size == (off_t)expected_size &&
           retained.st_dev == followed.st_dev && retained.st_ino == followed.st_ino;
}

static int run_symlink_leaf(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    int okay = 1;
    if (symlinkat("leaf", fixture->root_fd, "link") != 0) return 0;
    request.components[0].length = 4;
    (void)memcpy(request.components[0].bytes, "link", 4);
    bh_po_test_reset();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_SYMLINK) &&
            bh_po_test_open_count() == 0;
    if (unlinkat(fixture->root_fd, "link", 0) != 0 ||
        symlinkat("missing", fixture->root_fd, "link") != 0) return 0;
    bh_po_test_reset();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_SYMLINK) &&
            bh_po_test_open_count() == 0;
    if (unlinkat(fixture->root_fd, "link", 0) != 0) return 0;
    request = request_for(fixture);
    static const char payload[] = "no-follow-target-sentinel";
    int writer = openat(fixture->root_fd, "leaf", O_WRONLY | O_CLOEXEC);
    if (writer < 0) return 0;
    ssize_t written = write(writer, payload, sizeof(payload) - 1);
    int writer_closed = close(writer);
    if (written != (ssize_t)(sizeof(payload) - 1) || writer_closed != 0) return 0;
    struct stat original;
    if (fstatat(fixture->root_fd, "leaf", &original,
                AT_SYMLINK_NOFOLLOW) != 0) return 0;
    bh_po_test_reset();
    if (bh_po_test_set_replacement(TEST_BEFORE_OPEN, TEST_REPLACE_SYMLINK,
                                   fixture->root_fd, "leaf", "saved") != 0)
        return 0;
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_REPLACED) &&
            (result.syscall_errno == ELOOP || result.syscall_errno == ENOTDIR) &&
            bh_po_test_mutation_done() == 1 &&
            bh_po_test_open_count() == 1 &&
            bh_po_test_open_success_count() == 0 &&
            bh_po_test_op_count(TEST_OPENAT) == 1 &&
            bh_po_test_op_count(TEST_FSTAT) == 2 &&
            bh_po_test_op_count(TEST_FSTATAT) == 1 &&
            bh_po_test_acl_get_count() == 1 &&
            retained_target_unchanged(fixture, &original, payload,
                                      sizeof(payload) - 1);
    return okay;
}

static int run_type(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    int okay = 1;
    if (mkfifoat(fixture->root_fd, "fifo", 0600) != 0) return 0;
    request.components[0].length = 4;
    (void)memcpy(request.components[0].bytes, "fifo", 4);
    bh_po_test_reset();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_BAD_TYPE) &&
            bh_po_test_open_count() == 0;
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int length = snprintf(address.sun_path, sizeof(address.sun_path), "%s/sock",
                          fixture->path);
    if (sock < 0 || length < 0 || (size_t)length >= sizeof(address.sun_path) ||
        bind(sock, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (sock >= 0) (void)close(sock);
        return 0;
    }
    request.components[0].length = 4;
    (void)memcpy(request.components[0].bytes, "sock", 4);
    bh_po_test_reset();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_BAD_TYPE) &&
            bh_po_test_open_count() == 0;
    if (close(sock) != 0) okay = 0;
    request = request_for(fixture);
    request.component_count = 2;
    request.components[1].length = 1;
    request.components[1].bytes[0] = 'x';
    bh_po_test_reset();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_BAD_TYPE) &&
            bh_po_test_open_count() == 0;
    request = request_for(fixture);
    request.leaf_kind = BH_PO_LEAF_DIRECTORY;
    bh_po_test_reset();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_BAD_TYPE) &&
            bh_po_test_open_count() == 0;
    if (mkdirat(fixture->root_fd, "dir", 0700) != 0) return 0;
    request = request_for(fixture);
    request.components[0].length = 3;
    (void)memcpy(request.components[0].bytes, "dir", 3);
    bh_po_test_reset();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_BAD_TYPE) &&
            bh_po_test_open_count() == 0;
    request = request_for(fixture);
    bh_po_test_reset();
    if (bh_po_test_set_replacement(TEST_BEFORE_OPEN, TEST_REPLACE_DIRECTORY,
                                   fixture->root_fd, "leaf", "saved") != 0)
        return 0;
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_REPLACED) &&
            bh_po_test_mutation_done() == 1;
    return okay;
}

static int run_replace_after_open(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    static const char payload[] = "after-open-retained-sentinel";
    int writer = openat(fixture->root_fd, "leaf", O_WRONLY | O_CLOEXEC);
    if (writer < 0) return 0;
    ssize_t written = write(writer, payload, sizeof(payload) - 1);
    int writer_closed = close(writer);
    if (written != (ssize_t)(sizeof(payload) - 1) || writer_closed != 0) return 0;
    struct stat original, retained, replacement;
    if (fstatat(fixture->root_fd, "leaf", &original,
                AT_SYMLINK_NOFOLLOW) != 0) return 0;
    bh_po_test_reset();
    if (bh_po_test_set_replacement(TEST_AFTER_OPEN, TEST_REPLACE_FILE,
                                   fixture->root_fd, "leaf", "saved") != 0)
        return 0;
    int oracle = invoke(fixture->root_fd, &request, &result,
                        BH_PO_REJECTED, BH_PO_REPLACED);
    if (fstatat(fixture->root_fd, "saved", &retained,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(fixture->root_fd, "leaf", &replacement,
                AT_SYMLINK_NOFOLLOW) != 0) return 0;
    char content[sizeof(payload)] = {0};
    int reader = openat(fixture->root_fd, "saved", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (reader < 0) return 0;
    ssize_t read_count = pread(reader, content, sizeof(payload) - 1, 0);
    int reader_closed = close(reader);
    return oracle && result.syscall_errno == 0 &&
           bh_po_test_mutation_done() == 1 &&
           bh_po_test_after_open_hook_count() == 1 &&
           bh_po_test_after_open_hook_fstat_count() == 4 &&
           bh_po_test_after_open_hook_acl_count() == 2 &&
           bh_po_test_after_open_hook_fstatat_count() == 2 &&
           bh_po_test_op_count(TEST_FSTATAT) == 2 &&
           bh_po_test_op_count(TEST_FSTAT) == 4 &&
           bh_po_test_open_count() == 1 &&
           bh_po_test_open_success_count() == 1 &&
           bh_po_test_acl_get_count() == 2 &&
           original.st_dev == retained.st_dev && original.st_ino == retained.st_ino &&
           original.st_uid == retained.st_uid && original.st_gid == retained.st_gid &&
           original.st_mode == retained.st_mode &&
           original.st_nlink == retained.st_nlink &&
           original.st_size == retained.st_size &&
           (retained.st_dev != replacement.st_dev ||
            retained.st_ino != replacement.st_ino) &&
           read_count == (ssize_t)(sizeof(payload) - 1) && reader_closed == 0 &&
           memcmp(content, payload, sizeof(payload) - 1) == 0;
}

static int run_metadata_change(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    bh_po_test_reset();
    bh_po_test_change_after_open_fstat();
    return invoke(fixture->root_fd, &request, &result,
                  BH_PO_REJECTED, BH_PO_CHANGED);
}

static int run_root_change(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    bh_po_test_reset();
    bh_po_test_root_change_after_acl();
    return invoke(fixture->root_fd, &request, &result,
                  BH_PO_REJECTED, BH_PO_CHANGED);
}

static int run_final_sweep(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    if (!make_dir_leaf(fixture)) return 0;
    use_dir_leaf(&request);
    bh_po_test_reset();
    if (bh_po_test_set_replacement(TEST_FINAL_SWEEP, TEST_REPLACE_FILE,
                                   fixture->root_fd, "dir", "saved") != 0)
        return 0;
    return invoke(fixture->root_fd, &request, &result,
                  BH_PO_REJECTED, BH_PO_REPLACED) &&
           bh_po_test_mutation_done() == 1;
}

static int run_acl_errors(const struct fixture *fixture) {
    const int errors[] = {EACCES, EBADF, EINVAL, ENOMEM, EIO, ENOTSUP, ENOENT, 0};
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    int okay = 1;
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        bh_po_test_reset();
        bh_po_test_acl(TEST_ACL_NULL, errors[i]);
        okay &= invoke(fixture->root_fd, &request, &result,
                       BH_PO_UNAVAILABLE, BH_PO_ACL_UNKNOWN) &&
                result.records[0].acl_state ==
                (errors[i] == ENOENT ? BH_PO_ACL_GET_ENOENT_UNCONFIRMED :
                                       BH_PO_ACL_ERROR) &&
                result.records[0].acl_errno == errors[i] &&
                result.syscall_errno == errors[i] &&
                result.completed_records == 0 &&
                bh_po_test_acl_live() == 0;
    }
    bh_po_test_reset();
    bh_po_test_fail(TEST_ACL_VALID, 1, EIO, 0);
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_UNAVAILABLE, BH_PO_ACL_UNKNOWN) &&
            result.records[0].acl_state == BH_PO_ACL_ERROR &&
            result.records[0].acl_errno == EIO && result.syscall_errno == EIO &&
            bh_po_test_acl_live() == 0;
    bh_po_test_reset();
    bh_po_test_fail(TEST_ACL_FIRST, 1, EIO, 0);
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_UNAVAILABLE, BH_PO_ACL_UNKNOWN) &&
            result.records[0].acl_state == BH_PO_ACL_ERROR &&
            result.records[0].acl_errno == EIO && result.syscall_errno == EIO &&
            bh_po_test_acl_live() == 0;
    bh_po_test_reset();
    bh_po_test_first_null_success();
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_UNAVAILABLE, BH_PO_ACL_UNKNOWN) &&
            result.records[0].acl_state == BH_PO_ACL_ERROR &&
            result.records[0].acl_errno == 0 && result.syscall_errno == 0 &&
            bh_po_test_acl_live() == 0;
    return okay;
}

static int run_acl_present(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    bh_po_test_reset();
    bh_po_test_acl(TEST_ACL_PRESENT, 0);
    return invoke(fixture->root_fd, &request, &result,
                  BH_PO_REJECTED, BH_PO_ACL_PRESENT_REASON) &&
           result.records[0].acl_state == BH_PO_ACL_PRESENT &&
           bh_po_test_acl_alloc_count() == 1 &&
           bh_po_test_acl_free_count() == 1 &&
           bh_po_test_open_count() == 0 &&
           bh_po_test_acl_live() == 0;
}

static int run_descriptor_budget(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    char path[64] = {0};
    size_t length = 0;
    int okay = 1;
    for (uint32_t i = 0; i < 15; ++i) {
        if (length != 0) path[length++] = '/';
        path[length++] = 'd';
        path[length] = '\0';
        if (mkdirat(fixture->root_fd, path, 0700) != 0) { okay = 0; break; }
        request.components[i].length = 1;
        request.components[i].bytes[0] = 'd';
    }
    if (okay) {
        char leaf_path[64];
        int len = snprintf(leaf_path, sizeof(leaf_path), "%s/leaf", path);
        if (len < 0 || (size_t)len >= sizeof(leaf_path)) okay = 0;
        else {
            int fd = openat(fixture->root_fd, leaf_path,
                            O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
            if (fd < 0 || close(fd) != 0) okay = 0;
            request.component_count = 16;
            request.components[15].length = 4;
            (void)memcpy(request.components[15].bytes, "leaf", 4);
            bh_po_test_reset();
            okay &= invoke(fixture->root_fd, &request, &result,
                           BH_PO_OBSERVED_UNTRUSTED, BH_PO_NONE) &&
                    result.completed_records == 17 &&
                    bh_po_test_max_owned() == 17 &&
                    bh_po_test_live_owned() == 0;
            request.component_count = 17;
            okay &= invalid_without_os(fixture->root_fd, &request,
                                       BH_PO_BAD_ARGUMENT);
            if (unlinkat(fixture->root_fd, leaf_path, 0) != 0) okay = 0;
        }
    }
    while (length > 0) {
        if (unlinkat(fixture->root_fd, path, AT_REMOVEDIR) != 0) okay = 0;
        while (length > 0 && path[length - 1] != '/') --length;
        if (length > 0) --length;
        path[length] = '\0';
    }
    return okay;
}

static int run_cleanup_failures(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    const int ops[] = {TEST_DUP, TEST_FSTAT, TEST_FSTATAT,
                       TEST_OPENAT, TEST_ACL_GET};
    int baseline_counts[sizeof(ops) / sizeof(ops[0])];
    bh_po_test_reset();
    if (!invoke(fixture->root_fd, &request, &result,
                BH_PO_OBSERVED_UNTRUSTED, BH_PO_NONE)) return 0;
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); ++i)
        baseline_counts[i] = bh_po_test_op_count(ops[i]);
    int okay = 1;
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); ++i) {
        if (baseline_counts[i] <= 0) return 0;
        for (int ordinal = 1; ordinal <= baseline_counts[i]; ++ordinal) {
            bh_po_test_reset();
            bh_po_test_fail(ops[i], ordinal, EIO, 0);
            uint32_t reason = ops[i] == TEST_ACL_GET ?
                BH_PO_ACL_UNKNOWN : BH_PO_SYSCALL;
            okay &= invoke(fixture->root_fd, &request, &result,
                           BH_PO_UNAVAILABLE, reason) &&
                    bh_po_test_op_count(ops[i]) == ordinal &&
                    bh_po_test_live_owned() == 0 && bh_po_test_acl_live() == 0;
        }
    }
    bh_po_test_reset();
    bh_po_test_fail(TEST_CLOSE, 1, EIO, 1);
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_UNAVAILABLE, BH_PO_CLEANUP) &&
            result.cleanup_failed == 1 && bh_po_test_live_owned() == 0;
    bh_po_test_reset();
    bh_po_test_fail(TEST_ACL_FREE, 1, EIO, 1);
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_UNAVAILABLE, BH_PO_CLEANUP) &&
            result.cleanup_failed == 1 && bh_po_test_acl_live() == 0;
    bh_po_test_reset();
    bh_po_test_fail(TEST_CLOSE, 1, EIO, 0);
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_UNAVAILABLE, BH_PO_CLEANUP) &&
            result.cleanup_failed == 1 &&
            bh_po_test_op_count(TEST_CLOSE) == 2 &&
            bh_po_test_live_owned() == 1; /* unknown, no leak-free assertion */
    bh_po_test_reset(); /* one intentionally unknown close resource remains */
    bh_po_test_fail(TEST_ACL_FREE, 1, EIO, 0);
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_UNAVAILABLE, BH_PO_CLEANUP) &&
            result.cleanup_failed == 1 &&
            bh_po_test_op_count(TEST_ACL_FREE) == 1 &&
            bh_po_test_acl_live() == 1 &&
            bh_po_test_resets_with_live_resources() == 1;
    return okay;
}

static int run_case(const char *name, const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    uint32_t returned;
    int okay = 0;
    struct stat before, after;
    int flags_before = fcntl(fixture->root_fd, F_GETFL);
    int fd_flags_before = fcntl(fixture->root_fd, F_GETFD);
    if (fstat(fixture->root_fd, &before) != 0 || flags_before < 0 ||
        fd_flags_before < 0) return 0;
    bh_po_test_reset();
    if (strcmp(name, "args") == 0) {
        okay = run_args(fixture);
    } else if (strcmp(name, "alias") == 0) {
        okay = run_alias(fixture);
    } else if (strcmp(name, "fd") == 0) {
        okay = invalid_without_os(-1, &request, BH_PO_BAD_FD) &&
               invalid_without_os(AT_FDCWD, &request, BH_PO_BAD_FD);
        int closed = dup(fixture->root_fd);
        if (closed < 0 || close(closed) != 0) return 0;
        bh_po_test_reset();
        okay &= invoke(closed, &request, &result, BH_PO_REJECTED, BH_PO_BAD_FD);
        int regular = openat(fixture->root_fd, "leaf", O_RDONLY | O_CLOEXEC);
        if (regular < 0) return 0;
        bh_po_test_reset();
        okay &= invoke(regular, &request, &result, BH_PO_REJECTED, BH_PO_BAD_TYPE);
        if (close(regular) != 0) okay = 0;
    } else if (strcmp(name, "raw-metadata") == 0) {
        okay = run_raw_metadata(fixture);
    } else if (strcmp(name, "owner-group") == 0) {
        okay = run_owner_group(fixture);
    } else if (strcmp(name, "symlink-intermediate") == 0) {
        okay = run_symlink_intermediate(fixture);
    } else if (strcmp(name, "symlink-leaf") == 0) {
        okay = run_symlink_leaf(fixture);
    } else if (strcmp(name, "type") == 0) {
        okay = run_type(fixture);
    } else if (strcmp(name, "links") == 0) {
        okay = run_links(fixture);
    } else if (strcmp(name, "acl-present") == 0) {
        okay = run_acl_present(fixture);
    } else if (strcmp(name, "acl-errors") == 0) {
        okay = run_acl_errors(fixture);
    } else if (strcmp(name, "replace-after-open") == 0) {
        okay = run_replace_after_open(fixture);
    } else if (strcmp(name, "metadata-change") == 0) {
        okay = run_metadata_change(fixture);
    } else if (strcmp(name, "root-change") == 0) {
        okay = run_root_change(fixture);
    } else if (strcmp(name, "final-sweep") == 0) {
        okay = run_final_sweep(fixture);
    } else if (strcmp(name, "cleanup-failures") == 0) {
        okay = run_cleanup_failures(fixture);
    } else if (strcmp(name, "descriptor-budget") == 0) {
        okay = run_descriptor_budget(fixture);
    } else if (strcmp(name, "empty-contract") == 0) {
        returned = bh_po_observe_v1(fixture->root_fd, &request, &result);
        last_result = result;
        okay = observed(&result, BH_PO_OBSERVED_UNTRUSTED, BH_PO_NONE) &&
               result.completed_records == 2 && result.failed_index == UINT32_MAX &&
               result.records[0].acl_state == BH_PO_ACL_EMPTY_VALIDATED &&
               result.records[1].acl_state == BH_PO_ACL_EMPTY_VALIDATED &&
               bh_po_test_acl_get_count() == 2 &&
               bh_po_test_acl_alloc_count() == 2 &&
               bh_po_test_acl_free_count() == 2 &&
               returned == result.outcome;
    } else if (strcmp(name, "replace-before-open") == 0) {
        struct stat original, retained, replacement;
        if (fstatat(fixture->root_fd, "leaf", &original,
                    AT_SYMLINK_NOFOLLOW) != 0) return 0;
        if (bh_po_test_mutate_before_open(fixture->root_fd, "leaf", "saved") != 0) return 0;
        bh_po_test_next_acl_eio_after_replacement();
        returned = bh_po_observe_v1(fixture->root_fd, &request, &result);
        last_result = result;
        okay = observed(&result, BH_PO_REJECTED, BH_PO_REPLACED) &&
               bh_po_test_mutation_done() == 1 && returned == result.outcome &&
               bh_po_test_next_call_count() == 0 &&
               fstatat(fixture->root_fd, "saved", &retained,
                       AT_SYMLINK_NOFOLLOW) == 0 &&
               fstatat(fixture->root_fd, "leaf", &replacement,
                       AT_SYMLINK_NOFOLLOW) == 0 &&
               original.st_dev == retained.st_dev &&
               original.st_ino == retained.st_ino &&
               (retained.st_dev != replacement.st_dev ||
                retained.st_ino != replacement.st_ino);
    } else if (strcmp(name, "writable") == 0) {
        okay = run_writable(fixture);
    } else if (strcmp(name, "no-authority") == 0) {
        returned = bh_po_observe_v1(fixture->root_fd, &request, &result);
        last_result = result;
        okay = returned == result.outcome &&
               observed(&result, BH_PO_OBSERVED_UNTRUSTED, BH_PO_NONE) &&
               result.completed_records == 2 &&
               result.failed_index == UINT32_MAX;
    } else {
        return 0;
    }
    int expects_unknown = strcmp(name, "cleanup-failures") == 0;
    return okay && fstat(fixture->root_fd, &after) == 0 &&
           before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           flags_before == fcntl(fixture->root_fd, F_GETFL) &&
           fd_flags_before == fcntl(fixture->root_fd, F_GETFD) &&
           bh_po_test_resets_with_live_resources() ==
               (expects_unknown ? 1 : 0) &&
           bh_po_test_max_owned() <= 17 &&
           (expects_unknown || (bh_po_test_live_owned() == 0 &&
                                bh_po_test_acl_live() == 0 &&
                                bh_po_test_acl_alloc_count() ==
                                bh_po_test_acl_free_count()));
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    struct fixture fixture;
    if (!make_fixture(&fixture)) {
        (void)fprintf(stderr, "SETUP_FAIL case=%s\n", argv[1]);
        (void)clean_fixture(&fixture);
        return 2;
    }
    int okay = run_case(argv[1], &fixture);
    int cleaned = clean_fixture(&fixture);
    (void)printf("case=%s status=%s cleanup=%s outcome=%u reason=%u errno=%d "
                 "cleanup_failed=%u authority=%u ready=%u open_count=%d "
                 "open_success_count=%d close_count=%d "
                 "max_owned=%d acl_get_count=%d next_call_count=%d\n",
                 argv[1], okay ? "PASS" : "FAIL",
                 cleaned ? "PASS" : "FAIL",
                 last_result.outcome, last_result.reason, last_result.syscall_errno,
                 last_result.cleanup_failed, last_result.installed_authority,
                 last_result.ready, bh_po_test_open_count(),
                 bh_po_test_open_success_count(),
                 bh_po_test_close_count(), bh_po_test_case_max_owned(),
                 bh_po_test_acl_get_count(), bh_po_test_next_call_count());
    return okay && cleaned ? 0 : 1;
}
