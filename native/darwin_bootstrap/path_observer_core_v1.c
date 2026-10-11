#include "path_observer_v1.h"
#include "path_observer_os_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

enum { BH_PO_CHAIN_CAPACITY = BH_PO_MAX_COMPONENTS_V1 + 1u };

static void bh_po_fail(bh_po_result_v1 *result, uint32_t outcome,
                       uint32_t reason, int error, uint32_t index) {
    result->outcome = outcome;
    result->reason = reason;
    result->syscall_errno = error;
    result->failed_index = index;
}

static int bh_po_same_identity(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino &&
           (left->st_mode & S_IFMT) == (right->st_mode & S_IFMT);
}

static int bh_po_same_snapshot(const struct stat *left, const struct stat *right) {
    return bh_po_same_identity(left, right) &&
           left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
           left->st_mode == right->st_mode && left->st_nlink == right->st_nlink &&
           left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
}

static int bh_po_match_snapshot(const struct stat *expected,
                                const struct stat *actual,
                                bh_po_result_v1 *result, uint32_t index) {
    if (!bh_po_same_identity(expected, actual)) {
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_REPLACED, 0, index);
        return 0;
    }
    if (!bh_po_same_snapshot(expected, actual)) {
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_CHANGED, 0, index);
        return 0;
    }
    return 1;
}

static int bh_po_capture_metadata(const struct stat *stat,
                                  bh_po_metadata_v1 *record,
                                  bh_po_result_v1 *result, uint32_t index) {
    if ((int64_t)stat->st_dev < 0 || (int64_t)stat->st_nlink < 0 ||
        (uintmax_t)stat->st_uid > UINT32_MAX ||
        (uintmax_t)stat->st_gid > UINT32_MAX ||
        (uintmax_t)stat->st_mode > UINT32_MAX) {
        bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_SYSCALL, EOVERFLOW, index);
        return 0;
    }
    record->device = (uint64_t)stat->st_dev;
    record->inode = (uint64_t)stat->st_ino;
    record->link_count = (uint64_t)stat->st_nlink;
    record->uid = (uint32_t)stat->st_uid;
    record->gid = (uint32_t)stat->st_gid;
    record->mode = (uint32_t)(stat->st_mode & 07777);
    record->file_type = (uint32_t)(stat->st_mode & S_IFMT);
    return 1;
}

static int bh_po_filter_metadata(const struct stat *stat,
                                 const bh_po_request_v1 *request,
                                 bh_po_result_v1 *result, uint32_t index,
                                 int directory) {
    if ((directory && !S_ISDIR(stat->st_mode)) ||
        (!directory && !S_ISREG(stat->st_mode))) {
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_BAD_TYPE, 0, index);
        return 0;
    }
    if ((uint32_t)stat->st_uid != request->expected_uid) {
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_OWNER, 0, index);
        return 0;
    }
    if ((uint32_t)stat->st_gid != request->expected_gid) {
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_GROUP, 0, index);
        return 0;
    }
    if ((stat->st_mode & 0022) != 0 ||
        (request->forbid_owner_write != 0 && (stat->st_mode & 0200) != 0)) {
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_WRITABLE, 0, index);
        return 0;
    }
    if ((stat->st_mode & 07000) != 0) {
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_SPECIAL_MODE, 0, index);
        return 0;
    }
    if ((directory && stat->st_nlink < 1) ||
        (!directory && stat->st_nlink != 1)) {
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_LINK_COUNT, 0, index);
        return 0;
    }
    return 1;
}

static int bh_po_observe_acl(int fd, bh_po_metadata_v1 *record,
                             bh_po_result_v1 *result, uint32_t index) {
    errno = 0;
    acl_t acl = bh_po_os_acl_get(fd, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        int error = errno;
        record->acl_state = error == ENOENT ?
            BH_PO_ACL_GET_ENOENT_UNCONFIRMED : BH_PO_ACL_ERROR;
        record->acl_errno = error;
        bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_ACL_UNKNOWN, error, index);
        return 0;
    }

    int accepted = 0;
    errno = 0;
    if (bh_po_os_acl_valid(acl) != 0) {
        int error = errno;
        record->acl_state = BH_PO_ACL_ERROR;
        record->acl_errno = error;
        bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_ACL_UNKNOWN, error, index);
    } else {
        acl_entry_t first = NULL;
        errno = 0;
        int entry_result = bh_po_os_acl_first(acl, ACL_FIRST_ENTRY, &first);
        int error = errno;
        if (entry_result == 0 && first != NULL) {
            record->acl_state = BH_PO_ACL_PRESENT;
            bh_po_fail(result, BH_PO_REJECTED, BH_PO_ACL_PRESENT_REASON, 0, index);
        } else if (entry_result == -1 && error == EINVAL) {
            record->acl_state = BH_PO_ACL_EMPTY_VALIDATED;
            accepted = 1;
        } else {
            record->acl_state = BH_PO_ACL_ERROR;
            record->acl_errno = error;
            bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_ACL_UNKNOWN, error, index);
        }
    }

    if (bh_po_os_acl_free(acl) != 0) {
        int error = errno;
        result->cleanup_failed = 1;
        bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_CLEANUP, error, index);
        return 0;
    }
    return accepted;
}

static int bh_po_validate_request(const bh_po_request_v1 *request,
                                  bh_po_result_v1 *result,
                                  char names[BH_PO_MAX_COMPONENTS_V1]
                                            [BH_PO_MAX_COMPONENT_BYTES_V1 + 1u]) {
    if (request->abi_version != BH_PO_ABI_V1 ||
        request->struct_size != sizeof(*request)) {
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_ABI, 0, UINT32_MAX);
        return 0;
    }
    if (request->component_count == 0 ||
        request->component_count > BH_PO_MAX_COMPONENTS_V1 ||
        (request->leaf_kind != BH_PO_LEAF_REGULAR &&
         request->leaf_kind != BH_PO_LEAF_DIRECTORY) ||
        request->forbid_owner_write > 1 || request->reserved != 0) {
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_BAD_ARGUMENT, 0, UINT32_MAX);
        return 0;
    }

    uint32_t total = 0;
    for (uint32_t i = 0; i < request->component_count; ++i) {
        uint32_t length = request->components[i].length;
        if (length == 0 || length > BH_PO_MAX_COMPONENT_BYTES_V1 ||
            length > BH_PO_MAX_TOTAL_BYTES_V1 - total) {
            bh_po_fail(result, BH_PO_REJECTED, BH_PO_BAD_ARGUMENT, 0, i + 1);
            return 0;
        }
        total += length;
        if ((length == 1 && request->components[i].bytes[0] == '.') ||
            (length == 2 && request->components[i].bytes[0] == '.' &&
             request->components[i].bytes[1] == '.')) {
            bh_po_fail(result, BH_PO_REJECTED, BH_PO_BAD_ARGUMENT, 0, i + 1);
            return 0;
        }
        for (uint32_t j = 0; j < length; ++j) {
            unsigned char byte = request->components[i].bytes[j];
            if (byte == 0 || byte == '/') {
                bh_po_fail(result, BH_PO_REJECTED, BH_PO_BAD_ARGUMENT, 0, i + 1);
                return 0;
            }
        }
        (void)memcpy(names[i], request->components[i].bytes, length);
        names[i][length] = '\0';
    }
    return 1;
}

uint32_t bh_po_observe_v1(int borrowed_root_fd,
                          const bh_po_request_v1 *request,
                          bh_po_result_v1 *result) {
    if (result == NULL) return BH_PO_REJECTED;
    if (request == NULL) {
        (void)memset(result, 0, sizeof(*result));
        result->abi_version = BH_PO_ABI_V1;
        result->struct_size = sizeof(*result);
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_BAD_ARGUMENT, 0, UINT32_MAX);
        return result->outcome;
    }

    bh_po_request_v1 snapshot;
    (void)memcpy(&snapshot, request, sizeof(snapshot));
    (void)memset(result, 0, sizeof(*result));
    result->abi_version = BH_PO_ABI_V1;
    result->struct_size = sizeof(*result);
    result->outcome = BH_PO_REJECTED;
    result->reason = BH_PO_BAD_ARGUMENT;
    result->failed_index = UINT32_MAX;

    char names[BH_PO_MAX_COMPONENTS_V1][BH_PO_MAX_COMPONENT_BYTES_V1 + 1u];
    if (!bh_po_validate_request(&snapshot, result, names)) return result->outcome;
    if (borrowed_root_fd < 0) {
        bh_po_fail(result, BH_PO_REJECTED, BH_PO_BAD_FD, 0, 0);
        return result->outcome;
    }

    int chain[BH_PO_CHAIN_CAPACITY];
    struct stat checked[BH_PO_CHAIN_CAPACITY];
    for (uint32_t i = 0; i < BH_PO_CHAIN_CAPACITY; ++i) chain[i] = -1;
    uint32_t opened_count = 0;

    chain[0] = bh_po_os_dup_cloexec(borrowed_root_fd);
    if (chain[0] < 0) {
        int error = errno;
        bh_po_fail(result, error == EBADF ? BH_PO_REJECTED : BH_PO_UNAVAILABLE,
                   error == EBADF ? BH_PO_BAD_FD : BH_PO_SYSCALL, error, 0);
        return result->outcome;
    }
    opened_count = 1;

    if (bh_po_os_fstat(chain[0], &checked[0]) != 0) {
        bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_SYSCALL, errno, 0);
        goto cleanup;
    }
    if (!bh_po_capture_metadata(&checked[0], &result->records[0], result, 0) ||
        !bh_po_filter_metadata(&checked[0], &snapshot, result, 0, 1) ||
        !bh_po_observe_acl(chain[0], &result->records[0], result, 0))
        goto cleanup;
    struct stat repeated;
    if (bh_po_os_fstat(chain[0], &repeated) != 0) {
        bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_SYSCALL, errno, 0);
        goto cleanup;
    }
    if (!bh_po_match_snapshot(&checked[0], &repeated, result, 0)) goto cleanup;
    result->completed_records = 1;

    for (uint32_t i = 0; i < snapshot.component_count; ++i) {
        uint32_t index = i + 1;
        int directory = index < snapshot.component_count ||
                        snapshot.leaf_kind == BH_PO_LEAF_DIRECTORY;
        struct stat entry;
        if (bh_po_os_fstatat(chain[i], names[i], &entry,
                             AT_SYMLINK_NOFOLLOW) != 0) {
            bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_SYSCALL, errno, index);
            goto cleanup;
        }
        if (S_ISLNK(entry.st_mode)) {
            bh_po_fail(result, BH_PO_REJECTED, BH_PO_SYMLINK, 0, index);
            goto cleanup;
        }
        if ((directory && !S_ISDIR(entry.st_mode)) ||
            (!directory && !S_ISREG(entry.st_mode))) {
            bh_po_fail(result, BH_PO_REJECTED, BH_PO_BAD_TYPE, 0, index);
            goto cleanup;
        }
        int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
        if (directory) flags |= O_DIRECTORY;
        chain[index] = bh_po_os_openat(chain[i], names[i], flags);
        if (chain[index] < 0) {
            int error = errno;
            bh_po_fail(result,
                       error == ELOOP || error == ENOTDIR ?
                           BH_PO_REJECTED : BH_PO_UNAVAILABLE,
                       error == ELOOP || error == ENOTDIR ?
                           BH_PO_REPLACED : BH_PO_SYSCALL,
                       error, index);
            goto cleanup;
        }
        opened_count = index + 1;
        if (bh_po_os_fstat(chain[index], &checked[index]) != 0) {
            bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_SYSCALL, errno, index);
            goto cleanup;
        }
        if (!bh_po_same_identity(&entry, &checked[index])) {
            bh_po_fail(result, BH_PO_REJECTED, BH_PO_REPLACED, 0, index);
            goto cleanup;
        }
        if (!bh_po_capture_metadata(&checked[index], &result->records[index],
                                    result, index) ||
            !bh_po_filter_metadata(&checked[index], &snapshot, result,
                                   index, directory) ||
            !bh_po_observe_acl(chain[index], &result->records[index],
                               result, index))
            goto cleanup;
        if (bh_po_os_fstat(chain[index], &repeated) != 0) {
            bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_SYSCALL, errno, index);
            goto cleanup;
        }
        if (!bh_po_match_snapshot(&checked[index], &repeated, result, index) ||
            !bh_po_match_snapshot(&entry, &repeated, result, index)) goto cleanup;
        if (bh_po_os_fstatat(chain[i], names[i], &repeated,
                             AT_SYMLINK_NOFOLLOW) != 0) {
            int error = errno;
            bh_po_fail(result, error == ENOENT ? BH_PO_REJECTED : BH_PO_UNAVAILABLE,
                       error == ENOENT ? BH_PO_REPLACED : BH_PO_SYSCALL,
                       error, index);
            goto cleanup;
        }
        if (!bh_po_match_snapshot(&checked[index], &repeated, result, index) ||
            !bh_po_match_snapshot(&entry, &repeated, result, index)) goto cleanup;
        result->completed_records = index + 1;
    }

    for (uint32_t remaining = opened_count; remaining > 0; --remaining) {
        uint32_t index = remaining - 1;
        if (index != 0) {
            if (bh_po_os_fstatat(chain[index - 1], names[index - 1],
                                 &repeated, AT_SYMLINK_NOFOLLOW) != 0) {
                int error = errno;
                bh_po_fail(result,
                           error == ENOENT ? BH_PO_REJECTED : BH_PO_UNAVAILABLE,
                           error == ENOENT ? BH_PO_REPLACED : BH_PO_SYSCALL,
                           error, index);
                goto cleanup;
            }
            if (!bh_po_match_snapshot(&checked[index], &repeated, result, index))
                goto cleanup;
        }
        if (bh_po_os_fstat(chain[index], &repeated) != 0) {
            bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_SYSCALL, errno, index);
            goto cleanup;
        }
        if (!bh_po_match_snapshot(&checked[index], &repeated, result, index))
            goto cleanup;
    }

    result->outcome = BH_PO_OBSERVED_UNTRUSTED;
    result->reason = BH_PO_NONE;
    result->syscall_errno = 0;
    result->failed_index = UINT32_MAX;

cleanup:
    for (uint32_t remaining = opened_count; remaining > 0; --remaining) {
        uint32_t index = remaining - 1;
        if (bh_po_os_close(chain[index]) != 0) {
            int error = errno;
            if (result->cleanup_failed == 0)
                bh_po_fail(result, BH_PO_UNAVAILABLE, BH_PO_CLEANUP, error, index);
            result->cleanup_failed = 1;
        }
    }
    return result->outcome;
}
