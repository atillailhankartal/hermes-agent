#include "../../../native/darwin_bootstrap/path_observer_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct fixture {
    char path[64];
    int root_fd;
};
static bh_po_result_v1 last_result;

static int make_fixture(struct fixture *fixture) {
    (void)memset(fixture, 0, sizeof(*fixture));
    fixture->root_fd = -1;
    (void)strcpy(fixture->path, "/private/tmp/bh-po-real-XXXXXX");
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
        if (unlinkat(fixture->root_fd, "leaf", 0) != 0) okay = 0;
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

static int observed(const bh_po_result_v1 *result, uint32_t status, uint32_t reason) {
    return result->abi_version == BH_PO_ABI_V1 &&
           result->struct_size == sizeof(*result) &&
           result->outcome == status && result->reason == reason &&
           result->installed_authority == 0 && result->ready == 0;
}

static int invoke(int fd, bh_po_request_v1 *request, bh_po_result_v1 *result,
                  uint32_t outcome, uint32_t reason) {
    uint32_t returned = bh_po_observe_v1(fd, request, result);
    last_result = *result;
    return returned == result->outcome && observed(result, outcome, reason);
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
    if (!invoke(fixture->root_fd, &request, &baseline,
                BH_PO_UNAVAILABLE, BH_PO_ACL_UNKNOWN)) return 0;
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
        uint32_t returned = bh_po_observe_v1(
            fixture->root_fd,
            (const bh_po_request_v1 *)(const void *)(storage + request_offset),
            (bh_po_result_v1 *)(void *)(storage + result_offset));
        bh_po_result_v1 actual;
        (void)memcpy(&actual, storage + result_offset, sizeof(actual));
        free(storage);
        last_result = actual;
        if (!aligned || !overlaps || returned != baseline.outcome ||
            !same_result(&baseline, &actual)) return 0;
    }
    bh_po_result_v1 branch_result;
    request.abi_version = BH_PO_ABI_V1 + 1;
    if (!invoke(fixture->root_fd, &request, &branch_result,
                BH_PO_REJECTED, BH_PO_ABI)) return 0;
    request.abi_version = BH_PO_ABI_V1;
    if (bh_po_observe_v1(fixture->root_fd, &request, NULL) != BH_PO_REJECTED ||
        !invoke(fixture->root_fd, NULL, &branch_result,
                BH_PO_REJECTED, BH_PO_BAD_ARGUMENT)) return 0;
    last_result = baseline;
    return 1;
}

static int run_args(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result;
    int okay = bh_po_observe_v1(fixture->root_fd, &request, NULL) ==
               BH_PO_REJECTED;
    okay &= invoke(fixture->root_fd, NULL, &result,
                   BH_PO_REJECTED, BH_PO_BAD_ARGUMENT);
    request.abi_version = 2;
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_ABI);
    request = request_for(fixture);
    request.struct_size--;
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_ABI);
    request = request_for(fixture);
    request.component_count = 0;
    okay &= invoke(fixture->root_fd, &request, &result,
                   BH_PO_REJECTED, BH_PO_BAD_ARGUMENT);
    return okay;
}

static int run_raw_metadata(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    struct stat root;
    if (fstat(fixture->root_fd, &root) != 0) return 0;
    return invoke(fixture->root_fd, &request, &result,
                  BH_PO_UNAVAILABLE, BH_PO_ACL_UNKNOWN) &&
           result.completed_records == 0 &&
           result.records[0].acl_state == BH_PO_ACL_GET_ENOENT_UNCONFIRMED &&
           result.records[0].acl_errno == ENOENT &&
           result.records[0].device == (uint64_t)root.st_dev &&
           result.records[0].inode == (uint64_t)root.st_ino &&
           result.records[0].link_count == (uint64_t)root.st_nlink &&
           result.records[0].uid == (uint32_t)root.st_uid &&
           result.records[0].gid == (uint32_t)root.st_gid &&
           result.records[0].mode == (uint32_t)(root.st_mode & 07777) &&
           result.records[0].file_type == (uint32_t)(root.st_mode & S_IFMT);
}

static int run_owner_group(const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    request.expected_uid = request.expected_uid == UINT32_MAX ?
        request.expected_uid - 1 : request.expected_uid + 1;
    int okay = invoke(fixture->root_fd, &request, &result,
                      BH_PO_REJECTED, BH_PO_OWNER);
    request = request_for(fixture);
    request.expected_gid = request.expected_gid == UINT32_MAX ?
        request.expected_gid - 1 : request.expected_gid + 1;
    return okay && invoke(fixture->root_fd, &request, &result,
                          BH_PO_REJECTED, BH_PO_GROUP);
}

static int run_case(const char *name, const struct fixture *fixture) {
    bh_po_request_v1 request = request_for(fixture);
    bh_po_result_v1 result = {0};
    struct stat before, after;
    int flags_before = fcntl(fixture->root_fd, F_GETFL);
    int fd_flags_before = fcntl(fixture->root_fd, F_GETFD);
    if (fstat(fixture->root_fd, &before) != 0 || flags_before < 0 || fd_flags_before < 0)
        return 0;
    uint32_t returned;
    int okay = 0;
    if (strcmp(name, "args") == 0) {
        okay = run_args(fixture);
    } else if (strcmp(name, "alias") == 0) {
        okay = run_alias(fixture);
    } else if (strcmp(name, "raw-metadata") == 0) {
        okay = run_raw_metadata(fixture);
    } else if (strcmp(name, "owner-group") == 0) {
        okay = run_owner_group(fixture);
    } else if (strcmp(name, "ordinary-acl-enoent") == 0) {
        returned = bh_po_observe_v1(fixture->root_fd, &request, &result);
        last_result = result;
        okay = observed(&result, BH_PO_UNAVAILABLE, BH_PO_ACL_UNKNOWN) &&
               result.records[0].acl_state == BH_PO_ACL_GET_ENOENT_UNCONFIRMED &&
               result.records[0].acl_errno == ENOENT && returned == result.outcome;
    } else if (strcmp(name, "fd") == 0) {
        returned = bh_po_observe_v1(-1, &request, &result);
        okay = observed(&result, BH_PO_REJECTED, BH_PO_BAD_FD) && returned == result.outcome;
        returned = bh_po_observe_v1(AT_FDCWD, &request, &result);
        okay = okay && observed(&result, BH_PO_REJECTED, BH_PO_BAD_FD) &&
               returned == result.outcome;
        int closed = dup(fixture->root_fd);
        if (closed < 0 || close(closed) != 0) return 0;
        okay &= invoke(closed, &request, &result, BH_PO_REJECTED, BH_PO_BAD_FD);
        int regular = openat(fixture->root_fd, "leaf", O_RDONLY | O_CLOEXEC);
        if (regular < 0) return 0;
        okay &= invoke(regular, &request, &result, BH_PO_REJECTED, BH_PO_BAD_TYPE);
        if (close(regular) != 0) okay = 0;
    } else if (strcmp(name, "no-authority") == 0) {
        returned = bh_po_observe_v1(fixture->root_fd, &request, &result);
        last_result = result;
        okay = returned == result.outcome &&
               observed(&result, BH_PO_UNAVAILABLE, BH_PO_ACL_UNKNOWN) &&
               result.records[0].acl_state == BH_PO_ACL_GET_ENOENT_UNCONFIRMED &&
               result.records[0].acl_errno == ENOENT;
    } else {
        return 0;
    }
    return okay && fstat(fixture->root_fd, &after) == 0 &&
           before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           flags_before == fcntl(fixture->root_fd, F_GETFL) &&
           fd_flags_before == fcntl(fixture->root_fd, F_GETFD);
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    struct fixture fixture;
    if (!make_fixture(&fixture)) {
        (void)fprintf(stderr, "SETUP_FAIL case=%s errno=%d\n", argv[1], errno);
        (void)clean_fixture(&fixture);
        return 2;
    }
    int okay = run_case(argv[1], &fixture);
    int cleaned = clean_fixture(&fixture);
    (void)printf("case=%s status=%s cleanup=%s outcome=%u reason=%u errno=%d "
                 "cleanup_failed=%u authority=%u ready=%u\n", argv[1],
                 okay ? "PASS" : "FAIL", cleaned ? "PASS" : "FAIL",
                 last_result.outcome, last_result.reason, last_result.syscall_errno,
                 last_result.cleanup_failed, last_result.installed_authority,
                 last_result.ready);
    return okay && cleaned ? 0 : 1;
}
