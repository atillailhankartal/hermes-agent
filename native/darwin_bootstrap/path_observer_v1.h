#ifndef BH_PATH_OBSERVER_V1_H
#define BH_PATH_OBSERVER_V1_H

#include <stdint.h>

#define BH_PO_ABI_V1 1u
#define BH_PO_MAX_COMPONENTS_V1 16u
#define BH_PO_MAX_COMPONENT_BYTES_V1 255u
#define BH_PO_MAX_TOTAL_BYTES_V1 2048u

enum { BH_PO_OBSERVED_UNTRUSTED = 1, BH_PO_REJECTED = 2, BH_PO_UNAVAILABLE = 3 };
enum { BH_PO_LEAF_REGULAR = 1, BH_PO_LEAF_DIRECTORY = 2 };
enum {
    BH_PO_ACL_UNOBSERVED = 0, BH_PO_ACL_EMPTY_VALIDATED = 1,
    BH_PO_ACL_PRESENT = 2, BH_PO_ACL_GET_ENOENT_UNCONFIRMED = 3,
    BH_PO_ACL_ERROR = 4
};
enum {
    BH_PO_NONE = 0, BH_PO_BAD_ARGUMENT = 1, BH_PO_BAD_FD = 2,
    BH_PO_BAD_TYPE = 3, BH_PO_SYMLINK = 4, BH_PO_OWNER = 5,
    BH_PO_GROUP = 6, BH_PO_WRITABLE = 7, BH_PO_SPECIAL_MODE = 8,
    BH_PO_LINK_COUNT = 9, BH_PO_REPLACED = 10, BH_PO_CHANGED = 11,
    BH_PO_ACL_PRESENT_REASON = 12, BH_PO_ACL_UNKNOWN = 13,
    BH_PO_SYSCALL = 14, BH_PO_CLEANUP = 15, BH_PO_ABI = 16
};

typedef struct {
    uint32_t length;
    unsigned char bytes[BH_PO_MAX_COMPONENT_BYTES_V1];
} bh_po_component_v1;

typedef struct {
    uint32_t abi_version, struct_size, component_count, leaf_kind;
    uint32_t expected_uid, expected_gid;
    uint32_t forbid_owner_write;
    uint32_t reserved;
    bh_po_component_v1 components[BH_PO_MAX_COMPONENTS_V1];
} bh_po_request_v1;

typedef struct {
    uint64_t device, inode, link_count;
    uint32_t uid, gid, mode, file_type, acl_state;
    int32_t acl_errno;
} bh_po_metadata_v1;

typedef struct {
    uint32_t abi_version, struct_size, outcome, reason;
    uint32_t installed_authority, ready;
    uint32_t completed_records, failed_index;
    int32_t syscall_errno;
    uint32_t cleanup_failed;
    bh_po_metadata_v1 records[BH_PO_MAX_COMPONENTS_V1 + 1u];
} bh_po_result_v1;

uint32_t bh_po_observe_v1(int borrowed_root_fd,
                          const bh_po_request_v1 *request,
                          bh_po_result_v1 *result);

#endif
