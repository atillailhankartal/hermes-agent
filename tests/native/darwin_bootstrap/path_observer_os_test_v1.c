/* Test-only link-time syscall adapter. It never decides observer outcomes. */
#include "../../../native/darwin_bootstrap/path_observer_os_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <unistd.h>

enum { BH_PO_TEST_ACL_REAL = 0, BH_PO_TEST_ACL_EMPTY = 1,
       BH_PO_TEST_ACL_NULL = 2, BH_PO_TEST_ACL_PRESENT = 3 };
enum { BH_PO_TEST_DUP = 1, BH_PO_TEST_FSTAT = 2,
       BH_PO_TEST_FSTATAT = 3, BH_PO_TEST_OPENAT = 4,
       BH_PO_TEST_ACL_GET = 5, BH_PO_TEST_ACL_VALID = 6,
       BH_PO_TEST_ACL_FIRST = 7, BH_PO_TEST_ACL_FREE = 8,
       BH_PO_TEST_CLOSE = 9 };
enum { BH_PO_TEST_BEFORE_OPEN = 1, BH_PO_TEST_AFTER_OPEN = 2,
       BH_PO_TEST_FINAL_SWEEP = 3 };
enum { BH_PO_TEST_REPLACE_FILE = 1, BH_PO_TEST_REPLACE_SYMLINK = 2,
       BH_PO_TEST_REPLACE_DIRECTORY = 3 };

static int acl_mode = BH_PO_TEST_ACL_EMPTY;
static int acl_error = ENOENT;
static int open_count;
static int open_success_count;
static int close_count;
static int live_owned;
static int max_owned;
static int case_max_owned;
static int acl_get_count;
static int acl_live;
static int acl_alloc_count;
static int acl_free_count;
static int resets_with_live_resources;
static int os_call_count;
static int op_calls[10];
static int fault_op;
static int fault_ordinal;
static int fault_errno;
static int fault_mode;
static int mutation_enabled;
static int mutation_done;
static int after_open_hook_count;
static int after_open_hook_fstat_count;
static int after_open_hook_acl_count;
static int after_open_hook_fstatat_count;
static int mutation_phase;
static int mutation_kind;
static int mutation_parent;
static char mutation_name[256];
static char mutation_saved[256];
static int final_leaf_checks;
static int next_acl_failure;
static int next_call_count;
static int change_after_open_fstat;
static int changed_after_open_fstat;
static int last_opened_fd;
static int root_change_after_acl;
static int root_owned_fd;
static int zero_link_on_leaf;
static int zero_link_on_root;
static int first_null_success;

void bh_po_test_reset(void) {
    if (live_owned != 0 || acl_live != 0) ++resets_with_live_resources;
    acl_mode = BH_PO_TEST_ACL_EMPTY;
    acl_error = ENOENT;
    open_count = 0;
    open_success_count = 0;
    close_count = 0;
    live_owned = 0;
    max_owned = 0;
    acl_get_count = 0;
    acl_live = 0;
    acl_alloc_count = 0;
    acl_free_count = 0;
    os_call_count = 0;
    (void)memset(op_calls, 0, sizeof(op_calls));
    fault_op = 0;
    fault_ordinal = 0;
    fault_errno = 0;
    fault_mode = 0;
    mutation_enabled = 0;
    mutation_done = 0;
    after_open_hook_count = 0;
    after_open_hook_fstat_count = 0;
    after_open_hook_acl_count = 0;
    after_open_hook_fstatat_count = 0;
    mutation_phase = 0;
    mutation_kind = 0;
    mutation_parent = -1;
    (void)memset(mutation_name, 0, sizeof(mutation_name));
    (void)memset(mutation_saved, 0, sizeof(mutation_saved));
    final_leaf_checks = 0;
    next_acl_failure = 0;
    next_call_count = 0;
    change_after_open_fstat = 0;
    changed_after_open_fstat = 0;
    last_opened_fd = -1;
    root_change_after_acl = 0;
    root_owned_fd = -1;
    zero_link_on_leaf = 0;
    zero_link_on_root = 0;
    first_null_success = 0;
}

void bh_po_test_acl(int mode, int error) {
    acl_mode = mode;
    acl_error = error;
}

int bh_po_test_mutate_before_open(int parent, const char *name,
                                  const char *saved) {
    size_t name_len = strlen(name);
    size_t saved_len = strlen(saved);
    if (name_len == 0 || name_len >= sizeof(mutation_name) ||
        saved_len == 0 || saved_len >= sizeof(mutation_saved)) return -1;
    mutation_parent = parent;
    (void)memcpy(mutation_name, name, name_len + 1);
    (void)memcpy(mutation_saved, saved, saved_len + 1);
    mutation_enabled = 1;
    mutation_phase = BH_PO_TEST_BEFORE_OPEN;
    mutation_kind = BH_PO_TEST_REPLACE_FILE;
    return 0;
}

int bh_po_test_set_replacement(int phase, int kind, int parent,
                               const char *name, const char *saved) {
    if (bh_po_test_mutate_before_open(parent, name, saved) != 0) return -1;
    mutation_phase = phase;
    mutation_kind = kind;
    return 0;
}

void bh_po_test_fail(int op, int ordinal, int error, int mode) {
    fault_op = op;
    fault_ordinal = ordinal;
    fault_errno = error;
    fault_mode = mode; /* 0=before OS call, 1=after successful real release. */
}

void bh_po_test_next_acl_eio_after_replacement(void) { next_acl_failure = 1; }
void bh_po_test_change_after_open_fstat(void) { change_after_open_fstat = 1; }
void bh_po_test_root_change_after_acl(void) { root_change_after_acl = 1; }
void bh_po_test_zero_link(int on_root, int on_leaf) {
    zero_link_on_root = on_root;
    zero_link_on_leaf = on_leaf;
}
void bh_po_test_first_null_success(void) { first_null_success = 1; }
int bh_po_test_next_call_count(void) { return next_call_count; }
int bh_po_test_os_call_count(void) { return os_call_count; }
int bh_po_test_op_count(int op) { return op > 0 && op < 10 ? op_calls[op] : -1; }
int bh_po_test_acl_live(void) { return acl_live; }
int bh_po_test_acl_alloc_count(void) { return acl_alloc_count; }
int bh_po_test_acl_free_count(void) { return acl_free_count; }
int bh_po_test_resets_with_live_resources(void) {
    return resets_with_live_resources;
}

int bh_po_test_mutation_done(void) { return mutation_done; }
int bh_po_test_after_open_hook_count(void) { return after_open_hook_count; }
int bh_po_test_after_open_hook_fstat_count(void) {
    return after_open_hook_fstat_count;
}
int bh_po_test_after_open_hook_acl_count(void) {
    return after_open_hook_acl_count;
}
int bh_po_test_after_open_hook_fstatat_count(void) {
    return after_open_hook_fstatat_count;
}
int bh_po_test_open_count(void) { return open_count; }
int bh_po_test_open_success_count(void) { return open_success_count; }
int bh_po_test_close_count(void) { return close_count; }
int bh_po_test_live_owned(void) { return live_owned; }
int bh_po_test_max_owned(void) { return max_owned; }
int bh_po_test_case_max_owned(void) { return case_max_owned; }
int bh_po_test_acl_get_count(void) { return acl_get_count; }

static void note_owned(void) {
    ++live_owned;
    if (live_owned > max_owned) max_owned = live_owned;
    if (live_owned > case_max_owned) case_max_owned = live_owned;
}

static int should_fail(int op) {
    ++os_call_count;
    ++op_calls[op];
    if (fault_op == op && fault_ordinal == op_calls[op] && fault_mode == 0) {
        errno = fault_errno;
        return 1;
    }
    return 0;
}

static int replace_entry(void) {
    int replacement;
    if (renameat(mutation_parent, mutation_name, mutation_parent,
                 mutation_saved) != 0) return -1;
    if (mutation_kind == BH_PO_TEST_REPLACE_SYMLINK) {
        replacement = symlinkat(mutation_saved, mutation_parent, mutation_name);
    } else if (mutation_kind == BH_PO_TEST_REPLACE_DIRECTORY) {
        replacement = mkdirat(mutation_parent, mutation_name, 0700);
    } else {
        int fd = openat(mutation_parent, mutation_name,
                        O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        replacement = fd < 0 ? -1 : close(fd);
    }
    if (replacement == 0) mutation_done = 1;
    return replacement;
}

static int same_directory(int left_fd, int right_fd) {
    struct stat left, right;
    return fstat(left_fd, &left) == 0 && fstat(right_fd, &right) == 0 &&
           left.st_dev == right.st_dev && left.st_ino == right.st_ino;
}

static acl_t present_acl(void) {
    acl_t acl = acl_init(1);
    acl_entry_t entry = NULL;
    acl_permset_t permissions = NULL;
    unsigned char subject_guid[16] = {1};
    if (acl == NULL) return NULL;
    if (acl_create_entry(&acl, &entry) == 0 &&
        acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0 &&
        acl_set_qualifier(entry, subject_guid) == 0 &&
        acl_get_permset(entry, &permissions) == 0 &&
        acl_add_perm(permissions, ACL_READ_DATA) == 0 &&
        acl_valid(acl) == 0) return acl;
    int saved_errno = errno;
    (void)acl_free(acl);
    errno = saved_errno;
    return NULL;
}

int bh_po_os_dup_cloexec(int fd) {
    if (should_fail(BH_PO_TEST_DUP)) return -1;
    int owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (owned >= 0) {
        note_owned();
        root_owned_fd = owned;
    }
    return owned;
}

int bh_po_os_fstat(int fd, struct stat *out) {
    if (should_fail(BH_PO_TEST_FSTAT)) return -1;
    int rc = fstat(fd, out);
    if (rc == 0 && ((zero_link_on_root && fd == root_owned_fd) ||
                    (zero_link_on_leaf && fd == last_opened_fd)))
        out->st_nlink = 0;
    if (rc == 0 && change_after_open_fstat && !changed_after_open_fstat &&
        fd == last_opened_fd) {
        if (fchmod(fd, 0640) != 0) return -1;
        changed_after_open_fstat = 1;
    }
    return rc;
}

int bh_po_os_fstatat(int parent, const char *name, struct stat *out, int flags) {
    if (should_fail(BH_PO_TEST_FSTATAT)) return -1;
    if (mutation_enabled && mutation_phase == BH_PO_TEST_AFTER_OPEN &&
        !mutation_done && last_opened_fd >= 0 &&
        same_directory(parent, mutation_parent) &&
        strcmp(name, mutation_name) == 0) {
        ++after_open_hook_count;
        after_open_hook_fstat_count = op_calls[BH_PO_TEST_FSTAT];
        after_open_hook_acl_count = acl_get_count;
        after_open_hook_fstatat_count = op_calls[BH_PO_TEST_FSTATAT];
        if (replace_entry() != 0) return -1;
    }
    if (mutation_enabled && mutation_phase == BH_PO_TEST_FINAL_SWEEP &&
        strcmp(name, "leaf") == 0 && ++final_leaf_checks == 3 &&
        !mutation_done && replace_entry() != 0) return -1;
    return fstatat(parent, name, out, flags);
}

int bh_po_os_openat(int parent, const char *name, int flags) {
    ++open_count;
    if (should_fail(BH_PO_TEST_OPENAT)) return -1;
    if (mutation_enabled && !mutation_done &&
        mutation_phase == BH_PO_TEST_BEFORE_OPEN &&
        same_directory(parent, mutation_parent) &&
        strcmp(name, mutation_name) == 0 &&
        replace_entry() != 0) return -1;
    int owned = openat(parent, name, flags);
    if (owned >= 0) {
        ++open_success_count;
        note_owned();
        last_opened_fd = owned;
    }
    return owned;
}

acl_t bh_po_os_acl_get(int fd, acl_type_t type) {
    if (should_fail(BH_PO_TEST_ACL_GET)) return NULL;
    ++acl_get_count;
    if (next_acl_failure && mutation_done) {
        ++next_call_count;
        errno = EIO;
        return NULL;
    }
    if (acl_mode == BH_PO_TEST_ACL_NULL) {
        errno = acl_error;
        return NULL;
    }
    acl_t acl = acl_mode == BH_PO_TEST_ACL_REAL ?
        acl_get_fd_np(fd, type) :
        (acl_mode == BH_PO_TEST_ACL_PRESENT ? present_acl() : acl_init(0));
    if (root_change_after_acl && fd == root_owned_fd) {
        if (fchmod(fd, 0710) != 0) {
            if (acl != NULL) (void)acl_free(acl);
            return NULL;
        }
        root_change_after_acl = 0;
    }
    if (acl != NULL) {
        ++acl_live;
        ++acl_alloc_count;
    }
    return acl;
}

int bh_po_os_acl_valid(acl_t acl) {
    if (should_fail(BH_PO_TEST_ACL_VALID)) return -1;
    return acl_valid(acl);
}

int bh_po_os_acl_first(acl_t acl, int entry_id, acl_entry_t *out) {
    if (should_fail(BH_PO_TEST_ACL_FIRST)) return -1;
    if (first_null_success) {
        *out = NULL;
        return 0;
    }
    return acl_get_entry(acl, entry_id, out);
}

int bh_po_os_acl_free(void *acl) {
    if (should_fail(BH_PO_TEST_ACL_FREE)) return -1;
    int rc = acl_free(acl);
    if (rc == 0) {
        --acl_live;
        ++acl_free_count;
    }
    if (rc == 0 && fault_op == BH_PO_TEST_ACL_FREE &&
        fault_mode == 1 && fault_ordinal == op_calls[BH_PO_TEST_ACL_FREE]) {
        errno = fault_errno;
        return -1;
    }
    return rc;
}

int bh_po_os_close(int fd) {
    ++close_count;
    if (should_fail(BH_PO_TEST_CLOSE)) return -1;
    int rc = close(fd);
    if (rc == 0) --live_owned;
    if (rc == 0 && fault_op == BH_PO_TEST_CLOSE &&
        fault_mode == 1 && fault_ordinal == op_calls[BH_PO_TEST_CLOSE]) {
        errno = fault_errno;
        return -1;
    }
    return rc;
}
