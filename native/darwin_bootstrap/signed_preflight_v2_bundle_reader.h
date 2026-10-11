#ifndef BH_SIGNED_PREFLIGHT_V2_BUNDLE_READER_H
#define BH_SIGNED_PREFLIGHT_V2_BUNDLE_READER_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#define BH_V2_BUNDLE_ABI 1u
enum bh_v2_bundle_status {
    BH_V2_BUNDLE_REJECTED = 0,
    BH_V2_BUNDLE_OBSERVED_UNTRUSTED = 1,
    BH_V2_BUNDLE_UNAVAILABLE = 2
};
struct bh_v2_bundle_expectation {
    uint32_t abi_version;
    size_t struct_size;
    dev_t device;
    ino_t inode;
    uid_t uid;
    gid_t gid;
};
struct bh_v2_bundle_result {
    enum bh_v2_bundle_status status;
    uint8_t *policy;
    size_t policy_len;
    uint8_t *signature;
    size_t signature_len;
    uint8_t *manifest;
    size_t manifest_len;
};
/* expected must remain readable/unchanged, and disjoint from out. The borrowed
 * FD must retain the same open description and flags for this ENTIRE synchronous
 * call. Initially out must be zero-initialized; dispose successful results before
 * reuse. Rejected reuse preserves the previous result. No authority is conveyed:
 * parent ancestry, writer exclusion and transient ABA are not established. */
enum bh_v2_bundle_status bh_v2_bundle_observe(int borrowed_version_dir_fd,
    const struct bh_v2_bundle_expectation *expected,
    struct bh_v2_bundle_result *out);
/* Idempotent on initialized/returned results only, never on forged pointers. */
void bh_v2_bundle_result_dispose(struct bh_v2_bundle_result *out);
#endif
