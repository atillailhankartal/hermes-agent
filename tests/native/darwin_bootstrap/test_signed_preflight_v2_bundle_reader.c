#include "signed_preflight_v2_bundle_reader.h"
#include "signed_preflight_v2_crypto.h"
#include "bundle_reader_os_test.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifndef BH_BUNDLE_FIXTURES
#define BH_BUNDLE_FIXTURES "tests/native/darwin_bootstrap/fixtures/signed_preflight_v2"
#endif
#ifndef BH_BUNDLE_PREFLIGHT
#define BH_BUNDLE_PREFLIGHT "/nonexistent-preflight"
#endif
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "assertion line=%d: %s\n", __LINE__, #x); ok = 0; } } while (0)
static const char *const leaves[] = {"policy.v2.bin", "policy.v2.sig", "release.v2.bin"};
struct fixture { int d, w[3]; char path[128]; unsigned char *bytes[3]; size_t len[3]; };
static unsigned char *load(const char *name, size_t *len) {
    char path[1024];
    if (snprintf(path, sizeof(path), "%s/%s", BH_BUNDLE_FIXTURES, name) >= (int)sizeof(path)) abort();
    FILE *f = fopen(path, "rb"); if (!f) abort();
    if (fseek(f, 0, SEEK_END)) abort();
    long n = ftell(f); if (n <= 0) abort();
    *len = (size_t)n; rewind(f);
    unsigned char *p = malloc(*len); if (!p || fread(p, 1, *len, f) != *len) abort();
    if (fclose(f)) abort();
    return p;
}
static void setup(struct fixture *f, int c) {
    memset(f, 0, sizeof(*f)); strcpy(f->path, "/tmp/bh-bundle-case-XXXXXX");
    if (!mkdtemp(f->path)) abort();
    f->d = open(f->path, O_RDONLY|O_DIRECTORY|O_CLOEXEC); if (f->d < 0) abort();
    const char *names[] = {"S2-policy.bin", "S2-signature.raw", "S2-manifest.bin"};
    if (c == 2) { names[0] = "H-MISSING-policy.bin"; names[1] = "H-MISSING-signature.raw"; names[2] = "H-MISSING-manifest.bin"; }
    if (c == 50) names[1] = "H-MISSING-signature.raw";
    if (c == 51) names[2] = "H-MISSING-manifest.bin";
    for (int i = 0; i < 3; ++i) {
        f->bytes[i] = load(names[i], &f->len[i]);
        f->w[i] = openat(f->d, leaves[i], O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC, 0600);
        if (f->w[i] < 0 || write(f->w[i], f->bytes[i], f->len[i]) != (ssize_t)f->len[i] ||
            fchmod(f->w[i], 0400)) abort();
    }
}
static void cleanup(struct fixture *f) {
    if (fchmod(f->d, 0700)) abort();
    const char *extra[] = {"alias", "POLICY.V2.BIN", "POLICY.V2.SIG", "RELEASE.V2.BIN", "policy.v1.bin", "policy.v1.sig", "release.v1.bin"};
    for (int i = 0; i < 3; ++i) {
        if (unlinkat(f->d, leaves[i], 0)) (void)unlinkat(f->d, leaves[i], AT_REMOVEDIR);
        close(f->w[i]); free(f->bytes[i]);
    }
    for (size_t i = 0; i < sizeof(extra)/sizeof(*extra); ++i) unlinkat(f->d, extra[i], 0);
    close(f->d); if (rmdir(f->path)) abort();
}
static int expected_status(int c) {
    if (c <= 6 || (c >= 49 && c <= 51) || c == 63) return 1;
    if ((c >= 12 && c <= 16) || (c >= 28 && c <= 30) || c == 37 || c == 38 ||
        (c >= 46 && c <= 48) || c == 58 || c == 59) return 2;
    return 0;
}
static int observe_case(int c, int variant) {
    int ok = 1;
    struct fixture f; setup(&f, c);
    struct stat original, after;
    if (fstat(f.d, &original)) abort();
    struct bh_v2_bundle_expectation e = {BH_V2_BUNDLE_ABI, sizeof(e), original.st_dev, original.st_ino, original.st_uid, original.st_gid};
    struct bh_v2_bundle_result out = {0};
    if (c == 3) { if (linkat(f.d, leaves[1], f.d, "alias", 0)) abort(); if (unlinkat(f.d, "alias", 0)) abort(); int x = openat(f.d, "alias", O_CREAT|O_WRONLY, 0600); if (x < 0) abort(); close(x); }
    if (c == 10) ++e.inode;
    if (c == 11) ++e.uid;
    if (c >= 12 && c <= 14) { if (unlinkat(f.d, leaves[c - 12], 0)) abort(); }
    if (c == 15 || c == 16) {
        const char *wrong[] = {"POLICY.V2.BIN", "POLICY.V2.SIG", "RELEASE.V2.BIN"};
        const char *old[] = {"policy.v1.bin", "policy.v1.sig", "release.v1.bin"};
        for (int i = 0; i < 3; ++i) if (renameat(f.d, leaves[i], f.d, c == 15 ? wrong[i] : old[i])) abort();
    }
    if (c == 15) {
        struct stat probe;
        errno = 0;
        int lookup = fstatat(f.d, leaves[0], &probe, AT_SYMLINK_NOFOLLOW);
        fprintf(stderr, "CASE_INSENSITIVE_VOLUME wrong_case_lookup=%d errno=%d\n", lookup, errno);
    }
    if (c >= 17 && c <= 19) { int i = c - 17; if (unlinkat(f.d, leaves[i], 0) || symlinkat("alias", f.d, leaves[i])) abort(); }
    if (c == 20 && linkat(f.d, leaves[0], f.d, "alias", 0)) abort();
    if (c == 21 || c == 22) { if (unlinkat(f.d, leaves[0], 0)) abort(); if (c == 21 ? mkdirat(f.d, leaves[0], 0500) : mkfifoat(f.d, leaves[0], 0400)) abort(); }
    if (c == 23 && fchmod(f.w[0], 0400 | (0200 >> (variant * 3)))) abort();
    if (c == 24 && fchmod(f.w[0], 0400 | S_ISUID)) abort();
    if (c >= 31 && c <= 36) {
        int i = c == 32 || c == 36 ? 2 : c == 33 || c == 34 ? 1 : 0;
        off_t sizes[] = {48, 16, 63, 65, 65585, 65553};
        if (ftruncate(f.w[i], sizes[c - 31])) abort();
    }
    if (fchmod(f.d, c == 55 ? (0500 | (0200 >> (variant * 3))) : 0500)) abort();
    if (c == 60) ++e.abi_version;
    if (c == 61) --e.struct_size;
    int flags = fcntl(f.d, F_GETFL), descriptor_flags = fcntl(f.d, F_GETFD);
    off_t offset = lseek(f.d, 0, SEEK_CUR);
    br_test_reset(c, variant, f.d, f.w);
    enum bh_v2_bundle_status actual;
    if (c == 64) {
        union { max_align_t align; unsigned char bytes[256]; } storage;
        memset(storage.bytes, 0xa5, sizeof(storage.bytes));
        unsigned char before[256]; memcpy(before, storage.bytes, sizeof(before));
        actual = bh_v2_bundle_observe(f.d, (const void *)storage.bytes, (void *)storage.bytes);
        REQUIRE(memcmp(before, storage.bytes, sizeof(before)) == 0);
    } else if (c == 65) {
        out.policy = (void *)(uintptr_t)1; out.policy_len = 12;
        struct bh_v2_bundle_result before = out;
        actual = bh_v2_bundle_observe(f.d, &e, &out);
        REQUIRE(memcmp(&before, &out, sizeof(out)) == 0);
        memset(&out, 0, sizeof(out));
    } else {
        actual = bh_v2_bundle_observe(c == 9 ? -1 : f.d, c == 8 ? NULL : &e, c == 7 ? NULL : &out);
    }
    REQUIRE((int)actual == expected_status(c));
    fprintf(stderr, "case=%d variant=%d expected=%d actual=%d acl_mode=%s calls=%d opens=%d closes=%d owned=%d alloc=%d live=%d reads=%d\n",
        c, variant, expected_status(c), actual, c == 28 ? "real-passthrough" : "test-validated-empty-or-fault", br_test.calls, br_test.opens, br_test.closes, br_test.owned, br_test.allocs, br_test.live, br_test.reads);
    REQUIRE(fstat(f.d, &after) == 0 && original.st_dev == after.st_dev && original.st_ino == after.st_ino);
    REQUIRE(fcntl(f.d, F_GETFL) == flags && fcntl(f.d, F_GETFD) == descriptor_flags && lseek(f.d, 0, SEEK_CUR) == offset);
    REQUIRE(br_test.owned == 0 && br_test.acl_live == 0 && br_test.failure == 0);
    fprintf(stderr, "resources case=%d flags=%x,%x,%x acl_gets=%d acl_frees=%d frees=%d second_reads=%d,%d,%d\n",
        c, br_test.flags[0], br_test.flags[1], br_test.flags[2], br_test.acl_gets,
        br_test.acl_frees, br_test.frees, br_test.read_counts[0], br_test.read_counts[1], br_test.read_counts[2]);
    if (c == 7 || c == 8 || c == 60 || c == 61 || c == 64 || c == 65) REQUIRE(br_test.calls == 0 && br_test.allocs == 0 && br_test.frees == 0);
    if (c == 35 || c == 36 || c == 62) REQUIRE(br_test.allocs == 0);
    if (c >= 54 && c <= 57) REQUIRE(br_test.opens == 0);
    if (c == 58 || c == 46 || c == 30 || c == 29) REQUIRE(br_test.opens >= 1);
    if (c == 47 || c == 59) REQUIRE(br_test.opens == 3);
    if (c == 48) { REQUIRE(br_test.ambiguous >= 0); if (br_test.ambiguous >= 0) { REQUIRE(fcntl(br_test.ambiguous, F_GETFD) >= 0); close(br_test.ambiguous); } }
    if (c == 53 || c == 62 || (c >= 39 && c <= 43)) REQUIRE(br_test.mutation == 1);
    if (actual == BH_V2_BUNDLE_OBSERVED_UNTRUSTED) {
        if (c == 5) for (int i = 0; i < 3; ++i) { if (fchmod(f.d, 0700) || unlinkat(f.d, leaves[i], 0)) abort(); }
        REQUIRE(out.policy_len == f.len[0] && out.signature_len == f.len[1] && out.manifest_len == f.len[2]);
        REQUIRE(out.policy && out.signature && out.manifest);
        if (out.policy && out.signature && out.manifest) {
            REQUIRE(memcmp(out.policy, f.bytes[0], f.len[0]) == 0 && memcmp(out.signature, f.bytes[1], f.len[1]) == 0 && memcmp(out.manifest, f.bytes[2], f.len[2]) == 0);
        }
        REQUIRE(br_test.opens == 3);
        if (c == 63) {
            struct bh_v2_bundle_result saved = out; int calls = br_test.calls, allocs = br_test.allocs;
            REQUIRE(bh_v2_bundle_observe(f.d, &e, &out) == BH_V2_BUNDLE_REJECTED);
            REQUIRE(memcmp(&saved, &out, sizeof(out)) == 0 && calls == br_test.calls && allocs == br_test.allocs);
            REQUIRE(memcmp(out.policy, f.bytes[0], f.len[0]) == 0 && memcmp(out.signature, f.bytes[1], f.len[1]) == 0 && memcmp(out.manifest, f.bytes[2], f.len[2]) == 0);
        }
        if (c == 2 || (c >= 49 && c <= 51)) {
            size_t n; unsigned char *key = load("S2-public-key.x963", &n);
            struct bh_v2_crypto_result r = bh_v2_check_signed_pair(out.policy, out.policy_len, out.manifest, out.manifest_len, out.signature, out.signature_len, key, n);
            if (c == 49) REQUIRE(r.status == BH_V2_CRYPTO_VALID_ONLY);
            if (c == 50) REQUIRE(r.status == BH_V2_CRYPTO_DENY_SIGNATURE);
            if (c == 51) REQUIRE(r.status == BH_V2_CRYPTO_DENY_STRUCTURE && r.structure_reason == BH_V2_DENY_MANIFEST_DIGEST);
            if (c == 2) REQUIRE(r.status == BH_V2_CRYPTO_DENY_STRUCTURE);
            free(key);
        }
    } else REQUIRE(out.policy == NULL && out.signature == NULL && out.manifest == NULL && out.policy_len == 0 && out.signature_len == 0 && out.manifest_len == 0 && br_test.live == 0);
    bh_v2_bundle_result_dispose(&out);
    int frees = br_test.frees;
    bh_v2_bundle_result_dispose(&out);
    REQUIRE(br_test.live == 0 && br_test.frees == frees && out.status == 0 && out.policy == NULL && out.signature == NULL && out.manifest == NULL);
    cleanup(&f); return ok;
}
static int preflight_case(void) {
    int p[2]; if (pipe(p)) abort(); pid_t child = fork(); if (child < 0) abort();
    if (!child) { close(p[0]); if (dup2(p[1], STDOUT_FILENO) < 0) _exit(111); close(p[1]); execl(BH_BUNDLE_PREFLIGHT, BH_BUNDLE_PREFLIGHT, (char *)NULL); _exit(112); }
    close(p[1]); char b[128] = {0}; ssize_t n = read(p[0], b, sizeof(b) - 1); close(p[0]);
    int status; if (waitpid(child, &status, 0) != child) abort();
    return n > 0 && strcmp(b, "UNAVAILABLE reason=no_policy synthetic=false installed_authority=false\n") == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 69;
}
static double monotonic(void) { struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) abort(); return t.tv_sec + t.tv_nsec / 1e9; }
static int bounded_case(int c) {
    fflush(NULL); pid_t child = fork(); if (child < 0) abort();
    if (!child) _exit(observe_case(c, 0) ? 0 : 1);
    double deadline = monotonic() + 3.0;
    for (;;) {
        int s; pid_t r = waitpid(child, &s, WNOHANG);
        if (r == child) return WIFEXITED(s) && WEXITSTATUS(s) == 0;
        if (r < 0) abort();
        if (monotonic() >= deadline) { kill(child, SIGKILL); waitpid(child, &s, 0); fprintf(stderr, "FAIL timeout case=%d\n", c); return 0; }
        struct timespec pause = {0, 10000000}; nanosleep(&pause, NULL);
    }
}
static const char *const cases[] = {
    "ObserveBundle_WhenS2FixedLeavesAreStable_ReturnsObservedUntrusted",
    "ObserveBundle_WhenHMissingFixedLeavesAreStable_ReturnsObservedUntrusted",
    "ObserveBundle_WhenExtraAlternateLeafExists_UsesOnlyFrozenNames",
    "ObserveBundle_WhenBorrowedDirectoryFdIsUsed_PreservesFdFlagsOffsetAndOwnership",
    "ObserveBundle_WhenFilesAreUnlinkedAfterReturn_KeepsOwnedSnapshotBytes",
    "ObserveBundle_WhenResultIsDisposedTwice_ReleasesOwnedBuffersOnce",
    "ObserveBundle_WhenResultPointerIsNull_RejectsBeforeOsCalls",
    "ObserveBundle_WhenExpectationPointerIsNull_RejectsBeforeOsCalls",
    "ObserveBundle_WhenDirectoryFdIsInvalid_RejectsWithoutClosingCallerFd",
    "ObserveBundle_WhenExpectedDirectoryIdentityDiffers_Rejects",
    "ObserveBundle_WhenExpectedDirectoryOwnerDiffers_Rejects",
    "ObserveBundle_WhenPolicyLeafIsMissing_ReturnsUnavailable",
    "ObserveBundle_WhenSignatureLeafIsMissing_ReturnsUnavailable",
    "ObserveBundle_WhenManifestLeafIsMissing_ReturnsUnavailable",
    "ObserveBundle_WhenOnlyWrongCaseNamesExist_ReturnsUnavailable",
    "ObserveBundle_WhenOnlyV1LeavesExist_ReturnsUnavailable",
    "ObserveBundle_WhenPolicyLeafIsSymlinked_Rejects",
    "ObserveBundle_WhenSignatureLeafIsSymlinked_Rejects",
    "ObserveBundle_WhenManifestLeafIsSymlinked_Rejects",
    "ObserveBundle_WhenLeafHasSecondHardLink_Rejects",
    "ObserveBundle_WhenLeafIsDirectory_Rejects",
    "ObserveBundle_WhenLeafIsFifo_RejectsWithoutBlocking",
    "ObserveBundle_WhenLeafHasAnyWriteBit_Rejects",
    "ObserveBundle_WhenLeafHasSpecialModeBits_Rejects",
    "ObserveBundle_WhenLeafOwnerDiffers_Rejects",
    "ObserveBundle_WhenLeafGroupDiffers_Rejects",
    "ObserveBundle_WhenExtendedAclGrantsAccess_Rejects",
    "ObserveBundle_WhenRealAclObservationIsUnknown_ReturnsUnavailable",
    "ObserveBundle_WhenAclGetOrValidFails_ReturnsUnavailable",
    "ObserveBundle_WhenAclReleaseFails_ReturnsUnavailable",
    "ObserveBundle_WhenPolicyIsHeaderOnly_RejectsBound",
    "ObserveBundle_WhenManifestIsHeaderOnly_RejectsBound",
    "ObserveBundle_WhenSignatureIs63Bytes_RejectsBound",
    "ObserveBundle_WhenSignatureIs65Bytes_RejectsBound",
    "ObserveBundle_WhenPolicyExceeds65584_RejectsBeforeAllocation",
    "ObserveBundle_WhenManifestExceeds65552_RejectsBeforeAllocation",
    "ObserveBundle_WhenPreadReturnsEarlyEof_ReturnsUnavailable",
    "ObserveBundle_WhenPreadFailsWithEio_ReturnsUnavailable",
    "ObserveBundle_WhenPolicyChangesInPlaceBetweenReads_Rejects",
    "ObserveBundle_WhenSignatureChangesInPlaceBetweenReads_Rejects",
    "ObserveBundle_WhenManifestChangesInPlaceBetweenReads_Rejects",
    "ObserveBundle_WhenPathReplacedAfterOpenWithEqualBytes_Rejects",
    "ObserveBundle_WhenPathReplacedAfterOpenWithSymlink_Rejects",
    "ObserveBundle_WhenDirectoryMetadataChangesBeforeFinalReadback_Rejects",
    "ObserveBundle_WhenLeafAclChangesBeforeFinalReadback_Rejects",
    "ObserveBundle_WhenSecondLeafOpenFails_CleansFirstFd",
    "ObserveBundle_WhenAllocationFails_CleansAllOwnedFds",
    "ObserveBundle_WhenOwnedFdCloseFails_ReturnsUnavailable",
    "ObserveBundle_WhenS2SnapshotIsCheckedWithTestKey_ReturnsCryptoValidOnly",
    "ObserveBundle_WhenPolicyAndSignatureComeFromDifferentPairs_DeniesCrypto",
    "ObserveBundle_WhenManifestIsSubstituted_DeniesDigest",
    "ObserveBundle_WhenPreflightExecutableRuns_RemainsNoPolicyExit69",
    "ObserveBundle_WhenRegularLeafBecomesFifoBeforeOpen_RejectsWithoutHanging",
    "ObserveBundle_WhenDirectoryGroupDiffers_Rejects",
    "ObserveBundle_WhenDirectoryHasAnyWriteBit_Rejects",
    "ObserveBundle_WhenDirectoryHasSpecialModeBits_Rejects",
    "ObserveBundle_WhenDirectoryAclHasEntry_Rejects",
    "ObserveBundle_WhenFstatFailsAfterLeafOpen_CleansOwnedResources",
    "ObserveBundle_WhenFstatatFailsAtFinalPathReadback_CleansOwnedResources",
    "ObserveBundle_WhenExpectationAbiVersionIsWrong_RejectsBeforeOsCalls",
    "ObserveBundle_WhenExpectationStructSizeIsWrong_RejectsBeforeOsCalls",
    "ObserveBundle_WhenPolicyGrowsPastBoundBetweenPathStatAndOpen_RejectsBeforeAllocation",
    "ObserveBundle_WhenLiveResultIsReused_RejectsAndPreservesOriginalSnapshot",
    "ObserveBundle_WhenExpectationOverlapsResult_RejectsWithoutMutation",
    "ObserveBundle_WhenResultOwnershipFieldsAreInvalid_RejectsWithoutImplicitFree",
};
int main(void) {
    int passed = 0;
    for (int c = 1; c <= 65; ++c) {
        int ok = 1;
        if (c == 52) ok = preflight_case();
        else if (c == 22 || c == 53) ok = bounded_case(c);
        else { int variants = c == 23 || c == 55 || c == 29 ? 3 : 1;
            for (int v = 0; v < variants; ++v) if (!observe_case(c, v)) ok = 0; }
        printf("%s %s\n", ok ? "PASS" : "FAIL", cases[c - 1]); fflush(stdout);
        passed += ok;
    }
    printf("SUMMARY %d/65 passed; %d failed; 0 skipped\n", passed, 65 - passed);
    return passed == 65 ? 0 : 1;
}
