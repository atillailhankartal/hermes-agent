#include "a2c_phase3_policy.h"
#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
struct encoding { unsigned char bytes[BH_A2C_PHASE3_JOURNAL_MAX]; size_t size; int failed; };
static void append(struct encoding *out, const void *bytes, size_t count) {
    if (count > sizeof(out->bytes) - out->size) { out->failed = 1; return; }
    memcpy(out->bytes + out->size, bytes, count);
    out->size += count;
}
static void integer(struct encoding *out, uint64_t value, size_t count) {
    unsigned char bytes[8];
    for (size_t i = count; i > 0; i--) { bytes[i - 1] = (unsigned char)value; value >>= 8; }
    append(out, bytes, count);
}
static void field(struct encoding *out, const char *bytes, size_t bound) {
    size_t count = strnlen(bytes, bound);
    if (!count || count == bound) { out->failed = 1; return; }
    integer(out, count, 4);
    append(out, bytes, count);
}
static int digest(const struct encoding *out, unsigned char result[32]) {
    return !out->failed && CC_SHA256(out->bytes, (CC_LONG)out->size, result) != NULL;
}
int bh_a2c_phase3_manifest_valid(const struct bh_a2c_phase3_core *core,
                                const struct bh_a2c_phase3_manifest *manifest) {
    struct encoding encoded = {0};
    unsigned char expected[32];
    if (!bh_a2c_phase3_core_valid(core) || !manifest ||
        memcmp(manifest->leaf, "broker.sock", sizeof("broker.sock")) ||
        manifest->stage[0] != '/' || manifest->final[0] != '/' ||
        strnlen(manifest->stage, sizeof(manifest->stage)) == sizeof(manifest->stage) ||
        strnlen(manifest->final, sizeof(manifest->final)) == sizeof(manifest->final) ||
        !strcmp(manifest->stage, manifest->final)) return 0;
    field(&encoded, "bee.a2c.phase3.release.v1", sizeof("bee.a2c.phase3.release.v1"));
    field(&encoded, manifest->stage, sizeof(manifest->stage));
    append(&encoded, manifest->stage_digest, 32);
    field(&encoded, manifest->final, sizeof(manifest->final));
    append(&encoded, manifest->final_digest, 32);
    field(&encoded, core->bundle, sizeof(core->bundle));
    return digest(&encoded, expected) && !memcmp(expected, manifest->release, 32);
}
static int image_matches(const char *path, const unsigned char expected[32]) {
    unsigned char buffer[8192], actual[32];
    CC_SHA256_CTX context;
    struct stat before, after;
    size_t total = 0;
    int okay = 0, fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_size <= 0 ||
        before.st_size > 64 * 1024 * 1024 || !CC_SHA256_Init(&context)) goto done;
    for (;;) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count < 0) goto done;
        if (!count) break;
        total += (size_t)count;
        if (total > 64 * 1024 * 1024 || !CC_SHA256_Update(&context, buffer, (CC_LONG)count)) goto done;
    }
    okay = !fstat(fd, &after) && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_size == after.st_size && total == (size_t)before.st_size &&
        CC_SHA256_Final(actual, &context) && !memcmp(actual, expected, 32);
done:
    if (close(fd)) okay = 0;
    return okay;
}
int bh_a2c_phase3_images(const struct bh_a2c_phase3_manifest *manifest) {
    return manifest && image_matches(manifest->stage, manifest->stage_digest) &&
        image_matches(manifest->final, manifest->final_digest);
}
static int directory_valid(int fd, struct stat *info) {
    return !fstat(fd, info) && S_ISDIR(info->st_mode) && info->st_uid == getuid() &&
        (info->st_mode & 07777) == 0700;
}
size_t bh_a2c_phase3_journal_encode(int directory, unsigned char state,
                                    unsigned char out[BH_A2C_PHASE3_JOURNAL_MAX]) {
    const struct bh_a2c_phase3_core *core = bh_a2c_phase3_core();
    const struct bh_a2c_phase3_manifest *manifest = bh_a2c_phase3_manifest();
    struct stat info;
    struct encoding record = {0}, hashed = {0};
    unsigned char key_digest[32], fingerprint[32];
    if (!out || state > 1 || !directory_valid(directory, &info) ||
        !bh_a2c_phase3_manifest_valid(core, manifest) ||
        !CC_SHA256(core->exercise_key, 32, key_digest)) return 0;
    integer(&record, 2, 4); integer(&record, state, 1);
    integer(&record, core->epoch, 4); integer(&record, core->generation, 8);
    append(&record, core->nonce, 32); append(&record, core->incarnation, 32);
    append(&record, key_digest, 32);
    integer(&record, (uint64_t)info.st_dev, 8); integer(&record, (uint64_t)info.st_ino, 8);
    field(&record, manifest->leaf, sizeof(manifest->leaf)); append(&record, manifest->release, 32);
    field(&record, manifest->stage, sizeof(manifest->stage)); append(&record, manifest->stage_digest, 32);
    field(&record, manifest->final, sizeof(manifest->final)); append(&record, manifest->final_digest, 32);
    field(&record, core->bundle, sizeof(core->bundle));
    field(&hashed, "bee.a2c.phase3.journal.v2", sizeof("bee.a2c.phase3.journal.v2"));
    append(&hashed, record.bytes, record.size);
    if (record.failed || !digest(&hashed, fingerprint)) return 0;
    append(&record, fingerprint, 32);
    if (record.failed) return 0;
    memcpy(out, record.bytes, record.size);
    return record.size;
}
static int file_valid(const struct stat *file) {
    return S_ISREG(file->st_mode) && file->st_uid == getuid() &&
        (file->st_mode & 07777) == 0600 && file->st_nlink == 1;
}
static int same_file(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}
static int exact_record(int directory, int fd, const struct stat *identity,
                        const unsigned char *expected, size_t length) {
    unsigned char actual[BH_A2C_PHASE3_JOURNAL_MAX + 1];
    struct stat file, path;
    if (fstat(fd, &file) || !file_valid(&file) || !same_file(&file, identity) ||
        file.st_size != (off_t)length ||
        fstatat(directory, "attempt.journal", &path, AT_SYMLINK_NOFOLLOW) ||
        !file_valid(&path) || !same_file(&path, identity)) return 0;
    ssize_t count = pread(fd, actual, sizeof(actual), 0);
    return count == (ssize_t)length && !memcmp(actual, expected, length) &&
        !fstat(fd, &file) && file_valid(&file) && same_file(&file, identity) &&
        file.st_size == (off_t)length &&
        !fstatat(directory, "attempt.journal", &path, AT_SYMLINK_NOFOLLOW) &&
        file_valid(&path) && same_file(&path, identity);
}
static int open_locked(int directory, struct stat *file) {
    struct stat info;
    if (!directory_valid(directory, &info)) return -1;
    int fd = openat(directory, "attempt.journal", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) || fstat(fd, file) || !file_valid(file)) {
        (void)close(fd); return -1;
    }
    return fd;
}
int bh_a2c_phase3_pending(int directory) {
    unsigned char record[BH_A2C_PHASE3_JOURNAL_MAX];
    struct stat identity;
    int okay = 0;
    size_t length = bh_a2c_phase3_journal_encode(directory, 0, record);
    if (!length || !bh_a2c_phase3_images(bh_a2c_phase3_manifest())) return 0;
    int fd = open_locked(directory, &identity);
    if (fd < 0) return 0;
    if (!exact_record(directory, fd, &identity, record, length)) goto done;
    length = bh_a2c_phase3_journal_encode(directory, 1, record);
    if (!length || pwrite(fd, record, length, 0) != (ssize_t)length ||
        ftruncate(fd, (off_t)length) || fsync(fd) || fsync(directory)) goto done;
#ifdef BH_A2C_TEST_READBACK_FAIL
    goto done; /* Simulated readback failure after the real persistent transition. */
#endif
    okay = exact_record(directory, fd, &identity, record, length);
done:
    if (close(fd)) okay = 0;
    return okay;
}
int bh_a2c_phase3_check_pending(int directory, struct stat *identity, int pinned) {
    unsigned char record[BH_A2C_PHASE3_JOURNAL_MAX];
    struct stat file;
    size_t length = bh_a2c_phase3_journal_encode(directory, 1, record);
    if (!identity || !length) return 0;
    int fd = open_locked(directory, &file);
    if (fd < 0) return 0;
    int okay = (!pinned || same_file(&file, identity)) &&
        exact_record(directory, fd, &file, record, length);
    if (close(fd)) okay = 0;
    if (okay) *identity = file;
    return okay;
}
