#include "a2c_policy.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

int bh_a2c_pending(int directory_fd) {
    char buffer[64] = {0};
    struct stat directory, file;
    int okay = 0;
    int fd = -1;
    ssize_t count;
    if (fstat(directory_fd, &directory) || !S_ISDIR(directory.st_mode) ||
        directory.st_uid != getuid() || (directory.st_mode & 0777) != 0700) return 0;
    /* P never creates/reinitializes this file. Missing/corrupt/pending denies. */
    fd = openat(directory_fd, "attempt.journal", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    if (flock(fd, LOCK_EX | LOCK_NB) || fstat(fd, &file) ||
        !S_ISREG(file.st_mode) || file.st_uid != getuid() ||
        (file.st_mode & 0777) != 0600 || file.st_nlink != 1) goto done;
    count = pread(fd, buffer, sizeof(buffer), 0);
    if (count != (ssize_t)(sizeof(BH_A2C_FRESH) - 1) ||
        memcmp(buffer, BH_A2C_FRESH, sizeof(BH_A2C_FRESH) - 1)) goto done;
    /* Any crash/short write leaves pending or invalid state; neither can launch. */
    if (ftruncate(fd, 0) ||
        pwrite(fd, BH_A2C_PENDING, sizeof(BH_A2C_PENDING) - 1, 0) !=
            (ssize_t)(sizeof(BH_A2C_PENDING) - 1) || fsync(fd) || fsync(directory_fd)) goto done;
    memset(buffer, 0, sizeof(buffer));
    count = pread(fd, buffer, sizeof(buffer), 0);
    okay = count == (ssize_t)(sizeof(BH_A2C_PENDING) - 1) &&
        !memcmp(buffer, BH_A2C_PENDING, sizeof(BH_A2C_PENDING) - 1);
done:
    if (close(fd)) okay = 0;
    return okay;
}

int bh_a2c_candidate(const struct bh_a2c_config *config, int parent_fd,
                     struct bh_a2a_manifest_v1 *manifest) {
    struct stat directory;
    if (!config || !manifest || config->version != BH_A2C_VERSION ||
        config->epoch != BH_A2C_EPOCH ||
        strnlen(config->parent, sizeof(config->parent)) == sizeof(config->parent) ||
        fstat(parent_fd, &directory) || !S_ISDIR(directory.st_mode) ||
        directory.st_uid != getuid() || (directory.st_mode & 0777) != 0700) return 0;
    memset(manifest, 0, sizeof(*manifest));
    manifest->version = 1;
    memcpy(manifest->parent_path, config->parent, sizeof(config->parent));
    memcpy(manifest->leaf, "broker.sock", sizeof("broker.sock"));
    /* Syntax-only dormant v1 fields. No stage0 is invoked in phase 1. */
    memcpy(manifest->stage0_path, "/uninstalled/a2c/no-stage0", sizeof("/uninstalled/a2c/no-stage0"));
    manifest->parent_uid = directory.st_uid;
    manifest->parent_gid = directory.st_gid;
    manifest->parent_mode = directory.st_mode & 07777;
    manifest->parent_device = directory.st_dev;
    manifest->parent_inode = directory.st_ino;
    manifest->broker_uid = getuid();
    manifest->broker_gid = getgid();
    manifest->release_digest[0] = 1; /* explicitly untrusted fixture marker */
    return bh_a2a_manifest_validate(manifest) == BH_A2A_OK;
}
