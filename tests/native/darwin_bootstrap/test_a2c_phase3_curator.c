/* Disposable test-only FRESH curator. No runtime target links this entrypoint. */
#include "../../../native/darwin_bootstrap/a2c_phase3_policy.h"
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    unsigned char record[BH_A2C_PHASE3_JOURNAL_MAX], actual[BH_A2C_PHASE3_JOURNAL_MAX + 1];
    size_t length = bh_a2c_phase3_journal_encode(directory, 0, record);
    if (!length) return 3;
    int fd = openat(directory, "attempt.journal", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat before, after, path;
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) || fstat(fd, &before) ||
        !S_ISREG(before.st_mode) || before.st_uid != getuid() ||
        (before.st_mode & 07777) != 0600 || before.st_nlink != 1 ||
        write(fd, record, length) != (ssize_t)length || fsync(fd) || fsync(directory) ||
        pread(fd, actual, sizeof(actual), 0) != (ssize_t)length || memcmp(record, actual, length) ||
        fstat(fd, &after) || after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
        after.st_size != (off_t)length || fstatat(directory, "attempt.journal", &path, AT_SYMLINK_NOFOLLOW) ||
        path.st_dev != before.st_dev || path.st_ino != before.st_ino) return 4;
    if (close(fd) || close(directory)) return 5;
    return 0;
}
