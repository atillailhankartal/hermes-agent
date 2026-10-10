/* Passive test-only syscall recording around the unchanged F source. */
#include "../../../native/darwin_bootstrap/launch_control.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
static unsigned char frame[153], receipt[256];
static size_t frame_size, receipt_size;
static int frame_eof;
static ssize_t observed_recv(int fd, void *data, size_t size, int flags) {
    ssize_t count = recv(fd, data, size, flags);
    int saved = errno;
    if (fd == 3 && !(flags & MSG_PEEK)) {
        if (count == 0) frame_eof = 1;
        if (count > 0) {
            size_t copied = (size_t)count;
            if (copied > sizeof(frame) - frame_size) copied = sizeof(frame) - frame_size;
            for (size_t i = 0; i < copied; i++) frame[frame_size++] = ((unsigned char *)data)[i];
        }
    }
    errno = saved;
    return count;
}
static ssize_t observed_send(int fd, const void *data, size_t size, int flags) {
    ssize_t count = send(fd, data, size, flags);
    int saved = errno;
    if (fd == 4 && count > 0) {
        size_t copied = (size_t)count;
        if (copied > sizeof(receipt) - receipt_size) copied = sizeof(receipt) - receipt_size;
        for (size_t i = 0; i < copied; i++) receipt[receipt_size++] = ((const unsigned char *)data)[i];
    }
    errno = saved;
    return count;
}
static _Noreturn void observed_exit(int status) {
    unsigned char pending[153];
    ssize_t peek = recv(3, pending, sizeof(pending), MSG_PEEK | MSG_DONTWAIT);
    int saved = errno;
    char frame_hex[307], receipt_hex[513];
    for (size_t i = 0; i < frame_size; i++) (void)snprintf(frame_hex + i * 2, 3, "%02x", frame[i]);
    for (size_t i = 0; i < receipt_size; i++) (void)snprintf(receipt_hex + i * 2, 3, "%02x", receipt[i]);
    frame_hex[frame_size * 2] = '\0'; receipt_hex[receipt_size * 2] = '\0';
    (void)dprintf(1, "OBS_F status=%d bytes=%zu eof=%d peek=%ld errno=%d frame=%s receipt=%s\n",
                  status, frame_size, frame_eof, (long)peek, peek < 0 ? saved : 0, frame_hex, receipt_hex);
    _exit(status);
}
#define recv observed_recv
#define send observed_send
#include "../../../native/darwin_bootstrap/launch_control.c"
#ifdef BH_A2C_PHASE3_FINAL
#include "../../../native/darwin_bootstrap/a2c_phase3_io.c"
#define BH_A2C_PHASE3
#endif
#define _exit observed_exit
#include "../../../native/darwin_bootstrap/final_entry.c"
