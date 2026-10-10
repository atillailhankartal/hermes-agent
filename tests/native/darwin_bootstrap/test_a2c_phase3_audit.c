/* Test-only A audit: observe owned descriptors without modifying them. */
#include <fcntl.h>
#include <libproc.h>
#include <stdio.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int bh_a2c_fixture_drop(void) { return getuid() != 0 && getuid() == geteuid() && getgid() == getegid(); }
void bh_a2c_test_audit(const char *event, pid_t child, int status) {
    char buffer[128];
    int flags = fcntl(2, F_GETFL);
    if (flags < 0 || !(flags & O_NONBLOCK)) return;
    int size = snprintf(buffer, sizeof(buffer), "AUDIT %s %ld %d\n", event, (long)child, status);
    if (size > 0 && (size_t)size < sizeof(buffer)) (void)write(2, buffer, (size_t)size);
    if (!strcmp(event, "FORWARD") && status == 'X') {
        struct proc_fdinfo entries[512];
        int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, entries, sizeof(entries));
        int roots = 0;
        if (bytes <= 0 || (size_t)bytes >= sizeof(entries) || bytes % sizeof(entries[0])) roots = -1;
        else for (size_t i = 0; i < (size_t)bytes / sizeof(entries[0]); i++) {
            struct sockaddr_un address = {0};
            socklen_t length = sizeof(address);
            if (!getsockname(entries[i].proc_fd, (struct sockaddr *)&address, &length) &&
                address.sun_family == AF_UNIX && length > offsetof(struct sockaddr_un, sun_path) &&
                address.sun_path[0]) roots++;
        }
        (void)dprintf(1, "OBS_A root6=%d bound_aliases=%d management3=%d\n",
                      fcntl(6, F_GETFD) >= 0, roots, fcntl(3, F_GETFD) >= 0);
    }
}
