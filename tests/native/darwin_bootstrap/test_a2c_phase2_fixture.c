/* Linked only into test images; no installed identity or authorization bypass. */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int bh_a2c_fixture_drop(void) { return getuid() != 0 && getuid() == geteuid() && getgid() == getegid(); }
void bh_a2c_test_audit(const char *event, pid_t child, int status) {
    char buffer[128];
    int flags = fcntl(2, F_GETFL);
    if (flags < 0 || !(flags & O_NONBLOCK)) return;
    int size = snprintf(buffer, sizeof(buffer), "AUDIT %s %ld %d\n", event, (long)child, status);
    if (size > 0 && (size_t)size < sizeof(buffer)) (void)write(2, buffer, (size_t)size);
}
