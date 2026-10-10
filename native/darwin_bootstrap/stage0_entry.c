#include "launch_control.h"
#include <fcntl.h>
#include <unistd.h>
#ifndef BH_A2C_FINAL_IMAGE
#define BH_A2C_FINAL_IMAGE "/uninstalled/a2c/final"
#endif
#ifdef BH_A2C_TEST_DROP
int bh_a2c_fixture_drop(void);
#else
static int bh_a2c_fixture_drop(void) {
    /* No installed identity policy in this source slice: production drop denies. */
    return bh_a2a_stage0_drop(0, 0) == BH_A2A_OK;
}
#endif
int main(void) {
    int64_t deadline = bh_a2c_now() + BH_A2C_TIMEOUT_MS;
    unsigned char command = 0, entered = 'S';
    if (!bh_a2c_signals_match() || bh_a2a_stage0_validate() != BH_A2A_OK) _exit(41);
    int flags = fcntl(4, F_GETFL);
    if (flags < 0 || fcntl(4, F_SETFL, flags | O_NONBLOCK)) _exit(42);
    if (!bh_a2c_send(4, &entered, 1, deadline) ||
        !bh_a2c_receive(4, &command, 1, deadline) || command != 'E') _exit(43);
    if (!bh_a2c_fixture_drop()) _exit(44);
    char *const arguments[] = { (char *)BH_A2C_FINAL_IMAGE, NULL };
    char *const environment[] = { NULL };
    execve(BH_A2C_FINAL_IMAGE, arguments, environment);
    /* Exec failure status is best effort and cannot block _exit. */
    flags = fcntl(5, F_GETFL);
    if (flags >= 0 && !fcntl(5, F_SETFL, flags | O_NONBLOCK)) (void)write(5, "X", 1);
    _exit(45);
}
