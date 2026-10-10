#include "launch_control.h"
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int main(void) {
    const int allowed[] = {0, 1, 2, 3, 4, 6};
    const int sockets[] = {3, 4, 6};
    struct bh_a2a_inventory inventory;
    struct sockaddr_un address;
    socklen_t length = sizeof(address);
    int64_t deadline;
    unsigned char entered = 'F', command = 0;
    if (bh_a2a_inventory_check(allowed, 6, &inventory) != BH_A2A_OK || inventory.count != 6) _exit(52);
    for (size_t i = 0; i < 3; i++) {
        int flags = fcntl(sockets[i], F_GETFD), type = 0;
        socklen_t size = sizeof(type);
        if (flags < 0 || fcntl(sockets[i], F_SETFD, flags | FD_CLOEXEC) ||
            (fcntl(sockets[i], F_GETFD) & FD_CLOEXEC) == 0 ||
            getsockopt(sockets[i], SOL_SOCKET, SO_TYPE, &type, &size) || type != SOCK_STREAM) _exit(51);
    }
    if (!bh_a2c_signals_match() || getsockname(6, (struct sockaddr *)&address, &length) ||
        address.sun_family != AF_UNIX || length <= offsetof(struct sockaddr_un, sun_path) ||
        !bh_a2c_channel_init(4)) _exit(52);
    deadline = bh_a2c_now() + BH_A2C_TIMEOUT_MS;
    if (!bh_a2c_send(4, &entered, 1, deadline) ||
        !bh_a2c_receive(4, &command, 1, deadline) || command != 'X') _exit(53);
    _exit(0); /* Inert; no listen, authority, key or source processing. */
}
