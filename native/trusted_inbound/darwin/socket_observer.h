#ifndef BH_DARWIN_SOCKET_OBSERVER_H
#define BH_DARWIN_SOCKET_OBSERVER_H
#include <stddef.h>
#include <sys/stat.h>

/* Local, unqualified measurements. None of these states grants authority. */
enum bh_socket_state { BH_UNKNOWN, BH_BOUND_OBSERVED, BH_LISTENER_OBSERVED };
enum bh_socket_reason { BH_OBSERVED, BH_INPUT, BH_RUNTIME, BH_DIRECT, BH_RECORD, BH_CHANGED };
struct bh_socket_observation {
    enum bh_socket_state state;
    enum bh_socket_reason reason;
};
/* Caller retains directory_fd and FD6 exclusively throughout the call.
 * Strings and node metadata are consistency inputs, never a trusted manifest.
 * pathname must use the exact canonical parent spelling returned by F_GETPATH;
 * aliases (including /tmp for /private/tmp) are not normalized.
 * pathname_length excludes NUL; pathname must contain that many readable bytes.
 * basename is NUL terminated within 104 bytes. No descriptor is consumed. */
struct bh_socket_expectation {
    int directory_fd;
    const char *basename;
    const char *pathname;
    size_t pathname_length;
    struct stat node;
};
struct bh_socket_observation bh_darwin_observe_fd6(const struct bh_socket_expectation *expected);
#endif
