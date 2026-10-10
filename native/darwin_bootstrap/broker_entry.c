#include "broker_entry.h"

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct owned_directory { int fd; struct stat identity; int known; };

static int same_metadata(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_mode == b->st_mode;
}

static int compare_fd(const void *a, const void *b) {
    const struct bh_a2b_fd *left = a, *right = b;
    return (left->number > right->number) - (left->number < right->number);
}

static int inventory(struct bh_a2b_inventory *out) {
    struct proc_fdinfo entries[BH_A2B_MAX_FDS];
    size_t i;
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, entries, sizeof(entries));
    if (bytes <= 0 || (size_t)bytes >= sizeof(entries) ||
        (size_t)bytes % sizeof(entries[0]) != 0) return 0;
    out->count = (size_t)bytes / sizeof(entries[0]);
    for (i = 0; i < out->count; i++) {
        struct bh_a2b_fd *item = &out->descriptors[i];
        item->number = entries[i].proc_fd;
        item->descriptor_flags = fcntl(item->number, F_GETFD);
        item->status_flags = fcntl(item->number, F_GETFL);
        if (item->number < 0 || item->descriptor_flags < 0 || item->status_flags < 0 ||
            fstat(item->number, &item->metadata) != 0) return 0;
        if (S_ISSOCK(item->metadata.st_mode)) {
            struct socket_fdinfo socket_info;
            if (proc_pidfdinfo(getpid(), item->number, PROC_PIDFDSOCKETINFO, &socket_info,
                               sizeof(socket_info)) != sizeof(socket_info) ||
                socket_info.psi.soi_so == 0) return 0;
            item->socket_identity = socket_info.psi.soi_so;
        }
    }
    qsort(out->descriptors, out->count, sizeof(out->descriptors[0]), compare_fd);
    for (i = 1; i < out->count; i++)
        if (out->descriptors[i - 1].number == out->descriptors[i].number) return 0;
    out->complete = 1;
    return 1;
}

static int exact_map(const struct bh_a2b_inventory *map, int final) {
    const int expected[] = {0, 1, 2, 3, 4, 6, 7};
    size_t i, count = final ? 7 : 6;
    if (!map->complete || map->count != count) return 0;
    for (i = 0; i < count; i++)
        if (map->descriptors[i].number != expected[i]) return 0;
    return 1;
}

static int inherited_match(const struct bh_a2b_candidate *candidate,
                           const struct bh_a2b_inventory *map) {
    const int numbers[] = {3, 4, 6};
    size_t i, previous;
    for (i = 0; i < 3; i++) {
        const struct bh_a2b_fd *actual = &map->descriptors[i + 3];
        const struct bh_a2b_fd *expected = &candidate->inherited[i];
        struct sockaddr_un address;
        for (previous = 0; previous < i; previous++)
            if (actual->socket_identity == map->descriptors[previous + 3].socket_identity)
                return 0;
        int type = -1;
        socklen_t length = sizeof(address), type_length = sizeof(type);
        if (expected->number != numbers[i] || actual->number != numbers[i] ||
            actual->descriptor_flags != FD_CLOEXEC ||
            expected->descriptor_flags != actual->descriptor_flags ||
            expected->status_flags != actual->status_flags ||
            expected->socket_identity != actual->socket_identity ||
            !S_ISSOCK(actual->metadata.st_mode) ||
            !same_metadata(&expected->metadata, &actual->metadata) ||
            getsockopt(numbers[i], SOL_SOCKET, SO_TYPE, &type, &type_length) != 0 ||
            type_length != sizeof(type) || type != SOCK_STREAM ||
            getsockname(numbers[i], (struct sockaddr *)&address, &length) != 0 ||
            length < offsetof(struct sockaddr_un, sun_path) ||
            address.sun_family != AF_UNIX) return 0;
    }
    return 1;
}

static int valid_path(const struct bh_a2b_candidate *candidate) {
    size_t start = 1, i, length = candidate->path_length;
    if (length == 0 || length >= sizeof(candidate->path) || candidate->path[0] != '/' ||
        candidate->path[length] != '\0' || memchr(candidate->path, '\0', length) != NULL)
        return 0;
    if (length == 1) return 1;
    for (i = 1; i <= length; i++) {
        if (i != length && candidate->path[i] != '/') continue;
        if (i == start || (i - start == 1 && candidate->path[start] == '.') ||
            (i - start == 2 && candidate->path[start] == '.' && candidate->path[start + 1] == '.'))
            return 0;
        start = i + 1;
    }
    return 1;
}

static void retain_unknown(struct owned_directory *owned, struct bh_a2b_observation *out) {
    struct bh_a2b_cleanup *decision;
    if (owned->fd < 0) return;
    decision = &out->cleanup[out->cleanup_count++];
    decision->number = owned->fd;
    decision->decision = BH_A2B_RETAINED_UNKNOWN;
    owned->fd = -1; /* Forget the cleanup candidate, never close its numeric slot. */
}

static int retire(struct owned_directory *owned, struct bh_a2b_observation *out) {
    struct stat current;
    struct bh_a2b_cleanup *decision;
    int clean = 0;
    if (owned->fd < 0) return 1;
    /* Success-path retirement alone relies on the sealed-entry precondition.
     * Vnode metadata cannot prove open-file-description identity. On any error,
     * retain uncertain slots for terminal cancellation; never retry a close. */
    if (!owned->known) { retain_unknown(owned, out); return 0; }
    decision = &out->cleanup[out->cleanup_count++];
    decision->number = owned->fd;
    if (fstat(owned->fd, &current) != 0 ||
        !same_metadata(&current, &owned->identity)) {
        decision->decision = BH_A2B_RETAINED_UNKNOWN;
    } else if (close(owned->fd) == 0) {
        decision->decision = BH_A2B_CLOSED;
        clean = 1;
    } else {
        decision->decision = BH_A2B_CLOSE_FAILED;
    }
    owned->fd = -1;
    return clean;
}

static int observe_directory(struct owned_directory *owned, const char *path,
                             struct bh_a2b_observation *out) {
    char observed[BH_A2B_PATH_MAX];
    struct bh_a2b_ancestor *ancestor;
    int flags;
    if (fstat(owned->fd, &owned->identity) != 0) return 0;
    owned->known = 1;
    flags = fcntl(owned->fd, F_GETFL);
    if (!S_ISDIR(owned->identity.st_mode) || flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        fcntl(owned->fd, F_GETFD) != FD_CLOEXEC ||
        fcntl(owned->fd, F_GETPATH, observed) != 0 || strcmp(observed, path) != 0 ||
        out->ancestor_count >= BH_A2B_MAX_ANCESTORS) return 0;
    ancestor = &out->ancestors[out->ancestor_count++];
    strcpy(ancestor->path, observed);
    ancestor->metadata = owned->identity;
    return 1;
}

static int walk(const struct bh_a2b_candidate *candidate, struct owned_directory *current,
                struct bh_a2b_observation *out) {
    size_t start = 1, end;
    char component[BH_A2B_PATH_MAX], path[BH_A2B_PATH_MAX] = "/";
    const int flags = O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
    current->fd = openat(AT_FDCWD, "/", flags);
    if (current->fd < 0 || !observe_directory(current, "/", out)) return 0;
    while (start < candidate->path_length) {
        struct owned_directory next = {.fd = -1};
        for (end = start; end < candidate->path_length && candidate->path[end] != '/'; end++) {}
        if (out->ancestor_count >= BH_A2B_MAX_ANCESTORS) return 0;
        memcpy(component, candidate->path + start, end - start);
        component[end - start] = '\0';
        memcpy(path, candidate->path, end);
        path[end] = '\0';
        next.fd = openat(current->fd, component, flags);
        if (next.fd < 0) return 0;
        if (!observe_directory(&next, path, out)) { retain_unknown(&next, out); return 0; }
        if (!retire(current, out)) { retain_unknown(&next, out); return 0; }
        *current = next;
        start = end + 1;
    }
    return 1;
}

enum bh_a2b_result bh_a2b_observe_fd7(const struct bh_a2b_candidate *candidate,
                                      struct bh_a2b_observation *out) {
    struct owned_directory current = {.fd = -1}, installed = {.fd = -1};
    struct stat final_metadata;
    char path[BH_A2B_PATH_MAX];
    int flags;
    if (out == NULL) return BH_A2B_PAUSED;
    memset(out, 0, sizeof(*out));
    out->source_fd = -1;
    if (candidate == NULL || !inventory(&out->initial) || !exact_map(&out->initial, 0) ||
        !inherited_match(candidate, &out->initial) || !valid_path(candidate)) goto fail;
    if (!walk(candidate, &current, out) || !same_metadata(&current.identity, &candidate->parent))
        goto fail;
    out->source_fd = current.fd;
    if (current.fd == 7) {
        installed = current;
        current.fd = -1;
    } else {
        /* F_DUPFD_CLOEXEC never replaces a foreign FD7. A result >7 is owned
         * by this call, but signals that the slot ceased to be empty. */
        installed.fd = fcntl(current.fd, F_DUPFD_CLOEXEC, 7);
        if (installed.fd < 0) goto fail;
        installed.identity = current.identity;
        installed.known = 1;
        if (installed.fd != 7) goto fail;
    }
    out->fd7_installed = 1;
    if (!retire(&current, out)) goto fail;
    flags = fcntl(7, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || fcntl(7, F_GETFD) != FD_CLOEXEC ||
        fstat(7, &final_metadata) != 0 || !S_ISDIR(final_metadata.st_mode) ||
        !same_metadata(&final_metadata, &candidate->parent) ||
        fcntl(7, F_GETPATH, path) != 0 || strcmp(path, candidate->path) != 0 ||
        !inventory(&out->final) || !exact_map(&out->final, 1) ||
        !inherited_match(candidate, &out->final)) goto fail;
    out->result = BH_A2B_FD7_OBSERVED_UNTRUSTED;
    return out->result;
fail:
    /* Once observation fails, no metadata read can exclude same-vnode ABA.
     * Keep every outstanding slot, even when its metadata still matches. */
    retain_unknown(&current, out);
    retain_unknown(&installed, out);
    memset(&out->final, 0, sizeof(out->final));
    (void)inventory(&out->final);
    return BH_A2B_PAUSED;
}
