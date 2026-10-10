/* Dormant local measurement only; no runtime admission consumer. */
#include "socket_observer.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <libproc.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

_Static_assert(sizeof(struct socket_fdinfo) == 792, "unsupported SDK record size");
#define ABI_OFFSET(field, offset) _Static_assert(offsetof(struct socket_fdinfo, field) == offset, "unsupported SDK " #field)
ABI_OFFSET(psi, 24);
ABI_OFFSET(psi.soi_so, 160);
ABI_OFFSET(psi.soi_pcb, 168);
ABI_OFFSET(psi.soi_type, 176);
ABI_OFFSET(psi.soi_protocol, 180);
ABI_OFFSET(psi.soi_family, 184);
ABI_OFFSET(psi.soi_options, 188);
ABI_OFFSET(psi.soi_state, 192);
ABI_OFFSET(psi.soi_error, 202);
ABI_OFFSET(psi.soi_kind, 256);
ABI_OFFSET(psi.soi_proto.pri_un, 264);
ABI_OFFSET(psi.soi_proto.pri_un.unsi_addr, 280);
ABI_OFFSET(psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_path, 282);
_Static_assert(SO_ACCEPTCONN == 0x0002 && PROC_PIDFDSOCKETINFO == 3, "unsupported SDK constants");
_Static_assert(AF_UNIX == 1 && SOCK_STREAM == 1 && SOCKINFO_UN == 3, "unsupported SDK socket kinds");
_Static_assert(sizeof(((struct socket_info *)0)->soi_options) == 2, "unsupported option width");

struct direct_snapshot {
    struct stat descriptor, node, directory;
    struct sockaddr_un address;
    socklen_t address_length;
    int descriptor_flags, status_flags, type;
    bool complete;
};
struct socket_sample {
    struct socket_fdinfo record;
    int bytes;
    struct direct_snapshot before, after;
};

static bool same_node(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        (a->st_mode & S_IFMT) == (b->st_mode & S_IFMT);
}
static bool same_path_metadata(const struct stat *a, const struct stat *b)
{
    return same_node(a, b) && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid;
}
static bool valid_input(const struct bh_socket_expectation *e)
{
    if (!e || e->directory_fd < 0 || e->directory_fd == 6 || !e->basename || !e->pathname ||
        !e->pathname_length || e->pathname_length >= sizeof(((struct sockaddr_un *)0)->sun_path)) return false;
    size_t n = strnlen(e->basename, sizeof(((struct sockaddr_un *)0)->sun_path));
    return n && n < sizeof(((struct sockaddr_un *)0)->sun_path) &&
        !strchr(e->basename, '/') && strcmp(e->basename, ".") && strcmp(e->basename, "..") &&
        e->pathname[0] == '/' && !memchr(e->pathname, '\0', e->pathname_length) &&
        e->pathname_length > n && e->pathname[e->pathname_length - n - 1] == '/' &&
        !memcmp(e->pathname + e->pathname_length - n, e->basename, n) && S_ISSOCK(e->node.st_mode);
}
/* The address length bounds every byte inspected; trailing SDK padding is not identity. */
static bool valid_address(const struct sockaddr_un *a, size_t length,
                          const struct bh_socket_expectation *e)
{
    size_t prefix = offsetof(struct sockaddr_un, sun_path);
    if (length < prefix || length > sizeof(*a) || a->sun_len != length || a->sun_family != AF_UNIX)
        return false;
    size_t available = length - prefix;
    return available >= e->pathname_length &&
        !memcmp(a->sun_path, e->pathname, e->pathname_length) &&
        (available == e->pathname_length || a->sun_path[e->pathname_length] == '\0');
}
static bool valid_direct(const struct direct_snapshot *d, const struct bh_socket_expectation *e)
{
    return d->complete && d->descriptor_flags >= 0 && d->status_flags >= 0 &&
        d->type == SOCK_STREAM && S_ISSOCK(d->descriptor.st_mode) && S_ISDIR(d->directory.st_mode) &&
        same_path_metadata(&d->node, &e->node) && valid_address(&d->address, d->address_length, e);
}
static bool same_direct(const struct direct_snapshot *a, const struct direct_snapshot *b)
{
    return same_node(&a->descriptor, &b->descriptor) && same_path_metadata(&a->node, &b->node) &&
        same_node(&a->directory, &b->directory) && a->descriptor_flags == b->descriptor_flags &&
        a->status_flags == b->status_flags && a->address_length == b->address_length;
}
static struct direct_snapshot read_direct(const struct bh_socket_expectation *e)
{
    struct direct_snapshot d = {0};
    d.descriptor_flags = fcntl(6, F_GETFD);
    d.status_flags = fcntl(6, F_GETFL);
    d.address_length = sizeof(d.address);
    socklen_t type_length = sizeof(d.type);
    struct sockaddr_un peer = {0};
    socklen_t peer_length = sizeof(peer);
    if (d.descriptor_flags < 0 || d.status_flags < 0 || fstat(6, &d.descriptor) ||
        fstat(e->directory_fd, &d.directory) ||
        fstatat(e->directory_fd, e->basename, &d.node, AT_SYMLINK_NOFOLLOW) ||
        getsockopt(6, SOL_SOCKET, SO_TYPE, &d.type, &type_length) || type_length != sizeof(d.type) ||
        getsockname(6, (struct sockaddr *)&d.address, &d.address_length)) return d;
    /* Any outcome other than ENOTCONN is unknown, including a connected peer. */
    if (getpeername(6, (struct sockaddr *)&peer, &peer_length) != -1 || errno != ENOTCONN) return d;
    d.complete = true;
    return d;
}
static bool os_value_matches(const char *name, const char *expected)
{
    char value[64] = {0};
    size_t size = sizeof(value);
    return !sysctlbyname(name, value, &size, NULL, 0) && size == strlen(expected) + 1 &&
        !memcmp(value, expected, size);
}
static bool runtime_matches(void)
{
    struct utsname u;
    return !uname(&u) && !strcmp(u.sysname, "Darwin") && !strcmp(u.machine, "arm64") &&
        os_value_matches("kern.osrelease", "27.0.0") &&
        os_value_matches("kern.osproductversion", "27.0.1") &&
        os_value_matches("kern.osversion", "26A434");
}
static int query_socket_info(struct socket_fdinfo *record)
{
    return proc_pidfdinfo(getpid(), 6, PROC_PIDFDSOCKETINFO, record, sizeof(*record));
}
static bool valid_record(const struct socket_sample *s, const struct bh_socket_expectation *e)
{
    /* Check scalar size before touching even the first record field. */
    if (s->bytes != (int)sizeof(s->record)) return false;
    /* XNU leaves soi_stat zero; descriptor identity comes from direct fstat. */
    const struct socket_info *i = &s->record.psi;
    return i->soi_so && i->soi_pcb && i->soi_family == AF_UNIX && i->soi_type == SOCK_STREAM &&
        i->soi_protocol == 0 && i->soi_kind == SOCKINFO_UN &&
        valid_address(&i->soi_proto.pri_un.unsi_addr.ua_sun,
                      i->soi_proto.pri_un.unsi_addr.ua_sun.sun_len, e) &&
        i->soi_proto.pri_un.unsi_addr.ua_sun.sun_len == s->before.address_length &&
        !(i->soi_state & SOI_S_ISCONNECTED) && !i->soi_proto.pri_un.unsi_conn_so &&
        !i->soi_proto.pri_un.unsi_conn_pcb;
}
/* Private, deterministic production validator. Tests include this translation unit;
 * no runtime syscall substitution or exported record-injection API exists. */
static struct bh_socket_observation validate_samples(const struct socket_sample samples[2],
                                                      const struct bh_socket_expectation *e)
{
    struct bh_socket_observation result = {BH_UNKNOWN, BH_INPUT};
    if (!valid_input(e)) return result;
    for (size_t k = 0; k < 2; k++) {
        const struct socket_sample *s = &samples[k];
        result.reason = BH_DIRECT;
        if (!valid_direct(&s->before, e) || !valid_direct(&s->after, e)) return result;
        result.reason = BH_RECORD;
        if (!valid_record(s, e)) return result;
        result.reason = BH_CHANGED;
        if (!same_direct(&samples[0].before, &s->before) || !same_direct(&s->before, &s->after)) return result;
    }
    const struct socket_info *a = &samples[0].record.psi, *b = &samples[1].record.psi;
    if (a->soi_so != b->soi_so || a->soi_pcb != b->soi_pcb ||
        ((uint16_t)a->soi_options & SO_ACCEPTCONN) != ((uint16_t)b->soi_options & SO_ACCEPTCONN)) return result;
    result.state = ((uint16_t)a->soi_options & SO_ACCEPTCONN) ? BH_LISTENER_OBSERVED : BH_BOUND_OBSERVED;
    result.reason = BH_OBSERVED;
    return result;
}
struct bh_socket_observation bh_darwin_observe_fd6(const struct bh_socket_expectation *e)
{
    if (!valid_input(e)) return (struct bh_socket_observation){BH_UNKNOWN, BH_INPUT};
    if (!runtime_matches()) return (struct bh_socket_observation){BH_UNKNOWN, BH_RUNTIME};
    struct socket_sample samples[2] = {0};
    for (size_t k = 0; k < 2; k++) {
        samples[k].before = read_direct(e);
        samples[k].bytes = query_socket_info(&samples[k].record);
        samples[k].after = read_direct(e);
    }
    if (!runtime_matches()) return (struct bh_socket_observation){BH_UNKNOWN, BH_RUNTIME};
    return validate_samples(samples, e);
}
