#include "signed_preflight_v2_transaction.h"
#include "signed_preflight_v2_transaction_os.h"
#include "signed_preflight_v2_journal_codec.h"
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/file.h>

#define TX_FDS (1u + 4u * BH_TX_COMPONENTS + 6u)
#define DIR_FLAGS (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
#define LEAF_FLAGS (O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
struct owned_fd {
    int fd;
    unsigned generation, parent;
    char name[BH_TX_NAME];
    int directory;
    off_t min_size, max_size;
    struct stat metadata;
};
struct bh_v2_transaction {
    struct bh_tx_install install;
    struct owned_fd ledger[TX_FDS];
    unsigned count, next_generation;
    unsigned leaves[3];
    unsigned state_indices[2], state_generations[2];
    unsigned char *snapshots[3];
    size_t snapshot_lengths[3];
    int observation_done, observation_failed;
    unsigned char *state_snapshots[2];
    size_t state_snapshot_lengths[2];
    int state_observation_done, state_observation_failed;
    int codec_observation_done, codec_observation_failed;
    bh_journal_parameters saved_parameters;
    int saved_parameters_valid, leaf_digest_done, leaf_digest_failed;
    int lock_index, locked, uncertain;
};
/* Address identity only: never a live transaction, never dereferenced or freed.
 * Static storage keeps the terminal marker valid after the owner allocation is
 * released, without relying on an implementation-defined integer pointer. */
static struct bh_v2_transaction terminal_owner;
static int overlap(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (x > UINTPTR_MAX-an || y > UINTPTR_MAX-bn) return 1;
    return x < y+bn && y < x+an;
}
static int name_valid(const char name[BH_TX_NAME]) {
    const char *end = memchr(name,0,BH_TX_NAME);
    if (!end || end == name || !strcmp(name,".") || !strcmp(name,"..")) return 0;
    for (const char *p = name; p != end; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_')) return 0;
    return 1;
}
static int path_valid(const struct bh_tx_path *p) {
    if (p->count > BH_TX_COMPONENTS) return 0;
    for (unsigned i=0; i<p->count; ++i) if (!name_valid(p->components[i])) return 0;
    return 1;
}
static int same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_flags == b->st_flags &&
        a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
        a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec;
}
static int acceptable(const struct bh_v2_transaction *t, const struct stat *s,
                      int directory, off_t min, off_t max) {
    return (directory ? S_ISDIR(s->st_mode) : S_ISREG(s->st_mode)) &&
        s->st_uid == t->install.uid && s->st_gid == t->install.gid &&
        !(s->st_mode & (0022 | S_ISUID | S_ISGID | S_ISVTX)) &&
        (directory || (s->st_nlink == 1 && s->st_size >= min && s->st_size <= max));
}
static uint32_t acl_check(int fd) {
    void *acl = bh_tx_os_acl_get(fd);
    if (!acl) return BH_TX_UNAVAILABLE;
    int empty = bh_tx_os_acl_empty(acl);
    int released = bh_tx_os_acl_free(acl);
    if (released || empty < 0) return BH_TX_UNAVAILABLE;
    return empty == 1 ? BH_TX_PREPARED_UNTRUSTED : BH_TX_REJECTED;
}
static unsigned retain(struct bh_v2_transaction *t, int fd) {
    unsigned i = t->count++;
    t->ledger[i].fd = fd;
    t->ledger[i].generation = ++t->next_generation;
    return i;
}
/* Retire the generation BEFORE close. EINTR/EIO cannot justify closing that
 * integer again: another thread may already have acquired its next lifetime. */
static int close_owned(struct owned_fd *entry) {
    int fd = entry->fd;
    entry->fd = -1;
    entry->generation = 0;
    return bh_tx_os_close(fd);
}
static int release(struct bh_v2_transaction *t) {
    int failed = 0;
    for (unsigned i=t->count; i>0; --i)
        if ((int)(i-1) != t->lock_index && close_owned(&t->ledger[i-1])) failed = 1;
    if (t->lock_index >= 0) {
        if (t->locked && bh_tx_os_flock(t->ledger[t->lock_index].fd,LOCK_UN)) failed = 1;
        t->locked = 0;
        if (close_owned(&t->ledger[t->lock_index])) failed = 1;
    }
    t->count = 0;
    return failed;
}
static uint32_t open_edge(struct bh_v2_transaction *t, unsigned parent,
                          const char *name, int directory, int writable,
                          off_t min, off_t max, unsigned *index) {
    int enum_fd = bh_tx_os_openat(t->ledger[parent].fd,".",DIR_FLAGS);
    if (enum_fd < 0) return BH_TX_UNAVAILABLE;
    struct stat observed, before, after;
    uint32_t status = BH_TX_PREPARED_UNTRUSTED;
    if (bh_tx_os_fstat(enum_fd,&observed)) status = BH_TX_UNAVAILABLE;
    else if (!same(&observed,&t->ledger[parent].metadata)) status = BH_TX_REJECTED;
    else {
        int exact = bh_tx_os_exact_name(enum_fd,name);
        if (exact < 0) status = BH_TX_UNAVAILABLE;
        else if (exact != 1) status = BH_TX_REJECTED;
    }
    /* This transient generation is retired exactly once, outside the ledger.
     * A failed close cannot prove release; carry that uncertainty to begin. */
    if (bh_tx_os_close(enum_fd)) { t->uncertain = 1; status = BH_TX_UNAVAILABLE; }
    if (status != BH_TX_PREPARED_UNTRUSTED) return status;
    if (bh_tx_os_fstatat(t->ledger[parent].fd,name,&before,AT_SYMLINK_NOFOLLOW)) return BH_TX_UNAVAILABLE;
    if (!acceptable(t,&before,directory,min,max)) return BH_TX_REJECTED;
    int flags = directory ? DIR_FLAGS : LEAF_FLAGS;
    if (writable) flags = (flags & ~O_ACCMODE) | O_RDWR;
    int fd = bh_tx_os_openat(t->ledger[parent].fd,name,flags);
    if (fd < 0) return BH_TX_UNAVAILABLE;
    *index = retain(t,fd);
    t->ledger[*index].parent = parent;
    memcpy(t->ledger[*index].name,name,strlen(name)+1);
    t->ledger[*index].directory = directory;
    t->ledger[*index].min_size = min;
    t->ledger[*index].max_size = max;
    if (bh_tx_os_fstat(fd,&observed)) return BH_TX_UNAVAILABLE;
    if (!same(&before,&observed) || !acceptable(t,&observed,directory,min,max)) return BH_TX_REJECTED;
    t->ledger[*index].metadata = observed;
    status = acl_check(fd);
    if (status != BH_TX_PREPARED_UNTRUSTED) return status;
    if (bh_tx_os_fstatat(t->ledger[parent].fd,name,&after,AT_SYMLINK_NOFOLLOW)) return BH_TX_UNAVAILABLE;
    return same(&observed,&after) ? BH_TX_PREPARED_UNTRUSTED : BH_TX_REJECTED;
}
static uint32_t walk(struct bh_v2_transaction *t, const struct bh_tx_path *path, unsigned *parent) {
    *parent = 0;
    for (unsigned i=0; i<path->count; ++i) {
        uint32_t status = open_edge(t,*parent,path->components[i],1,0,0,0,parent);
        if (status != BH_TX_PREPARED_UNTRUSTED) return status;
    }
    return BH_TX_PREPARED_UNTRUSTED;
}
static uint32_t acquire(struct bh_v2_transaction *t, int anchor) {
    int fd = bh_tx_os_dup_cloexec(anchor);
    if (fd < 0) return BH_TX_UNAVAILABLE;
    unsigned root = retain(t,fd), lock_parent, version, floor_parent, selector_parent, leaf;
    struct stat *s = &t->ledger[root].metadata;
    if (bh_tx_os_fstat(fd,s)) return BH_TX_UNAVAILABLE;
    if (!acceptable(t,s,1,0,0) || (uint64_t)s->st_dev != t->install.anchor_device ||
        (uint64_t)s->st_ino != t->install.anchor_inode) return BH_TX_REJECTED;
    uint32_t status = acl_check(fd);
    if (status != BH_TX_PREPARED_UNTRUSTED) return status;
#define STEP(call) do { status = (call); if (status != BH_TX_PREPARED_UNTRUSTED) return status; } while (0)
    STEP(walk(t,&t->install.lock_parent,&lock_parent));
    unsigned prior = t->count;
    status = open_edge(t,lock_parent,t->install.lock_name,0,1,0,INT64_MAX,&leaf);
    /* Even a lock failing metadata validation owns its independent FD. */
    if (t->count > prior) t->lock_index = (int)leaf;
    if (status != BH_TX_PREPARED_UNTRUSTED) return status;
    if (bh_tx_os_flock(t->ledger[leaf].fd,LOCK_EX|LOCK_NB)) {
        /* Darwin flock(2) documents EWOULDBLOCK for LOCK_NB contention.
         * EAGAIN is its alias; other errors do not prove non-acquisition. Do not issue an
         * unlock on an ambiguous acquisition; retire the FD once in release. */
        if (errno != EWOULDBLOCK && errno != EAGAIN) t->uncertain = 1;
        return BH_TX_UNAVAILABLE;
    }
    t->locked = 1;
    struct stat after;
    if (bh_tx_os_fstatat(t->ledger[lock_parent].fd,t->install.lock_name,&after,AT_SYMLINK_NOFOLLOW) ||
        !same(&after,&t->ledger[leaf].metadata)) return BH_TX_UNAVAILABLE;
    STEP(walk(t,&t->install.version,&version));
    STEP(walk(t,&t->install.floor_parent,&floor_parent));
    STEP(walk(t,&t->install.selector_parent,&selector_parent));
    STEP(open_edge(t,version,"policy.v2.bin",0,0,49,65584,&leaf));
    t->leaves[0] = leaf;
    STEP(open_edge(t,version,"policy.v2.sig",0,0,64,64,&leaf));
    t->leaves[1] = leaf;
    STEP(open_edge(t,version,"release.v2.bin",0,0,17,65552,&leaf));
    t->leaves[2] = leaf;
    STEP(open_edge(t,floor_parent,t->install.floor_name,0,1,0,INT64_MAX,&leaf));
    t->state_indices[0] = leaf;
    t->state_generations[0] = t->ledger[leaf].generation;
    STEP(open_edge(t,selector_parent,t->install.selector_name,0,0,0,INT64_MAX,&leaf));
    t->state_indices[1] = leaf;
    t->state_generations[1] = t->ledger[leaf].generation;
#undef STEP
    return BH_TX_PREPARED_UNTRUSTED;
}
static uint32_t outcome(struct bh_tx_result *r, uint32_t status) {
    memset(r,0,sizeof(*r)); r->status = status; return status;
}
uint32_t bh_v2_transaction_begin(int anchor, const struct bh_tx_install *d,
    struct bh_v2_transaction **owner, struct bh_tx_result *r) {
    if (!d || !owner || !r || anchor < 0 ||
        overlap(d,sizeof(*d),owner,sizeof(*owner)) || overlap(d,sizeof(*d),r,sizeof(*r)) ||
        overlap(owner,sizeof(*owner),r,sizeof(*r))) return BH_TX_REJECTED;
    struct bh_tx_result zero = {0};
    if (*owner || memcmp(r,&zero,sizeof(zero)) || d->abi_version != BH_TX_ABI || d->struct_size != sizeof(*d) ||
        !path_valid(&d->version) || !path_valid(&d->lock_parent) || !path_valid(&d->floor_parent) ||
        !path_valid(&d->selector_parent) || !name_valid(d->lock_name) || !name_valid(d->floor_name) ||
        !name_valid(d->selector_name)) return BH_TX_REJECTED;
    struct bh_v2_transaction pending = {0};
    pending.install = *d; pending.lock_index = -1;
    for (unsigned i=0; i<TX_FDS; ++i) pending.ledger[i].fd = -1;
    uint32_t status = acquire(&pending,anchor);
    if (status == BH_TX_PREPARED_UNTRUSTED) {
        struct bh_v2_transaction *allocated = bh_tx_os_alloc(sizeof(*allocated));
        if (allocated) { *allocated = pending; *owner = allocated; return outcome(r,status); }
        status = BH_TX_UNAVAILABLE;
    }
    if (release(&pending)) pending.uncertain = 1;
    if (pending.uncertain) { *owner = &terminal_owner; status = BH_TX_UNAVAILABLE; }
    return outcome(r,status);
}
static void free_snapshots(struct bh_v2_transaction *t) {
    for (unsigned i=0; i<3; ++i) {
        if (t->snapshots[i]) {
            bh_tx_os_free(t->snapshots[i]);
            t->snapshots[i] = NULL;
        }
        t->snapshot_lengths[i] = 0;
    }
}
static void free_state_snapshots(struct bh_v2_transaction *t) {
    for (unsigned i=0; i<2; ++i) {
        if (t->state_snapshots[i]) {
            bh_tx_os_free(t->state_snapshots[i]);
            t->state_snapshots[i] = NULL;
        }
        t->state_snapshot_lengths[i] = 0;
    }
}
/* Observe one immutable ledger edge. The enumeration handle is independent
 * of the retained parent description and is retired once even on failure. */
static uint32_t observe_edge(struct bh_v2_transaction *t, unsigned i) {
    struct owned_fd *parent = &t->ledger[t->ledger[i].parent];
    struct owned_fd *child = &t->ledger[i];
    struct stat current, path, enumerated;
    if (bh_tx_os_fstat(parent->fd,&current)) return BH_TX_UNAVAILABLE;
    if (!same(&current,&parent->metadata)) return BH_TX_REJECTED;
    if (bh_tx_os_fstat(child->fd,&current)) return BH_TX_UNAVAILABLE;
    if (!same(&current,&child->metadata) ||
        !acceptable(t,&current,child->directory,child->min_size,child->max_size))
        return BH_TX_REJECTED;
    int enumeration = bh_tx_os_openat(parent->fd,".",DIR_FLAGS);
    if (enumeration < 0) return BH_TX_UNAVAILABLE;
    uint32_t status = BH_TX_PREPARED_UNTRUSTED;
    if (bh_tx_os_fstat(enumeration,&enumerated)) status = BH_TX_UNAVAILABLE;
    else if (!same(&enumerated,&parent->metadata)) status = BH_TX_REJECTED;
    else {
        int exact = bh_tx_os_exact_name(enumeration,child->name);
        if (exact < 0) status = BH_TX_UNAVAILABLE;
        else if (exact != 1) status = BH_TX_REJECTED;
    }
    if (bh_tx_os_close(enumeration)) { t->uncertain = 1; status = BH_TX_UNAVAILABLE; }
    if (status != BH_TX_PREPARED_UNTRUSTED) return status;
    if (bh_tx_os_fstatat(parent->fd,child->name,&path,AT_SYMLINK_NOFOLLOW))
        return BH_TX_UNAVAILABLE;
    if (!same(&path,&child->metadata) ||
        !acceptable(t,&path,child->directory,child->min_size,child->max_size))
        return BH_TX_REJECTED;
    return acl_check(child->fd);
}
static uint32_t observe_all_edges(struct bh_v2_transaction *t) {
    struct stat anchor;
    if (bh_tx_os_fstat(t->ledger[0].fd,&anchor)) return BH_TX_UNAVAILABLE;
    if (!same(&anchor,&t->ledger[0].metadata) || !acceptable(t,&anchor,1,0,0))
        return BH_TX_REJECTED;
    uint32_t status = acl_check(t->ledger[0].fd);
    if (status != BH_TX_PREPARED_UNTRUSTED) return status;
    for (unsigned i=1; i<t->count; ++i) {
        status = observe_edge(t,i);
        if (status != BH_TX_PREPARED_UNTRUSTED) return status;
    }
    return BH_TX_PREPARED_UNTRUSTED;
}
uint32_t bh_v2_transaction_observe_retained(struct bh_v2_transaction **owner,
    struct bh_tx_result *r) {
    if (!owner || !r || overlap(owner,sizeof(*owner),r,sizeof(*r)))
        return BH_TX_REJECTED;
    struct bh_tx_result zero = {0};
    if (memcmp(r,&zero,sizeof(zero)) || !*owner) return BH_TX_REJECTED;
    struct bh_v2_transaction *t = *owner;
    if (t == &terminal_owner) return outcome(r,BH_TX_UNAVAILABLE);
    if (overlap(t,sizeof(*t),owner,sizeof(*owner)) ||
        overlap(t,sizeof(*t),r,sizeof(*r))) return BH_TX_REJECTED;
    if (t->observation_failed || t->leaf_digest_failed) return outcome(r,BH_TX_UNAVAILABLE);
    if (t->observation_done) return outcome(r,BH_TX_REJECTED);
    uint32_t status = observe_all_edges(t);
    unsigned char *scratch = NULL;
    if (status == BH_TX_PREPARED_UNTRUSTED) {
        size_t max_length = 0;
        for (unsigned i=0; i<3; ++i) {
            const struct owned_fd *leaf = &t->ledger[t->leaves[i]];
            /* observe_all_edges validated signed size and the frozen bounds. */
            size_t length = (size_t)leaf->metadata.st_size;
            t->snapshot_lengths[i] = length;
            if (length > max_length) max_length = length;
            t->snapshots[i] = bh_tx_os_alloc(length);
            if (!t->snapshots[i]) { status = BH_TX_UNAVAILABLE; break; }
        }
        if (status == BH_TX_PREPARED_UNTRUSTED) {
            scratch = bh_tx_os_alloc(max_length);
            if (!scratch) status = BH_TX_UNAVAILABLE;
        }
    }
    if (status == BH_TX_PREPARED_UNTRUSTED) {
        for (unsigned i=0; i<3; ++i) {
            const struct owned_fd *leaf = &t->ledger[t->leaves[i]];
            size_t length = t->snapshot_lengths[i];
            if (bh_tx_os_pread(leaf->fd,t->snapshots[i],length,0) != (ssize_t)length) {
                status = BH_TX_UNAVAILABLE; break;
            }
        }
    }
    if (status == BH_TX_PREPARED_UNTRUSTED) status = observe_all_edges(t);
    int bytes_changed = 0;
    if (status == BH_TX_PREPARED_UNTRUSTED) {
        for (unsigned i=0; i<3; ++i) {
            const struct owned_fd *leaf = &t->ledger[t->leaves[i]];
            size_t length = t->snapshot_lengths[i];
            if (bh_tx_os_pread(leaf->fd,scratch,length,0) != (ssize_t)length) {
                status = BH_TX_UNAVAILABLE; break;
            }
            if (memcmp(t->snapshots[i],scratch,length)) bytes_changed = 1;
        }
    }
    if (status == BH_TX_PREPARED_UNTRUSTED) status = observe_all_edges(t);
    if (status == BH_TX_PREPARED_UNTRUSTED && bytes_changed) status = BH_TX_REJECTED;
    if (scratch) bh_tx_os_free(scratch);
    if (status == BH_TX_PREPARED_UNTRUSTED) t->observation_done = 1;
    else { free_snapshots(t); t->observation_failed = 1; }
    return outcome(r,status);
}
uint32_t bh_v2_transaction_observe_local_state(struct bh_v2_transaction **owner,
    struct bh_tx_result *r) {
    if (!owner || !r || overlap(owner,sizeof(*owner),r,sizeof(*r)))
        return BH_TX_REJECTED;
    struct bh_tx_result zero = {0};
    if (memcmp(r,&zero,sizeof(zero)) || !*owner) return BH_TX_REJECTED;
    struct bh_v2_transaction *t = *owner;
    if (t == &terminal_owner) return outcome(r,BH_TX_UNAVAILABLE);
    if (overlap(t,sizeof(*t),owner,sizeof(*owner)) ||
        overlap(t,sizeof(*t),r,sizeof(*r))) return BH_TX_REJECTED;
    if (t->state_observation_failed || t->observation_failed || t->leaf_digest_failed)
        return outcome(r,BH_TX_UNAVAILABLE);
    if (t->state_observation_done || !t->observation_done)
        return outcome(r,BH_TX_REJECTED);

    uint32_t status = observe_all_edges(t);
    size_t lengths[2] = {0};
    unsigned char *scratch = NULL;
    if (status == BH_TX_PREPARED_UNTRUSTED) {
        for (unsigned i=0; i<2; ++i) {
            unsigned index = t->state_indices[i];
            /* The original ledger generation and signed size must be checked
             * before conversion, allocation, or an exact-length read. */
            if (index >= t->count) { status = BH_TX_UNAVAILABLE; break; }
            const struct owned_fd *state = &t->ledger[index];
            off_t size = state->metadata.st_size;
            size_t limit = i == 0 ? BH_JOURNAL_MAX_BYTES : BH_SELECTOR_MAX_BYTES;
            if (state->fd < 0 ||
                state->generation != t->state_generations[i]) {
                status = BH_TX_UNAVAILABLE; break;
            }
            if (size < 0 || (uintmax_t)size > (uintmax_t)limit ||
                (uintmax_t)size > (uintmax_t)SSIZE_MAX) {
                status = BH_TX_REJECTED; break;
            }
            if (size == 0) { status = BH_TX_UNAVAILABLE; break; }
            lengths[i] = (size_t)size;
        }
    }
    if (status == BH_TX_PREPARED_UNTRUSTED) {
        for (unsigned i=0; i<2; ++i) {
            t->state_snapshot_lengths[i] = lengths[i];
            t->state_snapshots[i] = bh_tx_os_alloc(lengths[i]);
            if (!t->state_snapshots[i]) { status = BH_TX_UNAVAILABLE; break; }
        }
        if (status == BH_TX_PREPARED_UNTRUSTED) {
            size_t max_length = lengths[0] > lengths[1] ? lengths[0] : lengths[1];
            scratch = bh_tx_os_alloc(max_length);
            if (!scratch) status = BH_TX_UNAVAILABLE;
        }
    }
    if (status == BH_TX_PREPARED_UNTRUSTED) {
        for (unsigned i=0; i<2; ++i) {
            const struct owned_fd *state = &t->ledger[t->state_indices[i]];
            if (bh_tx_os_pread(state->fd,t->state_snapshots[i],lengths[i],0) !=
                (ssize_t)lengths[i]) { status = BH_TX_UNAVAILABLE; break; }
        }
    }
    if (status == BH_TX_PREPARED_UNTRUSTED) status = observe_all_edges(t);
    int bytes_changed = 0;
    if (status == BH_TX_PREPARED_UNTRUSTED) {
        for (unsigned i=0; i<2; ++i) {
            const struct owned_fd *state = &t->ledger[t->state_indices[i]];
            if (bh_tx_os_pread(state->fd,scratch,lengths[i],0) !=
                (ssize_t)lengths[i]) { status = BH_TX_UNAVAILABLE; break; }
            if (memcmp(t->state_snapshots[i],scratch,lengths[i])) bytes_changed = 1;
        }
    }
    if (status == BH_TX_PREPARED_UNTRUSTED) status = observe_all_edges(t);
    if (status == BH_TX_PREPARED_UNTRUSTED && bytes_changed) status = BH_TX_REJECTED;
    if (scratch) bh_tx_os_free(scratch);
    if (status == BH_TX_PREPARED_UNTRUSTED) t->state_observation_done = 1;
    else {
        free_state_snapshots(t);
        free_snapshots(t);
        t->state_observation_failed = 1;
    }
    return outcome(r,status);
}
uint32_t bh_v2_transaction_observe_codec(struct bh_v2_transaction **owner,
    const bh_journal_parameters *diagnostic_parameters, struct bh_tx_result *r) {
    if (!owner || !r || !diagnostic_parameters ||
        overlap(owner,sizeof(*owner),r,sizeof(*r)) ||
        overlap(owner,sizeof(*owner),diagnostic_parameters,sizeof(*diagnostic_parameters)) ||
        overlap(r,sizeof(*r),diagnostic_parameters,sizeof(*diagnostic_parameters)))
        return BH_TX_REJECTED;
    struct bh_tx_result zero = {0};
    if (memcmp(r,&zero,sizeof(zero)) || !*owner) return BH_TX_REJECTED;
    struct bh_v2_transaction *t = *owner;
    if (t == &terminal_owner) return outcome(r,BH_TX_UNAVAILABLE);
    if (overlap(t,sizeof(*t),owner,sizeof(*owner)) ||
        overlap(t,sizeof(*t),r,sizeof(*r)) ||
        overlap(t,sizeof(*t),diagnostic_parameters,sizeof(*diagnostic_parameters)))
        return BH_TX_REJECTED;
    if (t->observation_failed || t->state_observation_failed || t->codec_observation_failed || t->leaf_digest_failed)
        return outcome(r,BH_TX_UNAVAILABLE);
    if (t->codec_observation_done || !t->observation_done || !t->state_observation_done)
        return outcome(r,BH_TX_REJECTED);

    bh_journal_parameters copied_parameters;
    memcpy(&copied_parameters,diagnostic_parameters,sizeof(copied_parameters));
    unsigned installation_nonzero = 0, key_nonzero = 0;
    for (size_t i=0; i<sizeof(copied_parameters.installation_id); ++i)
        installation_nonzero |= copied_parameters.installation_id[i];
    for (size_t i=0; i<sizeof(copied_parameters.new_key_id); ++i)
        key_nonzero |= copied_parameters.new_key_id[i];
    uint32_t status = BH_TX_REJECTED;
    if (installation_nonzero && key_nonzero && copied_parameters.threshold_t != 0 &&
        copied_parameters.threshold_t != UINT64_MAX) {
        bh_journal_snapshot journal = {t->state_snapshots[0],t->state_snapshot_lengths[0],1};
        bh_journal_snapshot selector = {t->state_snapshots[1],t->state_snapshot_lengths[1],1};
        bh_journal_observation observation = bh_journal_observe(journal,selector,
            &copied_parameters,BH_JOURNAL_STARTUP_RECOVER,NULL);
        /* Format consistency, including codec off=false, grants no authority. */
        status = observation.outcome == BH_JOURNAL_CONSISTENT_ONLY ?
            BH_TX_PREPARED_UNTRUSTED : BH_TX_UNAVAILABLE;
    }
    if (status == BH_TX_PREPARED_UNTRUSTED) {
        t->saved_parameters = copied_parameters;
        t->saved_parameters_valid = 1;
        t->codec_observation_done = 1;
    }
    else {
        free_state_snapshots(t);
        free_snapshots(t);
        t->codec_observation_failed = 1;
    }
    return outcome(r,status);
}
/* Structural validation precedes any caller-byte reads or diagnostic work. */
static int leaf_range_overlap(const struct bh_v2_transaction *t,
    const void *p, size_t length) {
    if (overlap(t,sizeof(*t),p,length)) return 1;
    for (unsigned i=0; i<3; ++i)
        if (t->snapshots[i] && overlap(t->snapshots[i],t->snapshot_lengths[i],p,length))
            return 1;
    for (unsigned i=0; i<2; ++i)
        if (t->state_snapshots[i] &&
            overlap(t->state_snapshots[i],t->state_snapshot_lengths[i],p,length)) return 1;
    return 0;
}
static int lower_alnum(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}
static size_t leaf_version_length(const struct bh_tx_path *path) {
    if (!path->count || path->count > BH_TX_COMPONENTS) return 0;
    const char *name = path->components[path->count-1];
    const char *end = memchr(name,0,BH_TX_NAME);
    if (!end || end == name || !lower_alnum((unsigned char)name[0]) ||
        !lower_alnum((unsigned char)end[-1])) return 0;
    for (const char *p=name; p!=end; ++p)
        if (!lower_alnum((unsigned char)*p) && *p != '_' && *p != '-') return 0;
    return (size_t)(end-name);
}
static uint32_t leaf_failure(struct bh_v2_transaction *t,
    struct bh_tx_result *r, uint32_t status) {
    t->leaf_digest_failed = 1;
    t->saved_parameters_valid = 0;
    memset(&t->saved_parameters,0,sizeof(t->saved_parameters));
    free_state_snapshots(t);
    free_snapshots(t);
    return outcome(r,status);
}
uint32_t bh_v2_transaction_observe_leaf_digests(struct bh_v2_transaction **owner,
    const struct bh_tx_leaf_claim *diagnostic_claim, struct bh_tx_result *r) {
    if (!owner || !r || !diagnostic_claim ||
        overlap(owner,sizeof(*owner),r,sizeof(*r)) ||
        overlap(owner,sizeof(*owner),diagnostic_claim,sizeof(*diagnostic_claim)) ||
        overlap(r,sizeof(*r),diagnostic_claim,sizeof(*diagnostic_claim))) return BH_TX_REJECTED;
    struct bh_v2_transaction *t = *owner;
    if (!t) return BH_TX_REJECTED;
    struct bh_tx_result zero = {0};
    if (t == &terminal_owner) {
        if (memcmp(r,&zero,sizeof(zero))) return BH_TX_REJECTED;
        return outcome(r,BH_TX_UNAVAILABLE);
    }
    if (leaf_range_overlap(t,owner,sizeof(*owner)) || leaf_range_overlap(t,r,sizeof(*r)) ||
        leaf_range_overlap(t,diagnostic_claim,sizeof(*diagnostic_claim))) return BH_TX_REJECTED;
    if (memcmp(r,&zero,sizeof(zero))) return BH_TX_REJECTED;
    if (t->observation_failed || t->state_observation_failed || t->codec_observation_failed ||
        t->leaf_digest_failed) return outcome(r,BH_TX_UNAVAILABLE);
    if (t->leaf_digest_done || !t->observation_done || !t->state_observation_done ||
        !t->codec_observation_done || !t->saved_parameters_valid) return outcome(r,BH_TX_REJECTED);
    struct bh_tx_leaf_claim claim;
    memcpy(&claim,diagnostic_claim,sizeof(claim));
    size_t version_length = leaf_version_length(&t->install.version);
    if (!claim.epoch || claim.key_state < 1 || claim.key_state > 3 || !version_length)
        return leaf_failure(t,r,BH_TX_REJECTED);
    if (!t->snapshots[0] || t->snapshot_lengths[0] < 49 || t->snapshot_lengths[0] > 65584 ||
        !t->snapshots[1] || t->snapshot_lengths[1] != 64 ||
        !t->snapshots[2] || t->snapshot_lengths[2] < 17 || t->snapshot_lengths[2] > 65552 ||
        !t->state_snapshots[0] || !t->state_snapshot_lengths[0] ||
        t->state_snapshot_lengths[0] > BH_JOURNAL_MAX_BYTES ||
        !t->state_snapshots[1] || !t->state_snapshot_lengths[1] ||
        t->state_snapshot_lengths[1] > BH_SELECTOR_MAX_BYTES)
        return leaf_failure(t,r,BH_TX_UNAVAILABLE);
    bh_journal_candidate candidate = {0};
    if (CC_SHA256(t->snapshots[0],(CC_LONG)t->snapshot_lengths[0],candidate.policy_digest) !=
        candidate.policy_digest) return leaf_failure(t,r,BH_TX_UNAVAILABLE);
    if (CC_SHA256(t->snapshots[2],(CC_LONG)t->snapshot_lengths[2],candidate.manifest_digest) !=
        candidate.manifest_digest) return leaf_failure(t,r,BH_TX_UNAVAILABLE);
    memcpy(candidate.installation_id,t->saved_parameters.installation_id,sizeof(candidate.installation_id));
    candidate.epoch = claim.epoch;
    candidate.key_state = (uint8_t)claim.key_state;
    if (claim.key_state != 1)
        memcpy(candidate.new_key_id,t->saved_parameters.new_key_id,sizeof(candidate.new_key_id));
    candidate.version_length = version_length;
    memcpy(candidate.version_id,t->install.version.components[t->install.version.count-1],version_length);
    bh_journal_snapshot journal = {t->state_snapshots[0],t->state_snapshot_lengths[0],1};
    bh_journal_snapshot selector = {t->state_snapshots[1],t->state_snapshot_lengths[1],1};
    bh_journal_observation observation = bh_journal_observe(journal,selector,
        &t->saved_parameters,BH_JOURNAL_SAME_EPOCH_CANDIDATE,&candidate);
    if (observation.outcome != BH_JOURNAL_CONSISTENT_ONLY)
        return leaf_failure(t,r,observation.outcome == BH_JOURNAL_OFF_REJECT ?
            BH_TX_REJECTED : BH_TX_UNAVAILABLE);
    t->leaf_digest_done = 1;
    return outcome(r,BH_TX_PREPARED_UNTRUSTED);
}
uint32_t bh_v2_transaction_abort(struct bh_v2_transaction **owner, struct bh_tx_result *r) {
    if (!owner || !r || overlap(owner,sizeof(*owner),r,sizeof(*r))) return BH_TX_REJECTED;
    struct bh_v2_transaction *t = *owner;
    if (t == &terminal_owner) return outcome(r,BH_TX_UNAVAILABLE);
    if (!t) return outcome(r,BH_TX_ABORTED);
    if (overlap(t,sizeof(*t),owner,sizeof(*owner)) || overlap(t,sizeof(*t),r,sizeof(*r))) return BH_TX_REJECTED;
    *owner = NULL;
    free_state_snapshots(t);
    free_snapshots(t);
    int failed = release(t);
    if (t->uncertain) failed = 1;
    bh_tx_os_free(t);
    if (failed) *owner = &terminal_owner;
    return outcome(r,failed ? BH_TX_UNAVAILABLE : BH_TX_ABORTED);
}
