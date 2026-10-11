#include "signed_preflight_v2_transaction_test_api.h"
#include "signed_preflight_v2_transaction_test_os.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "ASSERT %s variant=%d line=%d: %s\n", current, variant, __LINE__, #x); ok = 0; } } while (0)
#define LIMIT 2048
#define DIR_FLAGS (O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
#define LEAF_FLAGS (O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK)
#define STATE_FLAGS (O_RDWR|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK)
enum { ANCHOR, LOCKS, LOCK, VERSIONS, VERSION, FLOORS, SELECTORS, POLICY, SIGNATURE, MANIFEST, FLOOR, SELECTOR, NODES };
static const char *const names[NODES] = {"anchor", "locks", "install.lock", "versions", "release-7", "floors", "selectors", "policy.v2.bin", "policy.v2.sig", "release.v2.bin", "floor.journal", "current.selector"};
static const int parents[NODES] = {-1, ANCHOR, LOCKS, ANCHOR, VERSIONS, ANCHOR, ANCHOR, VERSION, VERSION, VERSION, FLOORS, SELECTORS};
struct event { char op; int node, arg; };
struct handle { int fd, node, alive, borrowed, enumeration, closes; unsigned generation; };
static struct {
    struct stat meta[NODES]; struct handle h[LIMIT]; unsigned next_generation;
    struct event events[LIMIT]; int count, handles, errors, lock_held;
    int fail_at, fail_reached, failure_errno, poison_node, poison_kind, poison_reached;
    int lock_error, lock_replaced, alias_node, alias_kind, alias_reached;
    char visible_names[NODES][BH_TX_NAME];
    int acl_live, allocations, frees, alloc_live, leaf_opens[3];
    unsigned leaf_original[3]; int close_sequence[LIMIT], closes;
    int caller_flags, caller_offset, ready, pair;
    int cleanup_mode, failed_handle, recycled_handle, quarantine_required;
    void *allocation;
} f;
static const char *current;
static int variant;
static int is_dir(int n) { return n == ANCHOR || n == LOCKS || n == VERSIONS || n == VERSION || n == FLOORS || n == SELECTORS; }
static int event(char op, int node, int arg) {
    if (f.count >= LIMIT) abort();
    f.events[f.count++] = (struct event){op,node,arg};
    if (f.fail_at == f.count) { ++f.fail_reached; errno = f.failure_errno ? f.failure_errno : EIO; return -1; }
    return 0;
}
static struct handle *handle(int fd) {
    for (int i = f.handles - 1; i >= 0; --i) if (f.h[i].fd == fd && f.h[i].alive) return &f.h[i];
    ++f.errors; return NULL;
}
static int add_handle(int node, int enumeration, int borrowed) {
    int fd = borrowed ? 9 : 32;
    for (;;) {
        int used = 0;
        for (int i = 0; i < f.handles; ++i) if (f.h[i].alive && f.h[i].fd == fd) used = 1;
        if (!used) break;
        ++fd;
    }
    if (f.handles >= LIMIT) abort();
    f.h[f.handles++] = (struct handle){fd,node,1,borrowed,enumeration,0,++f.next_generation};
    if (node >= POLICY && node <= MANIFEST && !enumeration) {
        int i = node - POLICY;
        if (!f.leaf_opens[i]++) f.leaf_original[i] = f.next_generation;
    }
    return fd;
}
static int lookup(int fd, const char *name) {
    struct handle *h = handle(fd); if (!h) return -1;
    if (!strcmp(name, ".")) return h->node;
    for (int i = 1; i < NODES; ++i) if (parents[i] == h->node && !strcmp(name,names[i])) return i;
    ++f.errors; errno = ENOENT; return -1;
}
static void reset(void) {
    if (f.allocation) free(f.allocation);
    memset(&f,0,sizeof(f)); f.poison_node = f.alias_node = f.failed_handle = f.recycled_handle = -1;
    f.caller_flags = 0x123; f.caller_offset = 37;
    for (int i = 0; i < NODES; ++i) {
        strcpy(f.visible_names[i], names[i]);
        f.meta[i].st_dev = 7; f.meta[i].st_ino = (ino_t)(100+i);
        f.meta[i].st_uid = 0; f.meta[i].st_gid = 0;
        f.meta[i].st_mode = (mode_t)(is_dir(i) ? S_IFDIR|0500 : S_IFREG|0400);
        f.meta[i].st_nlink = is_dir(i) ? 2 : 1;
        f.meta[i].st_size = i == POLICY ? 49 : i == SIGNATURE ? 64 : i == MANIFEST ? 17 : 32;
    }
    f.meta[LOCK].st_mode = S_IFREG|0600; f.meta[FLOOR].st_mode = S_IFREG|0600;
    (void)add_handle(ANCHOR,0,1);
}
static void poison(int node, struct stat *s, int opened) {
    if (node != f.poison_node) return;
    ++f.poison_reached;
    switch (f.poison_kind) {
        case 1: s->st_mode = S_IFLNK|0500; break;
        case 2: s->st_uid = 501; break;
        case 3: s->st_gid = 501; break;
        case 4: s->st_mode |= 0020; break;
        case 5: break; /* ACL presence is returned by ACL observation. */
        case 6: if (opened) ++s->st_ino; break;
        case 7: s->st_mode = S_IFDIR|0500; break;
        case 8: s->st_mode = S_IFIFO|0400; break;
        case 9: s->st_nlink = 2; break;
        case 10: s->st_size = node == POLICY ? 48 : node == SIGNATURE ? 63 : 16; break;
        case 11: s->st_size = node == POLICY ? 65585 : node == SIGNATURE ? 65 : 65553; break;
        case 12: if (opened) s->st_size = node == POLICY ? 65585 : node == SIGNATURE ? 65 : 65553; break;
        default: abort();
    }
}
int bh_tx_os_dup_cloexec(int fd) {
    struct handle *h = handle(fd); if (!h) return -1;
    if (event('D',h->node,O_CLOEXEC)) return -1;
    return add_handle(h->node,0,0);
}
int bh_tx_os_openat(int parent, const char *name, int flags) {
    int n = lookup(parent,name); if (n < 0) return -1;
    int enumeration = !strcmp(name,".");
    if (event(enumeration ? 'E' : 'O',n,flags)) return -1;
    if (flags != (is_dir(n) ? DIR_FLAGS : (n == LOCK || n == FLOOR) ? STATE_FLAGS : LEAF_FLAGS)) ++f.errors;
    struct handle *p = handle(parent); if (p && p->borrowed) ++f.errors;
    if ((n == FLOOR || n == SELECTOR) && !f.lock_held) ++f.errors;
    return add_handle(n,enumeration,0);
}
int bh_tx_os_fstat(int fd, struct stat *out) {
    struct handle *h = handle(fd); if (!h) return -1;
    if (event('S',h->node,0)) return -1;
    *out = f.meta[h->node]; poison(h->node,out,1); return 0;
}
int bh_tx_os_fstatat(int parent, const char *name, struct stat *out, int flags) {
    int n = lookup(parent,name); if (n < 0) return -1;
    if (event('T',n,flags)) return -1;
    if (flags != AT_SYMLINK_NOFOLLOW) ++f.errors;
    *out = f.meta[n]; poison(n,out,0);
    if (n == LOCK && f.lock_held && f.lock_replaced) { ++out->st_ino; ++f.poison_reached; }
    return 0;
}
int bh_tx_os_exact_name(int fd, const char *name) {
    struct handle *h = handle(fd); int n = lookup(fd,name); if (!h || n < 0) return -1;
    if (!h->enumeration || h->borrowed) ++f.errors;
    if (event('N',n,0)) return -1;
    if (n == f.alias_node) {
        ++f.alias_reached;
        if (f.alias_kind != 4) return !strcmp(name,f.visible_names[n]);
    }
    return 1;
}
void *bh_tx_os_acl_get(int fd) {
    struct handle *h = handle(fd); if (!h) return NULL;
    if (event('A',h->node,0)) return NULL;
    ++f.acl_live; return (void *)&f.meta[h->node];
}
int bh_tx_os_acl_empty(void *acl) {
    int n = (int)((struct stat *)acl - f.meta);
    if (n < 0 || n >= NODES) abort();
    if (event('V',n,0)) return -1;
    if (n == f.poison_node && f.poison_kind == 5) { ++f.poison_reached; return 0; }
    return 1;
}
int bh_tx_os_acl_free(void *acl) {
    int n = (int)((struct stat *)acl - f.meta);
    if (n < 0 || n >= NODES) abort();
    --f.acl_live; return event('Q',n,0);
}
int bh_tx_os_flock(int fd, int operation) {
    struct handle *h = handle(fd); if (!h) return -1;
    if (h->borrowed || h->node != LOCK) ++f.errors;
    if (event(operation == LOCK_UN ? 'U' : 'L',h->node,operation)) {
        if (operation == LOCK_UN) {
            f.quarantine_required = 1;
            if (f.cleanup_mode != 1) f.lock_held = 0;
        }
        return -1;
    }
    if (operation == LOCK_UN) { if (!f.lock_held) ++f.errors; f.lock_held = 0; return 0; }
    if (operation != (LOCK_EX|LOCK_NB)) ++f.errors;
    if (f.lock_error) { ++f.poison_reached; errno = f.lock_error; return -1; }
    f.lock_held = 1; return 0;
}
int bh_tx_os_close(int fd) {
    struct handle *h = handle(fd); if (!h) return -1;
    if (h->borrowed || h->closes) ++f.errors;
    if (!h->enumeration) f.close_sequence[f.closes++] = (int)h->generation;
    ++h->closes;
    int failed = event(h->enumeration ? 'e' : 'C',h->node,0);
    if (failed) {
        f.quarantine_required = 1; f.failed_handle = (int)(h-f.h);
        if (f.cleanup_mode == 1) return -1; /* Error before release: OS ownership uncertain. */
    }
    h->alive = 0;
    if (h->node == LOCK) f.lock_held = 0;
    if (failed && f.cleanup_mode == 3) {
        /* Another owner obtains exactly this integer after kernel release.
         * Keep its generation distinct and fail any attempted second close. */
        if (f.handles >= LIMIT) abort();
        f.recycled_handle = f.handles;
        f.h[f.handles++] = (struct handle){fd,-1,1,1,0,0,++f.next_generation};
    }
    return failed;
}
void *bh_tx_os_alloc(size_t n) {
    ++f.allocations;
    if (event('M',-1,0)) return NULL;
    if (f.allocation || n == 0) abort();
    f.allocation = calloc(1,n); if (f.allocation) ++f.alloc_live;
    return f.allocation;
}
void bh_tx_os_free(void *p) {
    if (!p || p != f.allocation) { ++f.errors; return; }
    (void)event('F',-1,0); free(p); f.allocation = NULL; --f.alloc_live; ++f.frees;
}

/* Independent trace oracle for the acquisition-only protocol. These events
 * are generated from the fixture contract, never captured from the SUT. */
static struct event expected[LIMIT]; static int expected_count;
static void want(char op,int node,int arg) { expected[expected_count++] = (struct event){op,node,arg}; }
static void want_acl(int n) { want('A',n,0); want('V',n,0); want('Q',n,0); }
static void want_open(int n) {
    int p = parents[n];
    want('E',p,DIR_FLAGS); want('S',p,0); want('N',n,0); want('e',p,0);
    want('T',n,AT_SYMLINK_NOFOLLOW);
    want('O',n,is_dir(n) ? DIR_FLAGS : (n == LOCK || n == FLOOR) ? STATE_FLAGS : LEAF_FLAGS);
    want('S',n,0); want_acl(n); want('T',n,AT_SYMLINK_NOFOLLOW);
}
static void expected_begin(void) {
    expected_count = 0; want('D',ANCHOR,O_CLOEXEC); want('S',ANCHOR,0); want_acl(ANCHOR);
    want_open(LOCKS); want_open(LOCK); want('L',LOCK,LOCK_EX|LOCK_NB); want('T',LOCK,AT_SYMLINK_NOFOLLOW);
    want_open(VERSIONS); want_open(VERSION); want_open(FLOORS); want_open(SELECTORS);
    want_open(POLICY); want_open(SIGNATURE); want_open(MANIFEST);
    want_open(FLOOR); want_open(SELECTOR); want('M',-1,0);
}
static int trace_prefix(int count) {
    if (f.count < count || count > expected_count) return 0;
    for (int i = 0; i < count; ++i)
        if (f.events[i].op != expected[i].op || f.events[i].node != expected[i].node || f.events[i].arg != expected[i].arg) return 0;
    return 1;
}
static int acquisition_prefix(void) {
    int i = 0;
    while (i < f.count && f.events[i].op != 'C' && f.events[i].op != 'U' && f.events[i].op != 'F') ++i;
    /* ACL release and enumeration close on a failed operation remain local
     * cleanup, so a failure prefix may end before those cleanup events. */
    int count = f.fail_at && f.fail_reached ? f.fail_at : i;
    return count > 0 && trace_prefix(count);
}
static struct bh_tx_install install(void) {
    struct bh_tx_install d; memset(&d,0,sizeof(d)); d.abi_version = BH_TX_ABI; d.struct_size = sizeof(d);
    d.anchor_device = 7; d.anchor_inode = 100;
    d.version.count = 2; strcpy(d.version.components[0],names[VERSIONS]); strcpy(d.version.components[1],names[VERSION]);
    d.lock_parent.count = d.floor_parent.count = d.selector_parent.count = 1;
    strcpy(d.lock_parent.components[0],names[LOCKS]); strcpy(d.floor_parent.components[0],names[FLOORS]); strcpy(d.selector_parent.components[0],names[SELECTORS]);
    strcpy(d.lock_name,names[LOCK]); strcpy(d.floor_name,names[FLOOR]); strcpy(d.selector_name,names[SELECTOR]); return d;
}
static int safe_result(const struct bh_tx_result *r) { return !r->installed_authority && !r->ready && !r->pair && !r->pid && !f.ready && !f.pair; }
static int borrowed_preserved(void) {
    return f.h[0].fd == 9 && f.h[0].borrowed && f.h[0].alive && f.h[0].generation == 1 && !f.h[0].closes && f.caller_flags == 0x123 && f.caller_offset == 37;
}
static int owned_live(void) { int n = 0; for (int i = 0; i < f.handles; ++i) if (f.h[i].alive && !f.h[i].borrowed) ++n; return n; }
static int retention(void) {
    for (int n = POLICY; n <= MANIFEST; ++n) {
        int found = 0;
        if (f.leaf_opens[n-POLICY] != 1) return 0;
        for (int i = 0; i < f.handles; ++i) if (f.h[i].node == n && f.h[i].alive && f.h[i].generation == f.leaf_original[n-POLICY]) ++found;
        if (found != 1) return 0;
    }
    return 1;
}
static int cleanup_order(void) {
    int c = 0, lock_generation = -1;
    for (int i = f.handles - 1; i >= 1; --i) {
        const struct handle *h = &f.h[i];
        if (h->enumeration || h->borrowed) continue;
        if (h->node == LOCK) { lock_generation = (int)h->generation; continue; }
        if (c >= f.closes || f.close_sequence[c++] != (int)h->generation || h->closes != 1) return 0;
    }
    if (lock_generation >= 0 && (c >= f.closes || f.close_sequence[c++] != lock_generation)) return 0;
    if (c != f.closes) return 0;
    int cleanup = 0;
    for (int i = 0; i < f.count; ++i) {
        char op = f.events[i].op;
        if (op == 'C' || op == 'U' || op == 'F') cleanup = 1;
        if (cleanup && op != 'C' && op != 'U' && op != 'F') return 0;
        if (f.fail_at && f.fail_reached && i >= f.fail_at && op != 'Q' && op != 'e' && op != 'C' && op != 'U' && op != 'F') return 0;
    }
    return 1;
}
static void dump(void) {
    fprintf(stderr,"TRACE %s variant=%d count=%d injection=%d poison=%d alias=%d owned=%d acl=%d alloc=%d errors=%d\n",current,variant,f.count,f.fail_reached,f.poison_reached,f.alias_reached,owned_live(),f.acl_live,f.alloc_live,f.errors);
    for (int i = 0; i < f.count; ++i) fprintf(stderr," %c:%d:%d",f.events[i].op,f.events[i].node,f.events[i].arg);
    fputc('\n',stderr);
    for (int i = 0; i < f.handles; ++i) fprintf(stderr," FD fd=%d generation=%u node=%d borrowed=%d enumeration=%d alive=%d closes=%d\n",f.h[i].fd,f.h[i].generation,f.h[i].node,f.h[i].borrowed,f.h[i].enumeration,f.h[i].alive,f.h[i].closes);
}
static int run_variant(int which, int v) {
    int ok = 1; variant = v; reset(); expected_begin();
    struct bh_tx_install d = install(); struct bh_v2_transaction *owner = NULL;
    struct bh_tx_result r = {0}; uint32_t status;
    if (which == 0 && v >= 10) {
        union { max_align_t align; unsigned char bytes[4096]; } storage;
        memset(&storage,0,sizeof(storage)); memcpy(storage.bytes,&d,sizeof(d));
        unsigned char before[sizeof(storage.bytes)]; memcpy(before,storage.bytes,sizeof(before));
        struct bh_tx_install *di = (void *)storage.bytes;
        struct bh_v2_transaction **op = v == 11 ? (void *)storage.bytes : &owner;
        struct bh_tx_result *rp = v == 10 ? (void *)storage.bytes : &r;
        if (v == 12) { op = (void *)(storage.bytes+2048); rp = (void *)(storage.bytes+2048); }
        status = bh_v2_transaction_begin(9,di,op,rp);
        REQUIRE(status == BH_TX_REJECTED); REQUIRE(f.count == 0 && f.allocations == 0);
        REQUIRE(memcmp(before,storage.bytes,sizeof(before)) == 0);
        REQUIRE(borrowed_preserved() && f.errors == 0); dump(); return ok;
    }
    if (which == 0) {
        /* Each invalid argument variant must return before any OS/allocation. */
        if (v == 3) ++d.abi_version;
        if (v == 4) --d.struct_size;
        if (v == 5) strcpy(d.version.components[0],"..");
        if (v == 6) d.version.count = BH_TX_COMPONENTS+1;
        if (v == 7) memset(d.version.components[0],'x',BH_TX_NAME);
        if (v == 8) r.ready = 1;
        struct bh_tx_result before = r;
        status = bh_v2_transaction_begin(v == 2 ? -1 : 9,v == 1 ? NULL : &d,v == 9 ? NULL : &owner,v == 0 ? NULL : &r);
        REQUIRE(status == BH_TX_REJECTED); REQUIRE(f.count == 0 && f.allocations == 0);
        REQUIRE(memcmp(&r,&before,sizeof(r)) == 0); REQUIRE(owner == NULL);
        if (v != 8) REQUIRE(safe_result(&r));
    } else {
        if (which == 3) { const int ancestors[] = {ANCHOR,LOCKS,VERSIONS,VERSION,FLOORS,SELECTORS}; f.poison_node = ancestors[v/6]; f.poison_kind = v%6+1; }
        if (which == 4) { const int errors[] = {EWOULDBLOCK,EACCES,EINTR}; f.lock_error = errors[v]; }
        if (which == 5) f.lock_replaced = 1;
        if (which == 6) {
            const char *const aliases[] = {"POLICY.V2.BIN","policy.v1.bin","policy.v2.bin.suffix","client-selected.bin"};
            f.alias_node = POLICY+v/5; f.alias_kind = v%5;
            if (f.alias_kind < 4) strcpy(f.visible_names[f.alias_node],aliases[f.alias_kind]);
            else { f.poison_node = f.alias_node; f.poison_kind = 1; }
        }
        if (which == 7) { f.poison_node = POLICY+v/6; f.poison_kind = v%6+7; }
        if (which == 8) f.fail_at = v+1;
        status = bh_v2_transaction_begin(9,&d,&owner,&r);
        if (which == 1 || which == 2 || which == 9) {
            REQUIRE(status == BH_TX_PREPARED_UNTRUSTED && r.status == BH_TX_PREPARED_UNTRUSTED);
            REQUIRE(owner != NULL); REQUIRE(f.count == expected_count && trace_prefix(expected_count));
            REQUIRE(retention()); REQUIRE(owned_live() == 12); REQUIRE(f.lock_held == 1);
            if (which == 1) {
                struct bh_v2_transaction *saved = owner; struct bh_tx_result saved_result = r;
                int calls = f.count, handles = f.handles;
                REQUIRE(bh_v2_transaction_begin(9,&d,&owner,&r) == BH_TX_REJECTED);
                REQUIRE(owner == saved && memcmp(&r,&saved_result,sizeof(r)) == 0 && calls == f.count && handles == f.handles);
                REQUIRE(retention());
            }
            /* Copy contract: caller can retire descriptor storage after begin. */
            memset(&d,0xa5,sizeof(d));
            REQUIRE(bh_v2_transaction_abort(&owner,&r) == BH_TX_ABORTED);
            REQUIRE(r.status == BH_TX_ABORTED && owner == NULL);
            int calls = f.count;
            REQUIRE(bh_v2_transaction_abort(&owner,&r) == BH_TX_ABORTED);
            REQUIRE(calls == f.count);
        } else {
            uint32_t wanted = which == 4 || which == 5 || which == 8 ? BH_TX_UNAVAILABLE : BH_TX_REJECTED;
            REQUIRE(status == wanted && r.status == wanted); REQUIRE(owner == NULL);
            REQUIRE(acquisition_prefix());
            if (which == 3) { REQUIRE(f.poison_reached > 0); REQUIRE(f.leaf_opens[0]+f.leaf_opens[1]+f.leaf_opens[2] == 0); }
            if (which == 4 || which == 5) {
                REQUIRE(f.poison_reached == 1);
                for (int i = 0; i < f.count; ++i) REQUIRE(f.events[i].node != FLOOR && f.events[i].node != SELECTOR);
            }
            if (which == 6) REQUIRE(f.alias_reached == 1);
            if (which == 7) { REQUIRE(f.poison_reached > 0); REQUIRE(f.allocations == 0); }
            if (which == 8) REQUIRE(f.fail_reached == 1);
        }
        REQUIRE(safe_result(&r)); REQUIRE(owned_live() == 0 && f.acl_live == 0 && f.alloc_live == 0);
        REQUIRE(cleanup_order());
    }
    REQUIRE(borrowed_preserved()); REQUIRE(f.errors == 0); dump(); return ok;
}
static int mutation_oracle(void) {
    int ok = 1; variant = 0; reset();
    int fd[3]; for (int i = 0; i < 3; ++i) fd[i] = add_handle(POLICY+i,0,0);
    REQUIRE(retention()); unsigned old = f.leaf_original[0]; ino_t inode = f.meta[POLICY].st_ino;
    REQUIRE(bh_tx_os_close(fd[0]) == 0);
    int replacement = add_handle(POLICY,0,0);
    REQUIRE(replacement == fd[0] && f.meta[POLICY].st_ino == inode);
    REQUIRE(handle(replacement)->generation != old); REQUIRE(!retention());
    for (int i = 1; i < 3; ++i) REQUIRE(bh_tx_os_close(fd[i]) == 0);
    REQUIRE(bh_tx_os_close(replacement) == 0); REQUIRE(borrowed_preserved()); dump(); return ok;
}
static int abort_ambiguity(void) {
    int ok = 1;
    /* Twelve retained closes plus unlock; every event can fail with EIO/EINTR.
     * The fake consumes a close even on failure, exposing unsafe retries. */
    for (int error = 0; error < 2; ++error) for (int at = 1; at <= 13; ++at) {
        variant = error*13+at; reset(); expected_begin();
        struct bh_tx_install d = install();
        struct bh_v2_transaction *owner = NULL;
        struct bh_tx_result r = {0};
        REQUIRE(bh_v2_transaction_begin(9,&d,&owner,&r) == BH_TX_PREPARED_UNTRUSTED);
        f.fail_at = f.count+at; f.failure_errno = error ? EINTR : EIO;
        REQUIRE(bh_v2_transaction_abort(&owner,&r) == BH_TX_UNAVAILABLE);
        REQUIRE(r.status == BH_TX_UNAVAILABLE && safe_result(&r) && owner != NULL);
        REQUIRE(f.fail_reached == 1 && owned_live() == 0 && f.alloc_live == 0);
        REQUIRE(cleanup_order() && borrowed_preserved() && !f.errors);
        int calls = f.count;
        REQUIRE(bh_v2_transaction_abort(&owner,&r) == BH_TX_UNAVAILABLE && r.status == BH_TX_UNAVAILABLE && safe_result(&r) && calls == f.count);
        dump();
    }
    return ok;
}
/* Twelve closes x EIO/EINTR x before/after/recycled + unlock x
 * EIO/EINTR x before/after = 76 isolated terminal-owner variants. */
static int terminal_latch(int v) {
    int ok = 1; variant = v; reset(); expected_begin();
    struct bh_tx_install d = install(); struct bh_v2_transaction *owner = NULL;
    struct bh_v2_transaction *unrelated_owner = NULL;
    struct bh_tx_result r = {0}, unrelated_result = {BH_TX_ABORTED,0,0,0,0};
    struct bh_tx_result unrelated_before = unrelated_result;
    /* A descriptor owned outside this transaction is independently guarded. */
    int unrelated_index = f.handles;
    f.h[f.handles++] = (struct handle){1000,-1,1,1,0,0,++f.next_generation};
    struct handle unrelated_fd = f.h[unrelated_index];
    REQUIRE(bh_v2_transaction_begin(9,&d,&owner,&r) == BH_TX_PREPARED_UNTRUSTED);
    int at;
    if (v < 72) {
        int position = v/6; at = position < 11 ? position+1 : 13;
        f.cleanup_mode = v%3+1; f.failure_errno = (v/3)%2 ? EINTR : EIO;
    } else {
        at = 12; f.cleanup_mode = (v-72)%2+1; f.failure_errno = (v-72)/2 ? EINTR : EIO;
    }
    f.fail_at = f.count+at;
    REQUIRE(bh_v2_transaction_abort(&owner,&r) == BH_TX_UNAVAILABLE);
    REQUIRE(r.status == BH_TX_UNAVAILABLE && safe_result(&r));
    REQUIRE(f.fail_reached == 1 && f.quarantine_required == 1);
    /* A non-NULL opaque terminal owner is a latch, not a releasable live owner.
     * Resetting the writable result must never erase that lifetime failure. */
    REQUIRE(owner != NULL);
    struct bh_v2_transaction *terminal_owner = owner;
    int calls = f.count, closes = f.closes, allocations = f.allocations;
    memset(&r,0,sizeof(r));
    REQUIRE(bh_v2_transaction_abort(&owner,&r) == BH_TX_UNAVAILABLE);
    REQUIRE(r.status == BH_TX_UNAVAILABLE && safe_result(&r));
    REQUIRE(owner == terminal_owner && f.count == calls && f.closes == closes);
    memset(&r,0,sizeof(r));
    REQUIRE(bh_v2_transaction_begin(9,&d,&owner,&r) == BH_TX_REJECTED);
    REQUIRE(owner == terminal_owner && f.count == calls && f.allocations == allocations);
    REQUIRE(safe_result(&r));
    REQUIRE(unrelated_owner == NULL && memcmp(&unrelated_result,&unrelated_before,sizeof(unrelated_result)) == 0);
    REQUIRE(memcmp(&f.h[unrelated_index],&unrelated_fd,sizeof(unrelated_fd)) == 0);
    REQUIRE(borrowed_preserved() && f.errors == 0 && f.alloc_live == 0 && f.acl_live == 0);
    REQUIRE(owned_live() == (v < 72 && f.cleanup_mode == 1 ? 1 : 0));
    REQUIRE(cleanup_order());
    if (v < 72) {
        REQUIRE(f.failed_handle >= 0);
        if (f.failed_handle >= 0) {
            REQUIRE(f.h[f.failed_handle].closes == 1);
            REQUIRE(f.h[f.failed_handle].alive == (f.cleanup_mode == 1));
        }
        if (f.cleanup_mode == 3) {
            REQUIRE(f.recycled_handle >= 0);
            if (f.recycled_handle >= 0 && f.failed_handle >= 0) {
                struct handle *old = &f.h[f.failed_handle], *fresh = &f.h[f.recycled_handle];
                REQUIRE(fresh->fd == old->fd && fresh->generation != old->generation);
                REQUIRE(fresh->alive && fresh->borrowed && fresh->closes == 0);
            }
        }
    }
    fprintf(stderr,"QUARANTINE required=%d mode=%d errno=%d fault_event=%d failed_generation=%u recycled_generation=%u; terminate process before retry; no OS release claim\n",
        f.quarantine_required,f.cleanup_mode,f.failure_errno,f.fail_at,
        f.failed_handle < 0 ? 0 : f.h[f.failed_handle].generation,
        f.recycled_handle < 0 ? 0 : f.h[f.recycled_handle].generation);
    dump(); return ok;
}
struct test_case { const char *name; int variants; };
static const struct test_case cases[] = {
    {"Begin_WhenArgumentsOrAbiAreInvalid_RejectsBeforeOsCalls",13},
    {"Begin_WhenContextIsLive_RejectsReuseAndPreservesOwner",1},
    {"Begin_WhenAnchorIsBorrowed_PreservesCallerDescription",1},
    {"Begin_WhenAncestorIsUntrusted_RejectsBeforeLeafOpen",36},
    {"Begin_WhenLockIsBusyOrUnknown_ReturnsUnavailable",3},
    {"Begin_WhenLockPathIsReplaced_ReturnsUnavailable",1},
    {"Begin_WhenLeafNamesAreAliases_RejectsFrozenNameSubstitution",15},
    {"Begin_WhenLeafTypeLinkOrBoundsAreInvalid_RejectsBeforeAllocation",18},
    {"Begin_WhenAnyAcquireFails_ReleasesOnlyOwnedResources",-1},
    {"Begin_WhenStableBundleIsPrepared_RetainsOriginalDescriptionsUntilAbort",1},
    {"Harness_WhenLeafReopensWithSameIntegerAndInode_RetentionOracleRejects",1},
    {"Abort_WhenCleanupFails_LatchesUnavailableAndRejectsOwnerReuse",76}
};
int main(void) {
    int passed = 0, variants = 0; size_t count = sizeof(cases)/sizeof(cases[0]);
    if (count != 12) { fprintf(stderr,"FAIL empty or changed registry\n"); return 2; }
    expected_begin(); int acquisitions = expected_count;
    for (size_t i = 0; i < count; ++i) {
        int ok = 1, n = cases[i].variants < 0 ? acquisitions : cases[i].variants;
        current = cases[i].name;
        if (!current[0] || n <= 0) return 2;
        for (size_t j = 0; j < i; ++j) if (!strcmp(current,cases[j].name)) return 2;
        for (int v = 0; v < n; ++v) { if (!(i == 11 ? terminal_latch(v) : i == 10 ? mutation_oracle() : run_variant((int)i,v))) ok = 0; ++variants; }
        printf("%s %s variants=%d\n",ok ? "PASS" : "FAIL",current,n); fflush(stdout); passed += ok;
    }
    printf("SUMMARY %d/%zu named cases passed; %zu failed; variants=%d; 0 skipped; frozen Begin=9; source positive=1; harness=1; terminal latch=1\n",passed,count,count-(size_t)passed,variants);
    current = "Abort_WhenUnlockOrCloseIsAmbiguous_RetiresOwnershipWithoutRetry";
    int terminal = abort_ambiguity();
    printf("%s %s variants=26; source supplement; 0 skipped\n",terminal ? "PASS" : "FAIL",current);
    reset(); return passed == (int)count && terminal ? 0 : 1;
}
