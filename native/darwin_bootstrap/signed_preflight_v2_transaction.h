#ifndef BH_V2_TRANSACTION_H
#define BH_V2_TRANSACTION_H
#include <stddef.h>
#include <stdint.h>
#define BH_TX_ABI 1u
#define BH_TX_COMPONENTS 4u
#define BH_TX_NAME 64u
struct bh_v2_transaction;
struct bh_tx_path { uint32_t count; char components[BH_TX_COMPONENTS][BH_TX_NAME]; };
struct bh_tx_install {
    uint32_t abi_version, struct_size;
    uint64_t anchor_device, anchor_inode;
    uint32_t uid, gid;
    struct bh_tx_path version, lock_parent, floor_parent, selector_parent;
    char lock_name[BH_TX_NAME], floor_name[BH_TX_NAME], selector_name[BH_TX_NAME];
};
enum bh_tx_status { BH_TX_REJECTED = 1, BH_TX_UNAVAILABLE = 2, BH_TX_PREPARED_UNTRUSTED = 3, BH_TX_ABORTED = 4 };
struct bh_tx_result { uint32_t status, installed_authority, ready, pair; int64_t pid; };
/* Dormant acquisition only: no signature verification, writer exclusion,
 * anti-rollback, durability or launch authority. Single-threaded owner; copying
 * its pointer does not transfer ownership. The caller must serialize use.
 * Only *owner == NULL may begin. Both output ranges must be disjoint from
 * install and each other. Invalid/live calls preserve caller bytes. Begin
 * copies the immutable descriptor. Dup shares the anchor open description;
 * caller must not mutate shared status flags while the context is live.
 * Caller-provided descriptor and anchor do not establish protected-root trust. Result is always OFF/PID0, never authority.
 * Ambiguous begin lock acquisition or cleanup (including transient enumeration
 * handles) and ambiguous abort cleanup latch a non-NULL terminal owner. Known
 * lock contention or clean acquisition rejection leaves owner NULL, but does
 * not establish safe retry. Recovery inspection/admission is not implemented.
 * Successful abort releases known ownership and NULLs *owner; repeated abort
 * is inert and ABORTED. Ambiguous abort cleanup retires all known generations
 * without retry, but cannot prove the OS released every resource. It leaves a
 * non-NULL opaque terminal owner: repeated abort remains UNAVAILABLE without
 * OS calls, even if result is cleared; begin on that owner remains REJECTED.
 * The caller must not clear/copy/free/reuse a terminal owner, or retry any saved
 * FD integer. Quarantine and terminate the process before retrying work: an
 * ambiguous close may have left a handle live or recycled its integer. The
 * marker records failure only; it is never a live context or release proof. */
uint32_t bh_v2_transaction_begin(int borrowed_anchor, const struct bh_tx_install *install,
    struct bh_v2_transaction **owner, struct bh_tx_result *result);
/* One-shot OFF-only diagnostic of the original retained leaf descriptions.
 * A stable observation remains untrusted and grants no launch authority.
 * The live owner retains private bounded snapshots until abort. */
uint32_t bh_v2_transaction_observe_retained(struct bh_v2_transaction **owner,
    struct bh_tx_result *result);
/* One-shot OFF-only diagnostic of the original retained local floor/selector
 * descriptions. Requires successful leaf observation first. Both snapshots
 * remain private until abort; no format, witness, or admission proof is made. */
uint32_t bh_v2_transaction_observe_local_state(struct bh_v2_transaction **owner,
    struct bh_tx_result *result);
uint32_t bh_v2_transaction_abort(struct bh_v2_transaction **owner, struct bh_tx_result *result);
#endif
