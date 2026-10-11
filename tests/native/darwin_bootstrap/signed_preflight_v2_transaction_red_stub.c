/* Deliberately inert RED target, test-local only. Never a production adapter. */
#include "signed_preflight_v2_transaction_test_api.h"
uint32_t bh_v2_transaction_begin(int fd, const struct bh_tx_install *install,
    struct bh_v2_transaction **owner, struct bh_tx_result *out) {
    (void)fd; (void)install; (void)owner; (void)out;
    return BH_TX_UNAVAILABLE;
}
uint32_t bh_v2_transaction_abort(struct bh_v2_transaction **owner, struct bh_tx_result *out) {
    (void)owner; (void)out;
    return BH_TX_UNAVAILABLE;
}
