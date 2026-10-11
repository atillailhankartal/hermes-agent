#include "../../../native/darwin_bootstrap/install_preflight.h"
#include <string.h>

static int synthetic_observe(void *context, struct bh_ip_observation *out) {
    if (context == NULL || out == NULL) return -1;
    memcpy(out, context, sizeof(*out));
    return 0;
}

/* This symbol belongs only in the test target. It never proves installed trust. */
struct bh_ip_provider bh_ip_test_synthetic_provider(struct bh_ip_observation *observation) {
    struct bh_ip_provider provider = {BH_IP_PROVENANCE_TEST_SYNTHETIC,
                                      synthetic_observe, observation};
    return provider;
}
