#include "../../../native/darwin_bootstrap/install_preflight.h"

#ifndef BH_IP_MUTATION_KIND
#error "Select a test-only mutation kind"
#endif

/* Deliberately invalid core outcome. Linked only into a disposable CLI test. */
struct bh_ip_result bh_install_preflight(const struct bh_ip_test_policy *policy,
                                         const struct bh_ip_provider *provider) {
    (void)policy;
    (void)provider;
#if BH_IP_MUTATION_KIND == 1
    struct bh_ip_result wrong = {BH_IP_OBSERVED_UNTRUSTED, BH_IP_REASON_NONE, 1, 0};
#elif BH_IP_MUTATION_KIND == 2
    struct bh_ip_result wrong = {BH_IP_UNAVAILABLE, BH_IP_REASON_NO_POLICY, 0, 1};
#else
#error "Unknown test-only mutation kind"
#endif
    return wrong;
}

const char *bh_install_preflight_reason(enum bh_ip_reason reason) {
    (void)reason;
    return "no_policy";
}
