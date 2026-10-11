#include "../../../native/darwin_bootstrap/install_preflight.h"

/* Intentionally wrong GREEN impersonator for the behavioral RED phase. */
struct bh_ip_result bh_install_preflight(const struct bh_ip_test_policy *policy,
                                         const struct bh_ip_provider *provider) {
    (void)policy;
    (void)provider;
    struct bh_ip_result wrong = {BH_IP_OBSERVED_UNTRUSTED, BH_IP_REASON_NONE, 1, 0};
    return wrong;
}

struct bh_ip_provider bh_install_preflight_unavailable_provider(void) {
    struct bh_ip_provider provider = {BH_IP_PROVENANCE_NO_POLICY, NULL, NULL};
    return provider;
}

const char *bh_install_preflight_reason(enum bh_ip_reason reason) {
    (void)reason;
    return "wrong";
}
