#include "install_preflight.h"

struct bh_ip_provider bh_install_preflight_unavailable_provider(void) {
    struct bh_ip_provider provider = {BH_IP_PROVENANCE_NO_POLICY, NULL, NULL};
    return provider;
}
