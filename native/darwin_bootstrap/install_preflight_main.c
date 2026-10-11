#include "install_preflight.h"

#include <stdio.h>

int main(void) {
    const struct bh_ip_provider provider = bh_install_preflight_unavailable_provider();
    const struct bh_ip_result checked = bh_install_preflight(NULL, &provider);
    if (checked.status != BH_IP_UNAVAILABLE || checked.reason != BH_IP_REASON_NO_POLICY ||
        checked.synthetic != 0 || checked.installed_authority != 0) {
        (void)puts("UNAVAILABLE reason=internal_error synthetic=false installed_authority=false");
        return 70;
    }
    (void)printf("UNAVAILABLE reason=%s synthetic=false installed_authority=false\n",
                 bh_install_preflight_reason(checked.reason));
    return 69;
}
