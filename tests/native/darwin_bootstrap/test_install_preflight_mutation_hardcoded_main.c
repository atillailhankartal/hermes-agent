#include <stdio.h>

/* Deliberately wrong oracle: ignores the linked core result. */
int main(void) {
    (void)puts("UNAVAILABLE reason=no_policy synthetic=false installed_authority=false");
    return 69;
}
