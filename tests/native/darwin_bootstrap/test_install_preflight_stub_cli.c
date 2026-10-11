#include <stdio.h>

/* Deliberately wrong no-policy CLI. Not the real CMake executable. */
int main(void) {
    (void)puts("OBSERVED_UNTRUSTED synthetic=true installed_authority=false");
    return 0;
}
