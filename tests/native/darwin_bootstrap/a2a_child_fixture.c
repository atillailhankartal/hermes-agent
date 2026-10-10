#include "../../../native/darwin_bootstrap/abi_v1.h"

#include <CommonCrypto/CommonHMAC.h>
#include <string.h>
#include <unistd.h>

/* Disposable child checks the actual post-posix_spawn map; no product broker. */
int main(void) {
    unsigned char frame[152];
    unsigned char expected[32];
    unsigned char key[32] = {0};
    size_t received = 0;
    char signal = 'K';
    if (bh_a2a_stage0_validate() != BH_A2A_OK) return 41;
    while (received < sizeof(frame)) {
        ssize_t count = read(4, frame + received, sizeof(frame) - received);
        if (count <= 0) return 42;
        received += (size_t)count;
    }
    key[0] = 4; /* disposable fixture key; never a product credential */
    CCHmac(kCCHmacAlgSHA256, key, sizeof(key), frame, 120, expected);
    if (frame[3] != 1 || frame[7] != 1 || frame[15] != 1 || frame[87] != 4 ||
        memcmp(frame + 120, expected, sizeof(expected)) != 0) return 45;
    if (bh_a2a_stage0_validate() != BH_A2A_OK) return 43;
    if (write(4, &signal, 1) != 1) return 44;
    return 0;
}
