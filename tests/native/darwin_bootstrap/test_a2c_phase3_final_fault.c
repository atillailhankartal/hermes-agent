/* Adversarial fixture peer. Real writes/half-closes; no successful return is fabricated. */
#include "../../../native/darwin_bootstrap/a2c_phase3_policy.h"
#include "../../../native/darwin_bootstrap/a2c_phase3_io.h"
#include <string.h>
#include <time.h>
#ifndef BH_A2C_RECEIPT_FAULT
#error "compile-time fixture case required"
#endif
static int fault_receipt(struct bh_a2c_phase3_io *io, const void *data, size_t length) {
    unsigned char bytes[66];
    if (length != 33) return 0;
    memcpy(bytes, data, length);
    if (BH_A2C_RECEIPT_FAULT == 1) bytes[0] = 'F';
    if (BH_A2C_RECEIPT_FAULT == 2) bytes[1] ^= 1;
    if (BH_A2C_RECEIPT_FAULT == 3) length = 16;
    if (BH_A2C_RECEIPT_FAULT == 4) length = 0;
    if (BH_A2C_RECEIPT_FAULT == 5) { memcpy(bytes + 33, bytes, 33); length = 66; }
    return bh_a2c_phase3_write(io, bytes, length);
}
static int fault_half_close(struct bh_a2c_phase3_io *io) {
    if (BH_A2C_RECEIPT_FAULT >= 6) {
        struct timespec delay = { .tv_sec = BH_A2C_RECEIPT_FAULT == 8 ? 2 : 0,
                                  .tv_nsec = 200000000 };
        (void)nanosleep(&delay, NULL);
    }
    if (BH_A2C_RECEIPT_FAULT == 6 && !bh_a2c_phase3_write(io, "!", 1)) return 0;
    return bh_a2c_phase3_shutdown(io);
}
#define bh_a2c_phase3_write fault_receipt
#define bh_a2c_phase3_shutdown fault_half_close
#include "../../../native/darwin_bootstrap/final_entry.c"
