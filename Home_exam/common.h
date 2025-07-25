#include <stdint.h>
#ifndef COMMON_H
#define COMMON_H

// MIP Header Structure
struct mip_header_raw
{
    uint8_t dst_addr;     // Byte 0: bits 31–24
    uint8_t src_addr;     // Byte 1: bits 23–16
    uint8_t ttl_len_high; // Byte 2:
                          //   bits 7–4: TTL (bits 15–12)
                          //   bits 3–0: SDU len bits [8:5] (bits 11–8)

    uint8_t len_low_type; // Byte 3:
                          //   bits 7–3: SDU len bits [4:0] (bits 7–3)
                          //   bits 2–0: SDU type (bits 2–0)
};

#endif
