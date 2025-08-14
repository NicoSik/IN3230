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
#define MIP_SDU_TYPE_ARP 0x01
#define MIP_SDU_TYPE_PING 0x02
#define ARP_REQUEST 0x00
#define ARP_RESPONSE 0x01
#define ETH_PROTOCOL 0x88B5

#define MIP_GET_TTL(hdr) (((hdr)->ttl_len_high >> 4) & 0x0F)
// MIP header bit manipulation

#define MIP_GET_SDU_LEN(hdr) \
    ((((hdr)->ttl_len_high & 0x0F) << 5) | (((hdr)->len_low_type >> 3) & 0x1F))

#define MIP_GET_SDU_TYPE(hdr) ((hdr)->len_low_type & 0x07)

#define MIP_SET_TTL(hdr, ttl) \
    ((hdr)->ttl_len_high = ((ttl & 0x0F) << 4) | ((hdr)->ttl_len_high & 0x0F))

#define MIP_SET_SDU_LEN(hdr, len)                            \
    do                                                       \
    {                                                        \
        (hdr)->ttl_len_high = ((hdr)->ttl_len_high & 0xF0) | \
                              (((len) >> 5) & 0x0F);         \
        (hdr)->len_low_type = ((hdr)->len_low_type & 0x07) | \
                              (((len) & 0x1F) << 3);         \
    } while (0)

#define MIP_SET_SDU_TYPE(hdr, type) \
    ((hdr)->len_low_type = ((hdr)->len_low_type & 0xF8) | ((type) & 0x07))

#endif
