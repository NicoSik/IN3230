#pragma once

#include <stdint.h>
#include <netpacket/packet.h>
#include <sys/un.h>

#define ETH_PROTOCOL 0x88B5
#define MAX_CONNECTIONS 2
#define MAX_MIP_ADDRS 255

// MIP header bit manipulation
#define MIP_GET_TTL(hdr) (((hdr)->ttl_len_high >> 4) & 0x0F)

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

#define ARP_REQUEST 0x00
#define ARP_RESPONSE 0x01
