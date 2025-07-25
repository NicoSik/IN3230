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

#define MIP_SDU_TYPE_ARP 0x01
#define MIP_SDU_TYPE_PING 0x02
#define ARP_REQUEST 0x00
#define ARP_RESPONSE 0x01

typedef struct
{
    uint8_t mip_addr;
    uint8_t mac_addr[6];
    int valid;
} mip_arp_entry_t;

typedef struct
{
    mip_arp_entry_t entries[MAX_MIP_ADDRS];
} mip_arp_cache_t;

typedef struct
{
    int sock;
    int if_index;
    uint8_t mac[6];
} raw_socket_info_t;

struct ether_frame
{
    uint8_t dst_addr[6];
    uint8_t src_addr[6];
    uint16_t eth_proto;
} __attribute__((packed));
