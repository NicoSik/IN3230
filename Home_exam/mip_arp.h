#pragma once
#include <stdint.h>
#include "common.h"
typedef struct
{
    uint8_t mip_addr;
    uint8_t mac_addr[6];
    int valid;
} mip_arp_entry_t;

typedef struct
{
    mip_arp_entry_t entries[255]; // 0-254 are valid addresses
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

int send_arp_request(raw_socket_info_t raw_info, uint8_t my_mip, uint8_t target_mip);
int send_arp_response(raw_socket_info_t raw_info, uint8_t src_mip, uint8_t dst_mip, uint8_t *dst_mac);
void handle_arp_packet(struct ether_frame *eth, struct mip_header_raw *mip, uint8_t *payload,
                       raw_socket_info_t raw_info, int mip_addr);
void arp_cache_insert(mip_arp_cache_t *cache, uint8_t mip, uint8_t *mac, int if_index);
mip_arp_entry_t *arp_cache_lookup(mip_arp_cache_t *cache, uint8_t mip);
