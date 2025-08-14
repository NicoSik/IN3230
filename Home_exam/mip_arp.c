#include "common.h"
#include "mip_arp.h"
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

extern mip_arp_cache_t arp_cache;

void arp_cache_insert(mip_arp_cache_t *cache, uint8_t mip, uint8_t *mac, int if_index)
{
    (void)if_index; // Suppress unused parameter warning
    cache->entries[mip].mip_addr = mip;
    memcpy(cache->entries[mip].mac_addr, mac, 6);
    cache->entries[mip].valid = 1;
}
mip_arp_entry_t *arp_cache_lookup(mip_arp_cache_t *cache, uint8_t mip)
{
    if (cache->entries[mip].valid)
        return &cache->entries[mip];
    return NULL;
}
int send_arp_request(raw_socket_info_t raw_info, uint8_t my_mip, uint8_t target_mip)
{
    struct ether_mip_arp_frame
    {
        struct ether_frame eth;
        struct mip_header_raw mip;
        uint8_t payload[4]; // Contains the target MIP address
    } __attribute__((packed));

    struct ether_mip_arp_frame frame;
    struct sockaddr_ll dest_sockaddr;
    struct msghdr msg;
    struct iovec iov;

    // STEP 1: Construct frame header
    memset(&frame, 0, sizeof(frame));
    memset(&dest_sockaddr, 0, sizeof(dest_sockaddr));

    frame.payload[0] = ARP_REQUEST; // ARP request
    frame.payload[1] = target_mip;  // Target MIP address
    frame.payload[2] = 0x00;        // Padding
    frame.payload[3] = 0x00;        // Padding

    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(frame.eth.dst_addr, broadcast_mac, 6);
    memcpy(frame.eth.src_addr, raw_info.mac, 6);
    frame.eth.eth_proto = htons(ETH_PROTOCOL);

    // STEP 1 (continued): Construct MIP header
    frame.mip.dst_addr = 0xFF; // broadcast
    frame.mip.src_addr = my_mip;
    MIP_SET_TTL(&frame.mip, 1);     // TTL = 1 for ARP, for now?
    MIP_SET_SDU_LEN(&frame.mip, 1); // 4 bytes = 1 word
    MIP_SET_SDU_TYPE(&frame.mip, MIP_SDU_TYPE_ARP);

    // STEP 2: Point msg vec to frame buffer
    iov.iov_base = &frame;
    iov.iov_len = sizeof(frame);

    // STEP 3: Construct msg header
    dest_sockaddr.sll_family = AF_PACKET;
    dest_sockaddr.sll_ifindex = raw_info.if_index;
    dest_sockaddr.sll_halen = 6;
    memcpy(dest_sockaddr.sll_addr, broadcast_mac, 6);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &dest_sockaddr;
    msg.msg_namelen = sizeof(dest_sockaddr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // STEP 4: Send message
    int rc = sendmsg(raw_info.sock, &msg, 0);
    if (rc == -1)
    {
        perror("sendmsg (ARP request)");
        return -1;
    }
    else
    {
        printf("[DEBUG] Sent ARP request for MIP %u\n", target_mip);
    }
    return 0;
}

void handle_arp_packet(struct ether_frame *eth, struct mip_header_raw *mip, uint8_t *payload,
                       raw_socket_info_t raw_info, int mip_addr)
{
    if (payload[0] == ARP_REQUEST)
    {
        uint8_t target_mip = payload[1];
        if (target_mip == mip_addr)
        {
            // Prepare ARP response
            struct
            {
                struct ether_frame eth;
                struct mip_header_raw mip;
                uint8_t payload[4];
            } __attribute__((packed)) resp;

            memset(&resp, 0, sizeof(resp));
            memcpy(resp.eth.dst_addr, eth->src_addr, 6);
            memcpy(resp.eth.src_addr, raw_info.mac, 6);
            resp.eth.eth_proto = htons(ETH_PROTOCOL);

            resp.mip.dst_addr = mip->src_addr;
            resp.mip.src_addr = mip_addr;
            MIP_SET_TTL(&resp.mip, 1);
            MIP_SET_SDU_LEN(&resp.mip, 1); // 4 bytes = 1 word
            MIP_SET_SDU_TYPE(&resp.mip, MIP_SDU_TYPE_ARP);

            resp.payload[0] = ARP_RESPONSE;
            resp.payload[1] = mip_addr;
            resp.payload[2] = 0x00;
            resp.payload[3] = 0x00;

            struct sockaddr_ll sll = {0};
            sll.sll_family = AF_PACKET;
            sll.sll_ifindex = raw_info.if_index;
            sll.sll_halen = 6;
            memcpy(sll.sll_addr, eth->src_addr, 6);

            struct msghdr msg = {0};
            struct iovec iov = {0};
            iov.iov_base = &resp;
            iov.iov_len = sizeof(resp);
            msg.msg_name = &sll;
            msg.msg_namelen = sizeof(sll);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            arp_cache_insert(&arp_cache, mip->src_addr, eth->src_addr, raw_info.if_index);

            sendmsg(raw_info.sock, &msg, 0);
            printf("[DEBUG] Sent ARP response\n");
        }
    }
    else if (payload[0] == ARP_RESPONSE)
    {
        // Learn the MAC <-> MIP mapping
        printf("[DEBUG] Received ARP response\n");
        arp_cache_insert(&arp_cache, mip->src_addr, eth->src_addr, raw_info.if_index);
    }
}