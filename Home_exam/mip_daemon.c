#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include "mip_daemon.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "common.h"
#include <poll.h>
#include <net/if.h>
#include <net/if.h>    // for struct ifreq og SIOCGIFINDEX
#include <sys/ioctl.h> // for ioctl
#include <arpa/inet.h> // for htons

#define BUF_SIZE 2048
int send_arp_request(raw_socket_info_t raw_info, uint8_t my_mip, uint8_t target_mip);
int recv_arp_response(raw_socket_info_t raw_info, uint8_t expected_mip);
int send_mip_data(uint8_t *buffer, int mip_addr, raw_socket_info_t raw_info, size_t n, mip_arp_entry_t *entry);
void debug_log(const char *msg);
void print_usage(const char *progname);

mip_arp_cache_t arp_cache;
void arp_cache_insert(mip_arp_cache_t *cache, uint8_t mip, uint8_t *mac, int if_index)
{
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
void print_usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [-d] <socket_upper> <mip_addr>\n", progname);
    exit(EXIT_FAILURE);
}

void debug_log(const char *msg)
{
    // Placeholder debug printer
    fprintf(stderr, "[DEBUG] %s\n", msg);
}

int setup_unix_socket(const char *path)
{
    int sockfd;
    struct sockaddr_un addr;

    unlink(path);

    // Dgram ??
    sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sockfd == -1)
    {
        perror("socket (unix)");
        exit(EXIT_FAILURE);
    }
    // Probalby dont need this memset
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    // If the binding fails
    if (bind(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind (unix)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    return sockfd;
}
raw_socket_info_t create_socket(const char *iface_name)
{
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_PROTOCOL));

    if (raw_sock == -1)
    {
        perror("raw socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    // Get interface index
    if (ioctl(raw_sock, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl (SIOCGIFINDEX)");
        exit(EXIT_FAILURE);
    }

    int if_index = ifr.ifr_ifindex;

    // Get MAC address
    if (ioctl(raw_sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl (SIOCGIFHWADDR)");
        exit(EXIT_FAILURE);
    }

    raw_socket_info_t sock_info;
    sock_info.sock = raw_sock;
    sock_info.if_index = if_index;
    memcpy(sock_info.mac, ifr.ifr_hwaddr.sa_data, 6);

    // Bind to socket
    struct sockaddr_ll saddr = {0};
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_PROTOCOL);
    saddr.sll_ifindex = if_index;

    if (bind(raw_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    return sock_info;
}

void run_daemon(int app_fd, int mip_addr, raw_socket_info_t raw_info)
{

    struct pollfd fds[2];
    fds[0].fd = app_fd;
    fds[0].events = POLLIN;

    fds[1].fd = raw_info.sock;
    fds[1].events = POLLIN;

    uint8_t buffer[BUF_SIZE];

    while (1)
    {
        int ready = poll(fds, 2, -1);
        if (ready < 0)
        {
            perror("poll");
            break;
        }

        // Incoming from server
        if (fds[0].revents & POLLIN)

        {
            ssize_t n = recv(app_fd, buffer, sizeof(buffer), 0);
            if (n <= 0)
            {
                perror("recv from app");
                break;
            }

            // buffer[0] = destination MIP address
            uint8_t dst_mip = buffer[0];

            // interface indx for the network interface

            mip_arp_entry_t *entry = arp_cache_lookup(&arp_cache, dst_mip);
            // Dont have the mac addr yet
            if (entry == NULL)
            {
                if (send_arp_request(raw_info, mip_addr, dst_mip) < 0 ||
                    recv_arp_response(raw_info, dst_mip) < 0)
                {
                    fprintf(stderr, "[ERROR] Failed to resolve MIP address %d\n", dst_mip);
                    continue; // Skip sending
                }

                // Refresh entry after successful ARP
                entry = arp_cache_lookup(&arp_cache, dst_mip);
                if (!entry)
                {
                    fprintf(stderr, "[ERROR] ARP resolved but entry missing from cache\n");
                    continue;
                }
            }
            send_mip_data(buffer, mip_addr, raw_info, n, entry);
        }

        // Incoming from network/depack the message
        if (fds[1].revents & POLLIN)
        {
            ssize_t n = recv(raw_info.sock, buffer, sizeof(buffer), 0);
            if (n <= 0)
            {
                perror("recv from raw socket");
                break;
            }

            // TODO:
            // - Parse Ethernet + MIP header
            if (n < sizeof(struct ether_frame) + sizeof(struct mip_header_raw))
            {
                fprintf(stderr, "Frame too short\n");
                continue;
            }
            struct ether_frame *eth = (struct ether_frame *)buffer;
            struct mip_header_raw *mip = (struct mip_header_raw *)(buffer + sizeof(struct ether_frame));

            if (MIP_GET_SDU_TYPE(mip) != MIP_SDU_TYPE_PING)
            {
                continue;
            }
            // If its to your own addr or broadcast addr
            if (mip->dst_addr == mip_addr && mip->dst_addr == 0xFF)
            {
                size_t sdu_len = MIP_GET_SDU_LEN(mip);
                send(app_fd, buffer + sizeof(struct ether_frame) + sizeof(struct mip_header_raw), sdu_len, 0);
            }
        }
    }
}
int send_mip_data(uint8_t *buffer, int mip_addr, raw_socket_info_t raw_info, size_t n, mip_arp_entry_t *entry)
{
    uint8_t *payload = &buffer[1];
    size_t payload_len = n - 1;
    uint8_t dst_mip = buffer[0];
    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_ll dest_sockaddr;
    memset(&dest_sockaddr, 0, sizeof(dest_sockaddr));

    struct mip_frame
    {
        struct ether_frame eth;
        struct mip_header_raw mip;
        uint8_t payload[BUF_SIZE];
    } __attribute__((packed));

    struct mip_frame frame = {0};
    memcpy(frame.eth.dst_addr, entry->mac_addr, 6);
    memcpy(frame.eth.src_addr, raw_info.mac, 6);
    frame.eth.eth_proto = htons(ETH_PROTOCOL);
    // Dst addr
    frame.mip.dst_addr = dst_mip;
    frame.mip.src_addr = mip_addr;
    MIP_SET_TTL(&frame.mip, 1);
    MIP_SET_SDU_LEN(&frame.mip, payload_len);
    MIP_SET_SDU_TYPE(&frame.mip, MIP_SDU_TYPE_PING);

    // Payload
    memcpy(frame.payload, payload, payload_len);
    iov.iov_base = &frame;
    iov.iov_len = sizeof(struct ether_frame) + sizeof(struct mip_header_raw) + payload_len;

    // STEP 3: Construct msg header
    dest_sockaddr.sll_family = AF_PACKET;
    dest_sockaddr.sll_ifindex = raw_info.if_index;
    dest_sockaddr.sll_halen = 6;
    memcpy(dest_sockaddr.sll_addr, entry->mac_addr, 6);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &dest_sockaddr;
    msg.msg_namelen = sizeof(dest_sockaddr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // STEP 4: Send message
    int rc = sendmsg(raw_info.sock, &msg, 0);
    if (rc == -1)
    {
        perror("sendmsg (Data)");
        return -1;
    }
    else
    {
        printf("[DEBUG] Sent data packet to MIP %u\n", dst_mip);
    }
    return 0;
}
int recv_arp_response(raw_socket_info_t raw_info, uint8_t expected_mip)
{
    uint8_t buf[BUF_SIZE];
    struct sockaddr_ll recv_addr;
    socklen_t addrlen = sizeof(recv_addr);

    while (1)
    {
        ssize_t n = recvfrom(raw_info.sock, buf, BUF_SIZE, 0,
                             (struct sockaddr *)&recv_addr, &addrlen);
        if (n < 0)
        {
            perror("recvfrom (ARP response)");
            return -1;
        }
        if (n < sizeof(struct ether_frame) + sizeof(struct mip_header_raw))
        {
            fprintf(stderr, "Frame too short\n");
            continue;
        }

        struct ether_frame *eth = (struct ether_frame *)buf;
        struct mip_header_raw *mip = (struct mip_header_raw *)(buf + sizeof(struct ether_frame));
        // double check if its a arp request we are getting
        uint8_t *payload = buf + sizeof(struct ether_frame) + sizeof(struct mip_header_raw);

        if (MIP_GET_SDU_TYPE(mip) == MIP_SDU_TYPE_ARP && payload[0] == ARP_REQUEST)
        {
            if (mip->src_addr == expected_mip)
            {
                printf("[DEBUG] Received ARP response from MIP %u\n", mip->src_addr);
                arp_cache_insert(&arp_cache, mip->src_addr, eth->src_addr, recv_addr.sll_ifindex);
                return 0;
            }
            // if someone else responds their mac addr
            else
            {
                if (!arp_cache_lookup(&arp_cache, mip->src_addr))
                    arp_cache_insert(&arp_cache, mip->src_addr, eth->src_addr, recv_addr.sll_ifindex);
            }
        }
    }
    // cant happen
    return -1;
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
    frame.payload[0] = ARP_REQUEST; // ARP request
    frame.payload[1] = target_mip;  // Target MIP address
    frame.payload[2] = 0x00;        // Padding
    frame.payload[3] = 0x00;        // Padding

    // STEP 1: Construct frame header
    memset(&frame, 0, sizeof(frame));
    memset(&dest_sockaddr, 0, sizeof(dest_sockaddr));

    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(frame.eth.dst_addr, broadcast_mac, 6);
    memcpy(frame.eth.src_addr, raw_info.mac, 6);
    frame.eth.eth_proto = htons(ETH_PROTOCOL);

    // STEP 1 (continued): Construct MIP header
    frame.mip.dst_addr = 0xFF; // broadcast
    frame.mip.src_addr = my_mip;
    MIP_SET_TTL(&frame.mip, 1);     // TTL = 1 for ARP, for now?
    MIP_SET_SDU_LEN(&frame.mip, 4); // Payload = 4 byte
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
int main(int argc, char *argv[])
{
    int debug = 0;
    char *socket_path = NULL;
    uint8_t mip_addr = 0;

    // Argument parsing
    int opt;
    while ((opt = getopt(argc, argv, "dh")) != -1)
    {
        switch (opt)
        {
        case 'd':
            debug = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            break;
        default:
            print_usage(argv[0]);
        }
    }
    if (debug)
        debug_log("MIP daemon started in debug mode");
    if (argc - optind != 2)
        print_usage(argv[0]);

    socket_path = argv[optind];
    mip_addr = atoi(argv[optind + 1]);
    if (mip_addr > 254)
    {
        fprintf(stderr, "Invalid MIP address. Must be in [0, 254].\n");
        exit(EXIT_FAILURE);
    }
    raw_socket_info_t sock_info = create_socket("eth0");

    int unix_sock = setup_unix_socket(socket_path);
    listen(unix_sock, 1);

    int app_fd = accept(unix_sock, NULL, NULL);
    if (app_fd == -1)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // init the cache
    memset(&arp_cache, 0, sizeof(arp_cache));
    run_daemon(app_fd, mip_addr, sock_info);
    return 0;
}
// if (MIP_GET_SDU_TYPE(mip) == MIP_SDU_TYPE_ARP && payload[0] == ARP_REQUEST)
// {
//     uint8_t target_mip = payload[1];

//     // Check if the request is for us
//     if (target_mip == mip_addr) {
//         // Construct ARP response
//         struct ether_frame frame;
//         memset(&frame, 0, sizeof(frame));

//         // Ethernet Header
//         memcpy(frame.dst_addr, frame_in->src_addr, 6); // send to sender
//         memcpy(frame.src_addr, raw_info.my_mac, 6);
//         frame.eth_proto = htons(ETH_PROTOCOL);

//         // MIP header
//         frame.mip.dst_addr = mip->src_addr;   // Respond to sender
//         frame.mip.src_addr = mip_addr;
//         MIP_SET_TTL(&frame.mip, 1);
//         MIP_SET_SDU_TYPE(&frame.mip, MIP_SDU_TYPE_ARP);
//         MIP_SET_SDU_LEN(&frame.mip, 1); // 4 bytes = 1 word

//         // Payload: [0x01, mip_addr, 0x00, 0x00]
//         frame.payload[0] = ARP_RESPONSE;
//         frame.payload[1] = mip_addr;
//         frame.payload[2] = 0x00;
//         frame.payload[3] = 0x00;

//         // Send the response
//         struct sockaddr_ll sll = raw_info.sock_addr[ifindex]; // same ifindex as incoming frame
//         send_raw_packet(raw_info.sock, &sll, &frame);
//         printf("Sent ARP response for MIP 0x%02x to 0x%02x\n", mip_addr, frame.mip.dst_addr);
//     }
// }
