#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "mip_daemon.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "common.h"
#include <poll.h>
#include <net/if.h>
#include <sys/ioctl.h> // for ioctl
#include <arpa/inet.h> // for htons
// #include <linux/if_packet.h>
#include <ifaddrs.h> // for getifaddrs
#include "mip_arp.c"
#include "queue.c"

#define BUF_SIZE 2048
#define ARP_REQUEST 0x00
#define ARP_RESPONSE 0x01
#define ETH_PROTOCOL 0x88B5

// Message structure for queuing
typedef struct
{
    uint8_t buffer[BUF_SIZE];
    size_t length;
    uint8_t dst_mip;
} queued_message_t;

int recv_arp_response(raw_socket_info_t raw_info, uint8_t expected_mip);
int send_mip_data(uint8_t *buffer, int mip_addr, raw_socket_info_t raw_info, size_t n, mip_arp_entry_t *entry);
void handle_ping_packet(struct mip_header_raw *mip, uint8_t *payload, int app_fd, int mip_addr);
int parse_incoming_packet(uint8_t *buffer, ssize_t n, struct ether_frame **eth,
                          struct mip_header_raw **mip, uint8_t **payload);
void debug_log(const char *msg);
void print_usage(const char *progname);
int process_queued_messages(Queue *msg_queue, int mip_addr, raw_socket_info_t raw_info);

mip_arp_cache_t arp_cache;
int debug_mode = 0; // Global debug flag

void print_usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [-d] <socket_upper> <mip_addr> [interface]\n", progname);
    fprintf(stderr, "  If interface is not specified, first available interface will be used\n");
    exit(EXIT_FAILURE);
}

void debug_log(const char *msg)
{
    // Placeholder debug printer
    fprintf(stderr, "[DEBUG] %s\n", msg);
}

void debug_log_packet(const char *direction, struct ether_frame *eth, struct mip_header_raw *mip, int debug_enabled)
{
    if (!debug_enabled)
        return;

    fprintf(stderr, "[DEBUG] %s packet:\n", direction);
    fprintf(stderr, "  Ethernet: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
            eth->src_addr[0], eth->src_addr[1], eth->src_addr[2],
            eth->src_addr[3], eth->src_addr[4], eth->src_addr[5],
            eth->dst_addr[0], eth->dst_addr[1], eth->dst_addr[2],
            eth->dst_addr[3], eth->dst_addr[4], eth->dst_addr[5]);
    fprintf(stderr, "  MIP: %d -> %d (TTL=%d, SDU_LEN=%d, SDU_TYPE=%d)\n",
            mip->src_addr, mip->dst_addr, MIP_GET_TTL(mip),
            MIP_GET_SDU_LEN(mip), MIP_GET_SDU_TYPE(mip));
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

char *get_first_interface()
{
    struct ifaddrs *ifaces, *ifp;
    static char interface_name[IFNAMSIZ];

    /* Enumerate interfaces */
    if (getifaddrs(&ifaces) < 0)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    /* Walk the list looking for first non-loopback interface */
    for (ifp = ifaces; ifp != NULL; ifp = ifp->ifa_next)
    {
        if (ifp->ifa_addr != NULL &&
            ifp->ifa_addr->sa_family == AF_PACKET &&
            strcmp(ifp->ifa_name, "lo") != 0)
        {

            snprintf(interface_name, IFNAMSIZ, "%s", ifp->ifa_name);

            if (debug_mode)
            {
                fprintf(stderr, "[DEBUG] Auto-selected interface: %s\n", interface_name);
            }

            freeifaddrs(ifaces);
            return interface_name;
        }
    }

    freeifaddrs(ifaces);
    fprintf(stderr, "No suitable network interface found\n");
    exit(EXIT_FAILURE);
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
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    int if_index = ifr.ifr_ifindex;

    // Get MAC address
    if (ioctl(raw_sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl (SIOCGIFHWADDR)");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    raw_socket_info_t sock_info;
    sock_info.sock = raw_sock;
    sock_info.if_index = if_index;
    memcpy(sock_info.mac, ifr.ifr_hwaddr.sa_data, 6);

    if (debug_mode)
    {
        fprintf(stderr, "[DEBUG] Created raw socket on interface %s (index %d)\n", iface_name, if_index);
        fprintf(stderr, "[DEBUG] MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                sock_info.mac[0], sock_info.mac[1], sock_info.mac[2],
                sock_info.mac[3], sock_info.mac[4], sock_info.mac[5]);
    }

    // Bind to socket
    struct sockaddr_ll saddr = {0};
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_PROTOCOL);
    saddr.sll_ifindex = if_index;

    if (bind(raw_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    {
        perror("bind");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    return sock_info;
}

void handle_ping_packet(struct mip_header_raw *mip, uint8_t *payload, int app_fd, int mip_addr)
{
    if (mip->dst_addr == mip_addr || mip->dst_addr == 0xFF)
    {
        size_t sdu_len = MIP_GET_SDU_LEN(mip) * 4; // Convert words to bytes
        send(app_fd, payload, sdu_len, 0);
    }
}

int parse_incoming_packet(uint8_t *buffer, ssize_t n, struct ether_frame **eth,
                          struct mip_header_raw **mip, uint8_t **payload)
{
    size_t min_size = sizeof(struct ether_frame) + sizeof(struct mip_header_raw);
    if ((size_t)n < min_size)
    {
        fprintf(stderr, "Frame too short\n");
        return -1;
    }

    *eth = (struct ether_frame *)buffer;
    *mip = (struct mip_header_raw *)(buffer + sizeof(struct ether_frame));
    *payload = buffer + sizeof(struct ether_frame) + sizeof(struct mip_header_raw);

    return 0;
}

int process_queued_messages(Queue *msg_queue, int mip_addr, raw_socket_info_t raw_info)
{
    int processed = 0;
    queued_message_t *msg;

    // Process all messages that can now be sent (have ARP entries)
    Node *current = msg_queue->head;
    Node *prev = NULL;

    while (current != NULL)
    {
        msg = (queued_message_t *)current->data;

        // Check if we now have an ARP entry for this destination
        mip_arp_entry_t *entry = arp_cache_lookup(&arp_cache, msg->dst_mip);
        if (entry != NULL)
        {
            // We can send this message now
            if (debug_mode)
            {
                fprintf(stderr, "[DEBUG] Processing queued message for MIP %d\n", msg->dst_mip);
            }

            send_mip_data(msg->buffer, mip_addr, raw_info, msg->length, entry);

            // Remove this message from queue
            Node *to_remove = current;
            if (prev == NULL)
            {
                // Removing head
                msg_queue->head = current->next;
                if (msg_queue->head == NULL)
                {
                    msg_queue->tail = NULL;
                }
            }
            else
            {
                prev->next = current->next;
                if (current->next == NULL)
                {
                    // Removing tail
                    msg_queue->tail = prev;
                }
            }

            current = current->next;
            free(msg);
            free(to_remove);
            processed++;
        }
        else
        {
            prev = current;
            current = current->next;
        }
    }

    return processed;
}

void run_daemon(int app_fd, int mip_addr, raw_socket_info_t raw_info)
{
    // Create message queue for pending messages
    Queue *msg_queue = create_queue();
    if (!msg_queue)
    {
        fprintf(stderr, "[ERROR] Failed to create message queue\n");
        return;
    }

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

            mip_arp_entry_t *entry = arp_cache_lookup(&arp_cache, dst_mip);
            // Dont have the mac addr yet
            if (entry == NULL)
            {
                if (debug_mode)
                {
                    fprintf(stderr, "[DEBUG] No ARP entry for MIP %d, queueing message\n", dst_mip);
                }

                // Queue the message for later processing
                queued_message_t *msg = malloc(sizeof(queued_message_t));
                if (msg)
                {
                    memcpy(msg->buffer, buffer, n);
                    msg->length = n;
                    msg->dst_mip = dst_mip;

                    if (enqueue(msg_queue, msg) < 0)
                    {
                        fprintf(stderr, "[ERROR] Failed to queue message\n");
                        free(msg);
                    }
                }

                // Send ARP request
                if (send_arp_request(raw_info, mip_addr, dst_mip) < 0)
                {
                    fprintf(stderr, "[ERROR] Failed to send ARP request for MIP %d\n", dst_mip);
                    continue; // Skip sending
                }
            }
            else
            {
                // We have ARP entry, send immediately
                send_mip_data(buffer, mip_addr, raw_info, n, entry);
            }
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

            struct ether_frame *eth;
            struct mip_header_raw *mip;
            uint8_t *payload;

            if (parse_incoming_packet(buffer, n, &eth, &mip, &payload) < 0)
            {
                continue;
            }

            uint8_t sdu_type = MIP_GET_SDU_TYPE(mip);

            if (sdu_type == MIP_SDU_TYPE_ARP)
            {
                handle_arp_packet(eth, mip, payload, raw_info, mip_addr);

                // After handling ANY ARP packet (request or response), process queued messages
                // that might now be sendable due to updated ARP cache
                int processed = process_queued_messages(msg_queue, mip_addr, raw_info);
                if (debug_mode && processed > 0)
                {
                    fprintf(stderr, "[DEBUG] Processed %d queued messages after ARP update\n", processed);
                }
            }
            else if (sdu_type == MIP_SDU_TYPE_PING)
            {
                handle_ping_packet(mip, payload, app_fd, mip_addr);
            }
        }
    }

    // Cleanup
    destroy_queue(msg_queue);
}
int send_mip_data(uint8_t *buffer, int mip_addr, raw_socket_info_t raw_info, size_t n, mip_arp_entry_t *entry)
{
    uint8_t *payload = &buffer[1];
    size_t payload_len = n - 1;

    // Round up to nearest 4-byte boundary
    size_t aligned_payload_len = ((payload_len + 3) / 4) * 4;

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
    MIP_SET_SDU_LEN(&frame.mip, aligned_payload_len / 4); // Length in 32-bit words
    MIP_SET_SDU_TYPE(&frame.mip, MIP_SDU_TYPE_PING);

    // Payload - copy original data and zero-pad to 32-bit boundary
    memcpy(frame.payload, payload, payload_len);
    // Zero-pad the remaining bytes to reach 32-bit alignment
    memset(frame.payload + payload_len, 0, aligned_payload_len - payload_len);

    iov.iov_base = &frame;
    iov.iov_len = sizeof(struct ether_frame) + sizeof(struct mip_header_raw) + aligned_payload_len;

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
        size_t min_size = sizeof(struct ether_frame) + sizeof(struct mip_header_raw);
        if ((size_t)n < min_size)
        {
            fprintf(stderr, "Frame too short\n");
            continue;
        }

        struct ether_frame *eth = (struct ether_frame *)buf;
        struct mip_header_raw *mip = (struct mip_header_raw *)(buf + sizeof(struct ether_frame));
        // double check if its a arp request we are getting
        uint8_t *payload = buf + sizeof(struct ether_frame) + sizeof(struct mip_header_raw);

        if (MIP_GET_SDU_TYPE(mip) == MIP_SDU_TYPE_ARP && payload[0] == ARP_RESPONSE)
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

        // cant happen
    }
    return -1;
}
int main(int argc, char *argv[])
{
    int debug = 0;
    char *socket_path = NULL;
    uint8_t mip_addr = 0;
    char *interface = NULL;

    // Argument parsing
    int opt;
    while ((opt = getopt(argc, argv, "dh")) != -1)
    {
        switch (opt)
        {
        case 'd':
            debug = 1;
            debug_mode = 1; // Set global debug flag
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
    if (argc - optind < 2 || argc - optind > 3)
        print_usage(argv[0]);

    socket_path = argv[optind];
    mip_addr = atoi(argv[optind + 1]);

    // Interface is optional - if not provided, auto-select first available
    if (argc - optind == 3)
    {
        interface = argv[optind + 2];
    }
    else
    {
        interface = get_first_interface();
    }

    if (mip_addr > 254)
    {
        fprintf(stderr, "Invalid MIP address. Must be in [0, 254].\n");
        exit(EXIT_FAILURE);
    }
    raw_socket_info_t sock_info = create_socket(interface);

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
