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

#define BUF_SIZE 2048
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
    // SOCK_STREAM instead, its for udp?
    // SeqPacket is better for send/recv model
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
int create_socket(const char *iface_name)
{
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETHERNET_TYPE_PROTO));
    if (raw_sock == -1)
    {
        perror("raw socket");
        exit(EXIT_FAILURE);
    }

    // Bind to interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    if (ioctl(raw_sock, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_ll saddr = {0};
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETHERNET_TYPE_PROTO);
    saddr.sll_ifindex = ifr.ifr_ifindex;

    if (bind(raw_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    return raw_sock;
}
void daemon()
{

    int raw_sock = create_socket("eth0");

    struct pollfd fds[2];
    fds[0].fd = app_fd;
    fds[0].events = POLLIN;

    fds[1].fd = raw_sock;
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
            uint8_t *payload = &buffer[1];
            size_t payload_len = n - 1;

            // TODO:
            // - Lookup MAC for dst_mip via ARP
            // - Build MIP header
            // - Send Ethernet frame
        }

        // Incoming from network
        if (fds[1].revents & POLLIN)
        {
            ssize_t n = recv(raw_sock, buffer, sizeof(buffer), 0);
            if (n <= 0)
            {
                perror("recv from raw socket");
                break;
            }

            // TODO:
            // - Parse Ethernet + MIP header
            // - Check if destination MIP == my_mip
            // - If yes, send SDU to app_fd
        }
    }
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

    // TODO: create raw Ethernet socket (ETH_P_MIP)
    create_socket("eth0");
    // TODO: bind UNIX socket for upper layer
    int unix_sock = setup_unix_socket(socket_path);
    listen(unix_sock, 1);

    int app_fd = accept(unix_sock, NULL, NULL);
    if (app_fd == -1)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    // TODO: implement MIP-ARP and cache

    // TODO: main loop: select/poll, handle inbound/outbound traffic

    return 0;
}
// If we want to listen to more than 1 client at a time
//  void sock_listen(int server_fd)
//  {
//      int client_fd, connections = 0;
//      int pid;
//      listen(server_fd, MAX_CONNECTIONS);
//      while (1)
//      {
//          client_fd = accept(server_fd, NULL, NULL);
//          if (client_fd == -1)
//          {
//              perror("accept");
//              exit(EXIT_FAILURE);
//          }
//          pid = fork();
//          if (pid == -1)
//          {
//              perror("fork");
//              exit(EXIT_FAILURE);
//          }
//          if (pid == 0)
//          {
//              // it's child process
//              // it handles the corresponding client
//              // close the copy of the server_fd (listening socket)
//              close(server_fd);
//              handle_client(client_fd);
//              exit(EXIT_SUCCESS);
//          }
//          if (pid > 0)
//          {
//              connections++;
//              if (connections == MAX_CONNECTIONS)
//              {
//                  // wait for the child processes to finish the requests then shutdown the server
//                  // shutdown_server(server_fd, connections);
//              }
//          }
//      }
//  }