
/**
 * ping_client - Send a ping message to a MIP daemon and wait for a response.
 *
 * Usage:
 *   ping_client [-h] <socke    recv_buf[n] = '\0';
    const char *reply = (const char *)&recv_buf[1]; // Skip MIP address byte

    if (strncmp(reply, "PONG:", 5) == 0 && strcmp(reply + 5, user_msg) == 0)th> <destination_mip_address> <message>
 *
 * The client connects to the MIP daemon via a UNIX domain socket,
 * sends a "PING:<message>" to the specified MIP address, and waits
 * up to 1 second for a reply of the form "PONG:<message>".
 *
 * If a correct reply is received, it prints the round-trip time.
 * If no reply is received within 1 second, it prints "timeout".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <errno.h>
#include <poll.h>
#include <bits/getopt_core.h>
#include <stdint.h>

#define MAX_MSG_LEN 2048

void print_usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [-h] <socket_path> <destination_mip_address> <message>\\n", progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "h")) != -1)
    {
        if (opt == 'h')
            print_usage(argv[0]);
        else
            print_usage(argv[0]);
    }

    if (argc - optind != 3)
    {
        print_usage(argv[0]);
    }

    const char *socket_path = argv[optind];
    int dst_mip = atoi(argv[optind + 1]);
    const char *user_msg = argv[optind + 2];

    if (dst_mip < 0 || dst_mip > 254)
    {
        fprintf(stderr, "Invalid MIP address. Must be 0-254.\\n");
        exit(EXIT_FAILURE);
    }

    int sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sockfd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("connect");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    char full_msg[MAX_MSG_LEN];
    snprintf(full_msg, sizeof(full_msg), "PING:%s", user_msg);

    uint8_t send_buf[MAX_MSG_LEN];
    send_buf[0] = (uint8_t)dst_mip;
    memcpy(&send_buf[1], full_msg, strlen(full_msg));

    struct timeval start, end;
    gettimeofday(&start, NULL);

    if (send(sockfd, send_buf, strlen(full_msg) + 1, 0) < 0)
    {
        perror("send");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct pollfd pfd = {
        .fd = sockfd,
        .events = POLLIN};

    int ret = poll(&pfd, 1, 1000); // 1 second timeout
    if (ret == 0)
    {
        printf("timeout\\n");
        close(sockfd);
        return 0;
    }
    else if (ret < 0)
    {
        perror("poll");
        close(sockfd);
        return 1;
    }

    uint8_t recv_buf[MAX_MSG_LEN];
    ssize_t n = recv(sockfd, recv_buf, sizeof(recv_buf) - 1, 0);
    if (n < 0)
    {
        perror("recv");
        close(sockfd);
        return 1;
    }

    recv_buf[n] = '\\0';
    const char *reply = (const char *)&recv_buf[0];

    if (strncmp((char *)reply, "PONG:", 5) == 0 && strcmp(reply + 5, user_msg) == 0)
    {
        gettimeofday(&end, NULL);
        long ms = (end.tv_sec - start.tv_sec) * 1000 +
                  (end.tv_usec - start.tv_usec) / 1000;
        printf("reply from %d: time=%ldms\\n", dst_mip, ms);
    }
    else
    {
        printf("timeout\\n");
    }

    close(sockfd);
    return 0;
}
