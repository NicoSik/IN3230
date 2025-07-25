#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include "common.h"

#define BUF_SIZE 2048

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <unix_socket_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *socket_path = argv[1];
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

    unlink(socket_path); // remove existing
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 5) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Ping server listening on %s...\n", socket_path);

    int client_fd = accept(sockfd, NULL, NULL);
    if (client_fd < 0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        uint8_t buf[BUF_SIZE];
        ssize_t bytes = recv(client_fd, buf, sizeof(buf), 0);
        if (bytes <= 0)
        {
            perror("recv");
            break;
        }

        // Basic protocol format:
        // First byte: destination MIP
        // Second byte: SDU type (should be 0x02 for Ping)
        // Remaining: payload

        uint8_t dst = buf[0];
        uint8_t sdu_type = buf[1];
        uint8_t *payload = &buf[2];
        int payload_len = bytes - 2;

        if (sdu_type == MIP_SDU_TYPE_PING)
        {
            printf("Got ping request for MIP %d, replying...\n", dst);

            // Echo back same data
            uint8_t reply[BUF_SIZE];
            reply[0] = dst;               // destination = original sender
            reply[1] = MIP_SDU_TYPE_PING; // Ping type
            memcpy(&reply[2], payload, payload_len);

            if (send(client_fd, reply, payload_len + 2, 0) < 0)
            {
                perror("send");
            }
        }
        else
        {
            fprintf(stderr, "Unknown SDU type: %d\n", sdu_type);
        }
    }

    close(client_fd);
    close(sockfd);
    return 0;
}
