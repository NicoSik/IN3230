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

        // Protocol format per spec:
        // First byte: source/destination MIP address
        // Remaining bytes: payload (SDU)

        uint8_t src_mip = buf[0];        // Source MIP address
        char *payload = (char *)&buf[1]; // Payload starts at byte 1
        int payload_len = bytes - 1;

        printf("Received from MIP %d: %.*s\n", src_mip, payload_len, payload);

        // Check if it's a PING message
        if (payload_len >= 5 && strncmp(payload, "PING:", 5) == 0)
        {
            char *user_msg = payload + 5; // Extract user message after "PING:"
            int user_msg_len = payload_len - 5;

            printf("Got ping request from MIP %d, replying...\n", src_mip);

            // Create PONG response
            uint8_t reply[BUF_SIZE];
            reply[0] = src_mip; // Send back to original sender

            // Format: "PONG:<user_message>"
            int reply_len = snprintf((char *)&reply[1], BUF_SIZE - 1, "PONG:%.*s", user_msg_len, user_msg);

            if (send(client_fd, reply, reply_len + 1, 0) < 0)
            {
                perror("send");
            }
        }
    }

    close(client_fd);
    close(sockfd);
    return 0;
}
