#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include "common.h"

void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s <destination_host> <message> <socket_lower>\n", progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 4) print_usage(argv[0]);

    uint8_t dst_mip = atoi(argv[1]);
    char *msg = argv[2];
    char *socket_path = argv[3];

    // TODO: Connect to MIP daemon via UNIX socket
    // TODO: Send "PING: <msg>" to dst_mip
    // TODO: Start timer, wait for response (1 second timeout)
    // TODO: If "PONG: <msg>" received -> print RTT, else print "timeout"

    return 0;
}
