#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "common.h"

void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s <socket_lower>\n", progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 2) print_usage(argv[0]);
    char *socket_path = argv[1];

    // TODO: Connect to MIP daemon via UNIX socket
    // TODO: Receive incoming PING message
    // TODO: Print message, send "PONG: <msg>" reply

    return 0;
}
