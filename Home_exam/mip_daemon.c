#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "common.h"

void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s [-d] <socket_upper> <mip_addr>\n", progname);
    exit(EXIT_FAILURE);
}

void debug_log(const char *msg) {
    // Placeholder debug printer
    fprintf(stderr, "[DEBUG] %s\n", msg);
}

int main(int argc, char *argv[]) {
    int debug = 0;
    char *socket_path = NULL;
    uint8_t mip_addr = 0;

    // Argument parsing
    int opt;
    while ((opt = getopt(argc, argv, "dh")) != -1) {
        switch (opt) {
            case 'd': debug = 1; break;
            case 'h': print_usage(argv[0]); break;
            default: print_usage(argv[0]);
        }
    }

    if (argc - optind != 2) print_usage(argv[0]);

    socket_path = argv[optind];
    mip_addr = atoi(argv[optind + 1]);

    // TODO: create raw Ethernet socket (ETH_P_MIP)
    // TODO: bind UNIX socket for upper layer
    // TODO: implement MIP-ARP and cache
    // TODO: main loop: select/poll, handle inbound/outbound traffic

    if (debug) debug_log("MIP daemon started in debug mode");

    return 0;
}
