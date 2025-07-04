#include <sys/un.h>
#include <netpacket/packet.h>

#define MAX_CONNECTIONS 2
typedef struct
{
    int socket_fd;
    struct sockaddr_un addr;
} unix_socket_t;

typedef struct
{
    int socket_fd;
    struct sockaddr_ll if_addr;
    char if_name[IFNAMSIZ];
    int if_index;
} raw_socket_t;
typedef struct
{
    uint8_t tra; // transport protocol (always 0 for now)
    uint8_t ttl; // time to live (can be fixed)
    uint8_t src; // source MIP address
    uint8_t dst; // destination MIP address
} mip_header_t;
