#include <sys/un.h>
#include <netpacket/packet.h>
#define ETH_PROTOCOL 0x0806
#define MAX_CONNECTIONS 2
// Extracting the mip fields
// -------------------------------------------------------
// Extract TTL (4 bits)
#define MIP_GET_TTL(hdr) (((hdr)->ttl_len_high >> 4) & 0x0F)

// Extract SDU Length (9 bits)
// Remeber to len*4 when calling

#define MIP_GET_SDU_LEN(hdr) \
    ((((hdr)->ttl_len_high & 0x0F) << 5) | (((hdr)->len_low_type >> 3) & 0x1F))

// Extract SDU Type (3 bits)
#define MIP_GET_SDU_TYPE(hdr) ((hdr)->len_low_type & 0x07)
// ---------------------------------------------

// Set TTL (4 bits)
// ---------------------------------------------
#define MIP_SET_TTL(hdr, ttl) \
    ((hdr)->ttl_len_high = ((ttl & 0x0F) << 4) | ((hdr)->ttl_len_high & 0x0F))
// Set SDU Length (9 bits)
// Remeber to len/4 when calling
#define MIP_SET_SDU_LEN(hdr, len)                            \
    do                                                       \
    {                                                        \
        (hdr)->ttl_len_high = ((hdr)->ttl_len_high & 0xF0) | \
                              (((len) >> 5) & 0x0F);         \
        (hdr)->len_low_type = ((hdr)->len_low_type & 0x07) | \
                              (((len) & 0x1F) << 3);         \
    } while (0)

// Set SDU Type (3 bits)
#define MIP_SET_SDU_TYPE(hdr, type) \
    ((hdr)->len_low_type = ((hdr)->len_low_type & 0xF8) | ((type) & 0x07))
// ---------------------------------------------
typedef struct
{
    uint8_t mip_addr;    // MIP address (0–254)
    uint8_t mac_addr[6]; // Resolved Ethernet MAC address
    int valid;           // 1 = valid entry, 0 = unused
    typedef struct
} typedef struct
{
    mip_arp_entry_t entries[MAX_MIP_ADDRS];
} mip_arp_cache_t;
{
    int socket_fd;
    struct sockaddr_un addr;
}
unix_socket_t;

typedef struct
{
    int socket_fd;
    struct sockaddr_ll if_addr;
    char if_name[IFNAMSIZ];
    int if_index;
} raw_socket_t;
//   +--------------+-------------+---------+-----------+-----------+
//      | Dest. Addr.  | Src. Addr.  | TTL     | SDU Len.  | SDU type  |
//      +--------------+-------------+---------+-----------+-----------+
//      | 8 bits       | 8 bits      | 4 bits  | 9 bits    | 3 bits    |
//      +--------------+-------------+---------+-----------+-----------+

//    Destination address  The MIP address of the destination node

//    Source address       The MIP address of the source node

//    TTL                  Time To Live; maximum hop count

//    SDU length           Length of the SDU (i.e. payload) encapsulated within
//                         this MIP datagram.

//    SDU type             The type of the SDU (i.e. upper layer protocol type).
struct mip_header_raw
{
    uint8_t dst_addr;     // Byte 0: bits 31–24
    uint8_t src_addr;     // Byte 1: bits 23–16
    uint8_t ttl_len_high; // Byte 2:
                          //   bits 7–4: TTL (bits 15–12)
                          //   bits 3–0: SDU len bits [8:5] (bits 11–8)

    uint8_t len_low_type; // Byte 3:
                          //   bits 7–3: SDU len bits [4:0] (bits 7–3)
                          //   bits 2–0: SDU type (bits 2–0)
};
