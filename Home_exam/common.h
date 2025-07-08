#include <cstdint>
#ifndef COMMON_H
#define COMMON_H

#define ETH_P_MIP 0x88B5
#define MAX_PAYLOAD_SIZE 1492
#define MIP_HDR_SIZE 4

// MIP Header Structure
typedef struct
{
    uint8_t tra; // Transport protocol
    uint8_t ttl; // Time to live
    uint8_t src; // Source MIP address
    uint8_t dst; // Destination MIP address
} mip_header_t;

// MIP PDU: Header + Payload
typedef struct
{
    mip_header_t header;
    uint8_t payload[MAX_PAYLOAD_SIZE];
} mip_packet_t;

#endif
