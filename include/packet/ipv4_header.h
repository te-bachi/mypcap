#ifndef __IPV4_HEADER_H__
#define __IPV4_HEADER_H__

typedef struct _ipv4_header_t           ipv4_header_t;

#include "packet/packet.h"
#include "packet/net_address.h"

/* length on the wire! */
#define IPV4_HEADER_LEN                 20

/* IPv4 offsets */
#define IPV4_HEADER_OFFSET_VERSION      0
#define IPV4_HEADER_OFFSET_TOS          1
#define IPV4_HEADER_OFFSET_LEN          2
#define IPV4_HEADER_OFFSET_ID           4
#define IPV4_HEADER_OFFSET_FLAGS        6
#define IPV4_HEADER_OFFSET_TTL          8
#define IPV4_HEADER_OFFSET_PROTOCOL     9
#define IPV4_HEADER_OFFSET_CHECKSUM     10
#define IPV4_HEADER_OFFSET_SRC          12
#define IPV4_HEADER_OFFSET_DEST         16

/* IPv4 header values */
#define IPV4_HEADER_VERSION             4
#define IPV4_HEADER_IHL                 5           /* 5 x 32-bit = 160-bit = 20-byte */
#define IPV4_HEADER_MASK_FLAGS          0xE000
#define IPV4_HEADER_MASK_DONT_FRAGMENT  0x4000
#define IPV4_HEADER_MASK_MORE_FRAGMENT  0x2000

/* protocol */
#define IPV4_PROTOCOL_ICMP              1
#define IPV4_PROTOCOL_TCP               6
#define IPV4_PROTOCOL_UDP               17

struct _ipv4_header_t {
    header_t            header;
    
    union {
        uint8_t         ver_ihl;
        struct {
#if defined(__PPC__) || defined(__ARMEB__)
            uint8_t     version : 4;
            uint8_t     ihl     : 4;
#else
            uint8_t     ihl     : 4;
            uint8_t     version : 4;
#endif
        };
    };
    union {
        uint8_t         tos;
        struct {
#if defined(__PPC__) || defined(__ARMEB__)
            uint8_t     dscp : 6;
            uint8_t     ecn  : 2;
#else
            uint8_t     ecn  : 2;
            uint8_t     dscp : 6;
#endif
        };
    };
    uint16_t            len;
    uint16_t            id;
    union {
        uint16_t        flags_offset;
        struct {
#if defined(__PPC__) || defined(__ARMEB__)
            uint16_t    reserved        : 1;
            uint16_t    dont_fragment   : 1;
            uint16_t    more_fragments  : 1;
            uint16_t    fragment_offset : 13;
#else
            uint16_t    fragment_offset : 13;
            uint16_t    more_fragments  : 1;
            uint16_t    dont_fragment   : 1;
            uint16_t    reserved        : 1;
#endif
        };
    };
    uint8_t             ttl;
    uint8_t             protocol;
    uint16_t            checksum;
    ipv4_address_t      src;
    ipv4_address_t      dest;
};

ipv4_header_t  *ipv4_header_new     (void);
void            ipv4_header_free    (header_t *header);
packet_len_t    ipv4_header_encode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t       *ipv4_header_decode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

