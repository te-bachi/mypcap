#ifndef __ICMPV4_PACKET_H__
#define __ICMPV4_PACKET_H__

typedef struct _icmpv4_header_t             icmpv4_header_t;

#include "packet/net_address.h"

/* length on the wire! */
#define ICMPV4_HEADER_MIN_LEN              4
#define ICMPV4_HEADER_ECHO_MIN_LEN         8
#define ICMPV4_HEADER_ECHO_DATA_MAX_LEN    64

/* ICMP offsets */
#define ICMPV4_HEADER_OFFSET_TYPE          0
#define ICMPV4_HEADER_OFFSET_CODE          1
#define ICMPV4_HEADER_OFFSET_CHECKSUM      2

#define ICMPV4_HEADER_OFFSET_ECHO_ID       4
#define ICMPV4_HEADER_OFFSET_ECHO_SEQNO    6
#define ICMPV4_HEADER_OFFSET_ECHO_DATA     8

/* ICMP type */
#define ICMPV4_TYPE_ECHO_REQUEST           8
#define ICMPV4_TYPE_ECHO_REPLY             0

/* ICMP code */
#define ICMPV4_CODE_ECHO_REQUEST           8
#define ICMPV4_CODE_ECHO_REPLY             0

struct _icmpv4_header_t {
    header_t            header;

    uint8_t             type;
    uint8_t             code;
    uint16_t            checksum;
    union {
        struct {
            uint16_t    id;
            uint16_t    seqno;
            uint8_t     data[ICMPV4_HEADER_ECHO_DATA_MAX_LEN];
            uint16_t    len;        /**< no in the standard:
                                         used to calculate the total length */
        } echo;
    };
};

packet_len_t    icmpv4_packet_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t       *icmpv4_packet_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

