#ifndef __ARP_HEADER_H__
#define __ARP_HEADER_H__

typedef struct _arp_header_t            arp_header_t;


#include "packet/packet.h"
#include "packet/net_address.h"

/* length on the wire! */
#define ARP_HEADER_LEN                  28

/* ARP offsets */
#define ARP_HEADER_OFFSET_HTYPE         0
#define ARP_HEADER_OFFSET_PTYPE         2
#define ARP_HEADER_OFFSET_HLEN          4
#define ARP_HEADER_OFFSET_PLEN          5
#define ARP_HEADER_OFFSET_OPER          6
#define ARP_HEADER_OFFSET_SHA           8
#define ARP_HEADER_OFFSET_SPA           14
#define ARP_HEADER_OFFSET_THA           18
#define ARP_HEADER_OFFSET_TPA           24

/* hardware type (HTYPE) */
#define ARP_HTYPE_ETHERNET              0x0001

/* protocol type (PTYPE) */
#define ARP_PTYPE_IPV4                  0x0800

/* hadrware address length (HLEN) */
#define ARP_HLEN_ETHERNET               0x06

/* protocol address length (PLEN) */
#define ARP_PLEN_IPV4                   0x04

/* operation (OPER) */
#define ARP_OPER_REQUEST                0x0001
#define ARP_OPER_RESPONSE               0x0002

struct _arp_header_t {
    header_t            header;

    uint16_t            htype;      /* Hardware type (HTYPE)            */
    uint16_t            ptype;      /* Protocol type (PTYPE)            */
    uint8_t             hlen;       /* Hardware address length (HLEN)   */
    uint8_t             plen;       /* Protocol address length (PLEN)   */
    uint16_t            oper;       /* Operation (OPER)                 */
    mac_address_t       sha;        /* Sender hardware address (SHA)    */
    ipv4_address_t      spa;        /* Sender protocol address (SPA)    */
    mac_address_t       tha;        /* Target hardware address (THA)    */
    ipv4_address_t      tpa;        /* Target protocol address (TPA)    */
};

arp_header_t   *arp_header_new      (void);
void            arp_header_free     (header_t *header);
packet_len_t    arp_header_encode   (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t       *arp_header_decode   (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

