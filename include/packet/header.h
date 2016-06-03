#ifndef __HEADER_H__
#define __HEADER_H__

#include "packet/packet.h"
#include "packet/raw_packet.h"

#include "network_interface.h"

typedef struct _header_t                header_t;
typedef enum   _header_layer_t          header_layer_t;
typedef enum   _header_type_t           header_type_t;
typedef struct _header_class_t          header_class_t;

#include "packet/header_storage.h"

enum _header_layer_t {
    HEADER_LAYER_2,
    HEADER_LAYER_3,
    HEADER_LAYER_4,
    HEADER_LAYER_5,
    HEADER_LAYER_6,
    HEADER_LAYER_7,
    HEADER_LAYER_8
};

enum _header_type_t {
    HEADER_TYPE_ETHERNET,
    HEADER_TYPE_VLAN,
    HEADER_TYPE_ARP,
    HEADER_TYPE_IPV4,
    HEADER_TYPE_IPV6,
    HEADER_TYPE_ICMPV4,
    HEADER_TYPE_UDPV4,
    HEADER_TYPE_TCPV4,
    HEADER_TYPE_ICMPV6,
    HEADER_TYPE_UDPV6,
    HEADER_TYPE_TCPV6,
    HEADER_TYPE_DNS,
    HEADER_TYPE_PTP2,
    HEADER_TYPE_PTP2_SYNC,
    HEADER_TYPE_PTP2_ANNOUNCE,
    HEADER_TYPE_PTP2_DELAY_REQ,
    HEADER_TYPE_PTP2_DELAY_RESP,
    HEADER_TYPE_PTP2_SIGNALING,
    HEADER_TYPE_PTP2_SIGNALING_TLV,
    HEADER_TYPE_NTP,
    HEADER_TYPE_ADVA_TLV,
    HEADER_TYPE_IGNORE,
    HEADER_TYPE_ALL
};

typedef header_t     *(*header_new_fn)(void);
typedef void          (*header_free_fn)(header_t *header);
typedef header_t     *(*header_decode_fn)(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
typedef packet_len_t  (*header_encode_fn)(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

struct _header_class_t {
    header_type_t           type;
    uint16_t                size;
    header_free_fn          free;
};

/**
 * A header has has a next header (payload) and
 * could have a previous header (header)
 *
 * |_____________________|
 * |                     |
 * |     Next Header     | Layer n + 1
 * |_____________________|
 * |                     |
 * |       Header        | Layer n
 * |_____________________|
 * |                     |
 * |   Previous Header   | Layer n - 1
 * |_____________________|
 * |                     |
 *
 */
struct _header_t {
    header_class_t         *klass;
    header_storage_entry_t *entry;      /**< in what storage entry it was allocated so that it can be returned to the creator */
    uint32_t                idx;        /**< index in the allocated storage, used to return a header to the storage, @see header_storage_t */
    header_t               *prev;
    header_t               *next;
};

#include "packet/ethernet_header.h"
#include "packet/arp_header.h"
#include "packet/ipv4_header.h"
#include "packet/udpv4_header.h"
#include "packet/icmpv4_header.h"
#include "packet/dns_header.h"
#include "packet/ptp2_header.h"
#include "packet/ptp2_sync_header.h"
#include "packet/ptp2_announce_header.h"
#include "packet/ptp2_delay_req_header.h"
#include "packet/ptp2_delay_resp_header.h"
#include "packet/ptp2_signaling_header.h"
#include "packet/ptp2_signaling_tlv_header.h"
#include "packet/ntp_header.h"
#include "packet/adva_tlv_header.h"

#endif

