#ifndef __NTP_HEADER_H__
#define __NTP_HEADER_H__

typedef struct _ntp_header_t                           ntp_header_t;

#include "ntp_types.h"

/* length on the wire! */
#define NTP_HEADER_MIN_LEN                              48

#define NTP_HEADER_OFFSET_FLAGS                         0
#define NTP_HEADER_OFFSET_PEER_CLOCK_STRATUM            1
#define NTP_HEADER_OFFSET_PEER_POLLING_INTERVAL         2
#define NTP_HEADER_OFFSET_PEER_CLOCK_PRECISION          3
#define NTP_HEADER_OFFSET_ROOT_DELAY                    4
#define NTP_HEADER_OFFSET_ROOT_DISPERSION               8
#define NTP_HEADER_OFFSET_REFERENCE_ID                  12
#define NTP_HEADER_OFFSET_REFERENCE_TIMESTAMP_SEC       16
#define NTP_HEADER_OFFSET_REFERENCE_TIMESTAMP_NANOSEC   20
#define NTP_HEADER_OFFSET_ORIGIN_TIMESTAMP_SEC          24
#define NTP_HEADER_OFFSET_ORIGIN_TIMESTAMP_NANOSEC      28
#define NTP_HEADER_OFFSET_RECEIVE_TIMESTAMP_SEC         32
#define NTP_HEADER_OFFSET_RECEIVE_TIMESTAMP_NANOSEC     36
#define NTP_HEADER_OFFSET_TRANSMIT_TIMESTAMP_SEC        40
#define NTP_HEADER_OFFSET_TRANSMIT_TIMESTAMP_NANOSEC    44

struct _ntp_header_t {
    header_t                header;

    union {
        uint8_t             flags_raw;
        struct {
            uint8_t         mode            : 3;
            uint8_t         version         : 3;
            uint8_t         leap_indicator  : 2;
        };
    };
    uint8_t                 stratum;
    uint8_t                 polling_interval;
    int8_t                  clock_precision;    /* log2(clock_precision) */
    uint32_t                root_delay;
    uint32_t                root_dispersion;
    union {
        uint8_t             reference_id[NTP_REFERENCE_ID_LEN];
        ipv4_address_t      reference_ipv4;
    };
    ntp_timestamp_t         reference_timestamp;
    ntp_timestamp_t         origin_timestamp;
    ntp_timestamp_t         receive_timestamp;
    ntp_timestamp_t         transmit_timestamp;
};

ntp_header_t   *ntp_header_new     (void);
void            ntp_header_free    (header_t *header);
packet_len_t    ntp_header_encode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t       *ntp_header_decode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

