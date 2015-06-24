#ifndef __PTP2_ANNOUNCE_HEADER_H__
#define __PTP2_ANNOUNCE_HEADER_H__

typedef struct _ptp2_announce_header_t                          ptp2_announce_header_t;

#include "ptp2_types.h"

#define PTP2_ANNOUNCE_HEADER_LEN                                30

#define PTP2_ANNOUNCE_HEADER_OFFSET_ORIGIN_TIMESTAMP            0
#define PTP2_ANNOUNCE_HEADER_OFFSET_CURRENT_UTC_OFFSET          10
#define PTP2_ANNOUNCE_HEADER_OFFSET_GM_PRIORITY1                13
#define PTP2_ANNOUNCE_HEADER_OFFSET_GM_CLOCK_QUALITY            14
#define PTP2_ANNOUNCE_HEADER_OFFSET_GM_PRIORITY2                18
#define PTP2_ANNOUNCE_HEADER_OFFSET_GM_IDENTITY                 19
#define PTP2_ANNOUNCE_HEADER_OFFSET_STEPS_REMOVED               27
#define PTP2_ANNOUNCE_HEADER_OFFSET_TIME_SOURCE                 29

struct _ptp2_announce_header_t {
    header_t                header;

    ptp2_timestamp_t        origin_timestamp;
    int16_t                 current_utc_offset;
    uint8_t                 gm_priority1;
    ptp2_clock_quality_t    gm_clock_quality;
    uint8_t                 gm_priority2;
    ptp2_clock_identity_t   gm_identity;
    uint16_t                steps_removed;
    uint8_t                 time_source;
};

ptp2_announce_header_t     *ptp2_announce_header_new     (void);
void                        ptp2_announce_header_free    (header_t *header);
packet_len_t                ptp2_announce_header_encode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t                   *ptp2_announce_header_decode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

