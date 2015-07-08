#ifndef __PTP2_SYNC_HEADER_H__
#define __PTP2_SYNC_HEADER_H__

typedef struct _ptp2_sync_header_t                              ptp2_sync_header_t;

#include "ptp2_types.h"

/* length on the wire! */
#define PTP2_SYNC_HEADER_LEN                                    10

#define PTP2_SYNC_HEADER_OFFSET_ORIGIN_TIMESTAMP_SECONDS        0
#define PTP2_SYNC_HEADER_OFFSET_ORIGIN_TIMESTAMP_NANOSECONDS    6

struct _ptp2_sync_header_t {
    header_t                header;

    ptp2_timestamp_t        origin_timestamp;
};

ptp2_sync_header_t         *ptp2_sync_header_new       (void);
void                        ptp2_sync_header_free      (header_t *header);
packet_len_t                ptp2_sync_header_encode    (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t                   *ptp2_sync_header_decode    (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

