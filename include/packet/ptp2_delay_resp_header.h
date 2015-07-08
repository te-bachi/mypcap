#ifndef __PTP2_DELAY_RESP_HEADER_H__
#define __PTP2_DELAY_RESP_HEADER_H__

typedef struct _ptp2_delay_resp_header_t                            ptp2_delay_resp_header_t;

#include "ptp2_types.h"

/* length on the wire! */
#define PTP2_DELAY_RESP_HEADER_LEN                                  20

#define PTP2_DELAY_RESP_HEADER_OFFSET_RECEIVE_TIMESTAMP_SECONDS     0
#define PTP2_DELAY_RESP_HEADER_OFFSET_RECEIVE_TIMESTAMP_NANOSECONDS 6
#define PTP2_DELAY_RESP_HEADER_OFFSET_REQUESTING_PORT_IDENTITY      10

struct _ptp2_delay_resp_header_t {
    header_t                header;

    ptp2_timestamp_t        receive_timestamp;
    ptp2_port_identity_t    requesting_port_identity;
};

ptp2_delay_resp_header_t   *ptp2_delay_resp_header_new       (void);
void                        ptp2_delay_resp_header_free      (header_t *header);
packet_len_t                ptp2_delay_resp_header_encode    (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t                   *ptp2_delay_resp_header_decode    (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

