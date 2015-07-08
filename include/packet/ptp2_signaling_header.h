#ifndef __PTP2_SIGNALING_HEADER_H__
#define __PTP2_SIGNALING_HEADER_H__

typedef struct _ptp2_signaling_header_t                 ptp2_signaling_header_t;

#include "ptp2_types.h"

/* header + tlv */
#define PTP2_SIGNALING_HEADER_TARGET_PORT_IDENT_LEN     10 /* target port identity  */

#define PTP2_SIGNALING_HEADER_OFFSET_TARGET_PORT_IDENT  0
#define PTP2_SIGNALING_HEADER_OFFSET_TARGET_CLOCK_IDENT 0
#define PTP2_SIGNALING_HEADER_OFFSET_TARGET_PORT_NUMBER 8

struct _ptp2_signaling_header_t {
    header_t                            header;

    ptp2_port_identity_t                target_port_identity;
};

ptp2_signaling_header_t    *ptp2_signaling_header_new       (void);
void                        ptp2_signaling_header_free      (header_t *header);
packet_len_t                ptp2_signaling_header_encode    (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t                   *ptp2_signaling_header_decode    (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

