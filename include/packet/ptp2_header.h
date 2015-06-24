#ifndef __PTP2_HEADER_H__
#define __PTP2_HEADER_H__

typedef struct _ptp2_header_t                           ptp2_header_t;

#include "ptp2_types.h"

/* length on the wire! */
#define PTP2_HEADER_LEN                                 34

#define PTP2_HEADER_OFFSET_MSG_TYPE                     0
#define PTP2_HEADER_OFFSET_VERSION                      1
#define PTP2_HEADER_OFFSET_MSG_LEN                      2
#define PTP2_HEADER_OFFSET_DOMAIN_NUMBER                4
#define PTP2_HEADER_OFFSET_FLAGS                        6
#define PTP2_HEADER_OFFSET_CORRECTION                   8
#define PTP2_HEADER_OFFSET_SRC_CLOCK_IDENTITY           20
#define PTP2_HEADER_OFFSET_SRC_PORT_NUMBER              28
#define PTP2_HEADER_OFFSET_SEQ_ID                       30
#define PTP2_HEADER_OFFSET_CONTROL                      32
#define PTP2_HEADER_OFFSET_LOG_MSG_INTERVAL             33

#define PTP2_MESSAGE_TYPE_SYNC                          0x0
#define PTP2_MESSAGE_TYPE_DELAY_REQ                     0x1
#define PTP2_MESSAGE_TYPE_PDELAY_REQ                    0x2
#define PTP2_MESSAGE_TYPE_PDELAY_RESP                   0x3
#define PTP2_MESSAGE_TYPE_FOLLOW_UP                     0x8
#define PTP2_MESSAGE_TYPE_DELAY_RESP                    0x9
#define PTP2_MESSAGE_TYPE_PDELAY_RESP_FOLLOW_UP         0xa
#define PTP2_MESSAGE_TYPE_ANNOUNCE                      0xb
#define PTP2_MESSAGE_TYPE_SIGNALING                     0xc
#define PTP2_MESSAGE_TYPE_MANAGEMENT                    0xd

#define PTP2_HEADER_PORT_IDENTITY_LEN                   10
#define PTP2_HEADER_CLOCK_IDENTITY_LEN                  8
#define PTP2_HEADER_PORT_NUMBER_LEN                     2

#define PTP2_CONTROL_SYNC                               0x00
#define PTP2_CONTROL_DELAY_REQ                          0x01
#define PTP2_CONTROL_FOLLOW_UP                          0x02
#define PTP2_CONTROL_DELAY_RESP                         0x03
#define PTP2_CONTROL_MANAGEMENT                         0x04
#define PTP2_CONTROL_OTHERS                             0x05

#define PTP2_LOG_MSG_INTERVAL_SIGNALING                 0x7F

struct _ptp2_header_t {
    header_t                header;

    union {
        uint8_t             msg_raw;
        struct {
            uint8_t         msg_type  : 4;
            uint8_t         transport : 4;
        };
    };
    uint8_t                 version;
    uint16_t                msg_len;
    uint8_t                 domain_number;
    uint16_t                flags;
    ptp2_correction_t       correction;
    ptp2_port_identity_t    src_port_identity;
    uint16_t                seq_id;
    uint8_t                 control;
    uint8_t                 log_msg_interval;
};

ptp2_header_t  *ptp2_header_new     (void);
void            ptp2_header_free    (header_t *header);
packet_len_t    ptp2_header_encode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t       *ptp2_header_decode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

