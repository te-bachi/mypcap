#ifndef __PTP2_SIGNALING_TLV_HEADER_H__
#define __PTP2_SIGNALING_TLV_HEADER_H__

typedef struct _ptp2_signaling_tlv_header_t                       ptp2_signaling_tlv_header_t;

#include "ptp2_types.h"

/* length on the wire! */
#define PTP2_SIGNALING_TLV_MIN_LEN                                4  /* tlv type + tlv length */
#define PTP2_SIGNALING_TLV_REQUEST_UNICAST_LEN                    6  /* only tlv value length! */
#define PTP2_SIGNALING_TLV_GRANT_UNICAST_LEN                      8  /* only tlv value length! */
#define PTP2_SIGNALING_TLV_CANCEL_UNICAST_LEN                     2  /* only tlv value length! */
#define PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_LEN                 2  /* only tlv value length! */

#define PTP2_SIGNALING_TLV_OFFSET_TYPE                            0
#define PTP2_SIGNALING_TLV_OFFSET_LEN                             2

#define PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_TYPE            0
#define PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_LEN             2
#define PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_MSG_TYPE        4
#define PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_LOG_PERIOD      5
#define PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_DURATION        6

#define PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_TYPE              0
#define PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_LEN               2
#define PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_MSG_TYPE          4
#define PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_LOG_PERIOD        5
#define PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_DURATION          6
#define PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_UNUSED            10
#define PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_RENEWAL           11

#define PTP2_SIGNALING_TLV_CANCEL_UNICAST_OFFSET_TYPE             0
#define PTP2_SIGNALING_TLV_CANCEL_UNICAST_OFFSET_LEN              2
#define PTP2_SIGNALING_TLV_CANCEL_UNICAST_OFFSET_MSG_TYPE         4
#define PTP2_SIGNALING_TLV_CANCEL_UNICAST_OFFSET_UNUSED           5

#define PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_OFFSET_TYPE         0
#define PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_OFFSET_LEN          2
#define PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_OFFSET_MSG_TYPE     4
#define PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_OFFSET_UNUSED       5

/* host byte-order */
#define PTP2_SIGNALING_TLV_TYPE_MANAGEMENT                        0x0001
#define PTP2_SIGNALING_TLV_TYPE_MANAGEMENT_ERROR_STATUS           0x0002
#define PTP2_SIGNALING_TLV_TYPE_ORGANIZATION_EXTENSION            0x0003
#define PTP2_SIGNALING_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION      0x0004
#define PTP2_SIGNALING_TLV_TYPE_GRANT_UNICAST_TRANSMISSION        0x0005
#define PTP2_SIGNALING_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION       0x0006
#define PTP2_SIGNALING_TLV_TYPE_ACK_CANCEL_UNICAST_TRANSMISSION   0x0007
#define PTP2_SIGNALING_TLV_TYPE_PATH_TRACE                        0x0008
#define PTP2_SIGNALING_TLV_TYPE_ALTERNATE_TIME_OFFSET_INDICATOR   0x0009
#define PTP2_SIGNALING_TLV_TYPE_AUTHENTICATION                    0x2000
#define PTP2_SIGNALING_TLV_TYPE_AUTHENTICATION_CHALLENGE          0x2001
#define PTP2_SIGNALING_TLV_TYPE_SECURITY_ASSOCIATION_UPDATE       0x2002
#define PTP2_SIGNALING_TLV_TYPE_CUM_FREQ_SCALE_FACTOR_OFFSET      0x2003

/** 16.1.4.1 request unicast transmission */
typedef struct _ptp2_signaling_tlv_request_unicast_t {
    uint16_t                type;           /**< 16.1.4.1.1 tlvType */
    uint16_t                len;            /**< 16.1.4.1.2 lengthField */
    union {
        uint8_t             raw;
        struct {
            uint8_t         unused : 4;
            uint8_t         type   : 4;     /**< 16.1.4.1.3 messageType */
        };
    } msg;
    int8_t                  log_period;     /**< 16.1.4.1.4 logInterMessagePeriod: granted logarithmic period (2^log_period) in seconds */
    uint32_t                duration;       /**< 16.1.4.1.5 durationField: granted duration in seconds*/
} ptp2_signaling_tlv_request_unicast_t;

/** 16.1.4.2 grant unicast transmission */
typedef struct _ptp2_signaling_tlv_grant_unicast_t {
    uint16_t                type;           /**< 16.1.4.2.1 tlvType */
    uint16_t                len;            /**< 16.1.4.2.2 lengthField */
    union {
        uint8_t             raw;
        struct {
            uint8_t         unused : 4;
            uint8_t         type   : 4;     /**< 16.1.4.2.3 messageType */
        };
    } msg;
    int8_t                  log_period;     /**< 16.1.4.2.4 logInterMessagePeriod: granted logarithmic period (2^log_period) in seconds */
    uint32_t                duration;       /**< 16.1.4.2.5 durationField: granted duration in seconds*/
    uint8_t                 unused;
    union {
        uint8_t             raw;
        struct {
            uint8_t         flag   : 1;     /**< 16.1.4.2.6 renewalInvited: granted port consider to renew, if a request arrives during the lease */
            uint8_t         unused : 7;
        };
    } renewal;
} ptp2_signaling_tlv_grant_unicast_t;

/** 16.1.4.3 cancel unicast transmission */
typedef struct _ptp2_signaling_tlv_cancel_unicast_t {
    uint16_t                type;           /**< 16.1.4.3.1 tlvType */
    uint16_t                len;            /**< 16.1.4.3.2 lengthField */
    union {
        uint8_t             raw;
        struct {
            uint8_t         unused : 4;
            uint8_t         type   : 4;     /**< 16.1.4.3.3 messageType */
        };
    } msg;
    uint8_t                 unused;
} ptp2_signaling_tlv_cancel_unicast_t;

/** 16.1.4.4 acknowledge cancel unicast transmission */
typedef struct _ptp2_signaling_tlv_ack_cancel_unicast_t {
    uint16_t                type;           /**< 16.1.4.4.1 tlvType */
    uint16_t                len;            /**< 16.1.4.4.2 lengthField */
    union {
        uint8_t             raw;
        struct {
            uint8_t         unused : 4;
            uint8_t         type   : 4;     /**< 16.1.4.4.3 messageType */
        };
    } msg;
    uint8_t                 unused;
} ptp2_signaling_tlv_ack_cancel_unicast_t;

struct _ptp2_signaling_tlv_header_t {
    header_t                                        header;

    union {
        struct {
            uint16_t                                type;
            uint16_t                                len;
        };
        ptp2_signaling_tlv_request_unicast_t        request_unicast;
        ptp2_signaling_tlv_grant_unicast_t          grant_unicast;
        ptp2_signaling_tlv_cancel_unicast_t         cancel_unicast;
        ptp2_signaling_tlv_ack_cancel_unicast_t     ack_cancel_unicast;
    };
};

ptp2_signaling_tlv_header_t    *ptp2_signaling_tlv_header_new       (void);
void                            ptp2_signaling_tlv_header_free      (header_t *header);
packet_len_t                    ptp2_signaling_tlv_header_encode    (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t                       *ptp2_signaling_tlv_header_decode    (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

