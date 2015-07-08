

#include "packet/packet.h"
#include "log.h"

#include <string.h>
#include <inttypes.h>

#define PTP2_STORAGE_INIT_SIZE      2
#define PTP2_FAILURE_EXIT           ptp2_header_free((header_t *) ptp2); \
                                    return NULL


static ptp2_header_t            ptp2[PTP2_STORAGE_INIT_SIZE];
static uint32_t                 idx[PTP2_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = PACKET_TYPE_PTP2,
    .size               = sizeof(ptp2_header_t),
    .free               = ptp2_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) ptp2,
    .allocator_size     = PTP2_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = PTP2_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .init               = &entry
};

ptp2_header_t *
ptp2_header_new(void)
{
    ptp2_header_t *header = (ptp2_header_t *) header_storage_new(&storage);

    LOG_PRINTLN(LOG_HEADER_PTP2, LOG_DEBUG, ("PTP2 header new 0x%016" PRIxPTR, (unsigned long) header));

    return header;
}

void
ptp2_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);

    LOG_PRINTLN(LOG_HEADER_PTP2, LOG_DEBUG, ("PTP2 header free 0x%016" PRIxPTR, (unsigned long) header));

    header_storage_free(header);
}

/****************************************************************************
 * ptp2_header_encode
 *
 * @param  this                     logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @param  offset              offset from origin to ptp packet
 * @return                          number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
ptp2_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ptp2_header_t      *ptp2;
    packet_len_t        len;

    if (packet->tail->klass->type != PACKET_TYPE_PTP2) {
        return 0;
    }

    ptp2            = (ptp2_header_t *) packet->tail;
    packet->tail    = ptp2->header.next;
    
    /* decide */
    switch (ptp2->msg_type) {
        case PTP2_MESSAGE_TYPE_SIGNALING:   len = ptp2_signaling_header_encode(netif, packet, raw_packet, offset + PTP2_HEADER_LEN);    break;
        case PTP2_MESSAGE_TYPE_ANNOUNCE:    len = ptp2_announce_header_encode(netif, packet, raw_packet, offset + PTP2_HEADER_LEN);     break;
        default:                                                                                                                        return 0;
    }
    
    if (len == 0) {
        return 0;
    }
    
    len += PTP2_HEADER_LEN;
    
    raw_packet->data[offset + PTP2_HEADER_OFFSET_MSG_TYPE]                             = ptp2->msg_raw;                                                         /**< transportSpecific + messageType */
    raw_packet->data[offset + PTP2_HEADER_OFFSET_VERSION]                              = ptp2->version;                                                         /**< reserved + versionPTP */
    raw_packet->data[offset + PTP2_HEADER_OFFSET_DOMAIN_NUMBER]                        = ptp2->domain_number;                                                   /**< domainNumber */
    raw_packet->data[offset + PTP2_HEADER_OFFSET_CONTROL]                              = ptp2->control;                                                         /**< controlField */
    raw_packet->data[offset + PTP2_HEADER_OFFSET_LOG_MSG_INTERVAL]                     = ptp2->log_msg_interval;                                                /**< logMessageInterval */
    uint16_to_uint8(&(raw_packet->data[offset + PTP2_HEADER_OFFSET_MSG_LEN]),          &(ptp2->msg_len));                                                       /**< messageLength */
    uint16_to_uint8(&(raw_packet->data[offset + PTP2_HEADER_OFFSET_FLAGS]),            &(ptp2->flags));                                                         /**< flagField */
    int64_to_uint8 (&(raw_packet->data[offset + PTP2_HEADER_OFFSET_CORRECTION]),       &(ptp2->correction.nanoseconds));                                        /**< correctionField */
    uint16_to_uint8(&(raw_packet->data[offset + PTP2_HEADER_OFFSET_SEQ_ID]),           &(ptp2->seq_id));                                                        /**< sequenceId */
    memcpy(&(raw_packet->data[offset + PTP2_HEADER_OFFSET_SRC_CLOCK_IDENTITY]),        &(ptp2->src_port_identity.clock_identity), PTP2_CLOCK_IDENTITY_LEN);     /**< sourceClockIdentity */
    uint16_to_uint8(&(raw_packet->data[offset + PTP2_HEADER_OFFSET_SRC_PORT_NUMBER]),  &(ptp2->src_port_identity.port_number));                                 /**< sourcePortNumber */
    
    return len;
}

/****************************************************************************
 * ptp2_header_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 * @param  offset              offset from origin to ptp packet
 ***************************************************************************/
header_t *
ptp2_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ptp2_header_t *ptp2 = ptp2_header_new();
    
    if (raw_packet->len < (offset + PTP2_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_PTP2, LOG_ERROR, ("decode PTPv2 packet: size too small (present=%u, required=%u)", raw_packet->len, (offset + PTP2_HEADER_LEN)));
        PTP2_FAILURE_EXIT;
    }
    
    /* pre-fetch */
    ptp2->msg_raw             = raw_packet->data[offset + PTP2_HEADER_OFFSET_MSG_TYPE];                                                                         /**< transportSpecific + messageType */
    uint8_to_uint16(&(ptp2->msg_len),                 &(raw_packet->data[offset + PTP2_HEADER_OFFSET_MSG_LEN]));                                               /**< messageLength */
    
    /* check PTPv2-header messageLength with actual packet-size */
    if ((raw_packet->len - offset) != ptp2->msg_len) {
        LOG_PRINTLN(LOG_HEADER_PTP2, LOG_ERROR, ("decode PTPv2 packet: incorrect PTPv2 message length (msg_len=%u, packet_len=%u)", ptp2->msg_len, (raw_packet->len - offset)));
        PTP2_FAILURE_EXIT;
    }
    
    /* decide */
    switch (ptp2->msg_type) {
        case PTP2_MESSAGE_TYPE_SIGNALING:   ptp2->header.next = ptp2_signaling_header_decode(netif, packet, raw_packet, offset + PTP2_HEADER_LEN);   break;
        case PTP2_MESSAGE_TYPE_ANNOUNCE:    ptp2->header.next = ptp2_announce_header_decode(netif, packet, raw_packet, offset + PTP2_HEADER_LEN);     break;
        default:                            PTP2_FAILURE_EXIT;
    }
    
    if (ptp2->header.next == NULL) {
        PTP2_FAILURE_EXIT;
    }

    /* fetch the rest */
    ptp2->version                                               = raw_packet->data[offset + PTP2_HEADER_OFFSET_VERSION];                                        /**< reserved + versionPTP */
    ptp2->domain_number                                         = raw_packet->data[offset + PTP2_HEADER_OFFSET_DOMAIN_NUMBER];                                  /**< domainNumber */
    ptp2->control                                               = raw_packet->data[offset + PTP2_HEADER_OFFSET_CONTROL];                                        /**< controlField */
    ptp2->log_msg_interval                                      = raw_packet->data[offset + PTP2_HEADER_OFFSET_LOG_MSG_INTERVAL];                               /**< logMessageInterval */
    uint8_to_uint16(&(ptp2->flags),                             &(raw_packet->data[offset + PTP2_HEADER_OFFSET_FLAGS]));                                        /**< flagField */
    uint8_to_int64 (&(ptp2->correction.nanoseconds),            &(raw_packet->data[offset + PTP2_HEADER_OFFSET_CORRECTION]));                                   /**< correctionField */
    uint8_to_uint16(&(ptp2->seq_id),                            &(raw_packet->data[offset + PTP2_HEADER_OFFSET_SEQ_ID]));                                       /**< sequenceId */
    memcpy(&(ptp2->src_port_identity.clock_identity),           &(raw_packet->data[offset + PTP2_HEADER_OFFSET_SRC_CLOCK_IDENTITY]), PTP2_CLOCK_IDENTITY_LEN);  /**< sourceClockIdentity */
    uint8_to_uint16(&(ptp2->src_port_identity.port_number),     &(raw_packet->data[offset + PTP2_HEADER_OFFSET_SRC_PORT_NUMBER]));                              /**< sourcePortNumber */

    return (header_t *) ptp2;
}

