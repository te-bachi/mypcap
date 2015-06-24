#include "packet/packet.h"
#include "log.h"
#include "log_ptp2.h"

#include <string.h>
#include <inttypes.h>

#define PTP2_SIGNALING_TLV_STORAGE_INIT_SIZE    2
#define PTP2_SIGNALING_TLV_FAILURE_EXIT         ptp2_signaling_tlv_header_free((header_t *) ptp2_signaling_tlv); \
                                                return NULL


static ptp2_signaling_tlv_header_t              ptp2_signaling_tlv[PTP2_SIGNALING_TLV_STORAGE_INIT_SIZE];
static uint32_t                                 idx[PTP2_SIGNALING_TLV_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = PACKET_TYPE_PTP2_SIGNALING_TLV,
    .size               = sizeof(ptp2_signaling_tlv_header_t),
    .free               = ptp2_signaling_tlv_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) ptp2_signaling_tlv,
    .allocator_size     = PTP2_SIGNALING_TLV_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = PTP2_SIGNALING_TLV_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .init               = &entry
};

ptp2_signaling_tlv_header_t *
ptp2_signaling_tlv_header_new(void)
{
    ptp2_signaling_tlv_header_t *header = (ptp2_signaling_tlv_header_t *) header_storage_new(&storage);

    LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING_TLV, LOG_DEBUG, ("PTP2 signaling TLV header new 0x%016" PRIxPTR, (unsigned long) header));

    return header;
}

void
ptp2_signaling_tlv_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);

    LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING_TLV, LOG_DEBUG, ("PTP2 signaling TLV header free 0x%016" PRIxPTR, (unsigned long) header));

    header_storage_free(header);
}

/****************************************************************************
 * ptp2_signaling_header_encode
 *
 * @param  this                     logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @param  offset    offset from origin to ptp signaling packet
 * @return                          number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
ptp2_signaling_tlv_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ptp2_signaling_tlv_header_t    *ptp2_signaling_tlv;
    packet_len_t                    len;

    if (packet->tail->klass->type != PACKET_TYPE_PTP2_SIGNALING_TLV) {
        return 0;
    }

    ptp2_signaling_tlv  = (ptp2_signaling_tlv_header_t *) packet->tail;
    packet->tail        = ptp2_signaling_tlv->header.next;

    /* request unicast transmission */
    if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION) {

        /* push the rest */
        uint16_to_uint8(&(raw_packet->data[offset + PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_TYPE]),         &(ptp2_signaling_tlv->request_unicast.type));                          /**< tlvType */
        uint16_to_uint8(&(raw_packet->data[offset + PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_LEN]),          &(ptp2_signaling_tlv->request_unicast.len));                           /**< lengthField */
        uint32_to_uint8(&(raw_packet->data[offset + PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_DURATION]),     &(ptp2_signaling_tlv->request_unicast.duration));                      /**< duration */
        raw_packet->data[offset + PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_MSG_TYPE]                         = ptp2_signaling_tlv->request_unicast.msg.raw;                         /**< messageType + reserved */
        raw_packet->data[offset + PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_LOG_PERIOD]                       = ptp2_signaling_tlv->request_unicast.log_period;                      /**< logInterMessagePeriod */

        len = PTP2_SIGNALING_TLV_MIN_LEN + PTP2_SIGNALING_TLV_REQUEST_UNICAST_LEN;

    /* grant unicast transmission */
    } else if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_GRANT_UNICAST_TRANSMISSION) {

        /* push the rest */
        uint16_to_uint8(&(raw_packet->data[offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_TYPE]),           &(ptp2_signaling_tlv->grant_unicast.type));                            /**< tlvType */
        uint16_to_uint8(&(raw_packet->data[offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_LEN]),            &(ptp2_signaling_tlv->grant_unicast.len));                             /**< lengthField */
        uint32_to_uint8(&(raw_packet->data[offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_DURATION]),       &(ptp2_signaling_tlv->grant_unicast.duration));                        /**< duration */
        raw_packet->data[offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_MSG_TYPE]                           = ptp2_signaling_tlv->grant_unicast.msg.raw;                           /**< messageType + reserved */
        raw_packet->data[offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_LOG_PERIOD]                         = ptp2_signaling_tlv->grant_unicast.log_period;                        /**< logInterMessagePeriod */
        raw_packet->data[offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_RENEWAL]                            = ptp2_signaling_tlv->grant_unicast.renewal.raw;                       /**< renewalInvited */

        len = PTP2_SIGNALING_TLV_MIN_LEN + PTP2_SIGNALING_TLV_GRANT_UNICAST_LEN;

    /* cancel unicast transmission */
    } else if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION) {

        /* push the rest */
        uint16_to_uint8(&(raw_packet->data[offset + PTP2_SIGNALING_TLV_CANCEL_UNICAST_OFFSET_TYPE]),          &(ptp2_signaling_tlv->cancel_unicast.type));                           /**< tlvType */
        uint16_to_uint8(&(raw_packet->data[offset + PTP2_SIGNALING_TLV_CANCEL_UNICAST_OFFSET_LEN]),           &(ptp2_signaling_tlv->cancel_unicast.len));                            /**< lengthField */
        raw_packet->data[offset + PTP2_SIGNALING_TLV_CANCEL_UNICAST_OFFSET_MSG_TYPE]                          = ptp2_signaling_tlv->cancel_unicast.msg.raw;                          /**< messageType + reserved */
        raw_packet->data[offset + PTP2_SIGNALING_TLV_CANCEL_UNICAST_OFFSET_UNUSED]                            = ptp2_signaling_tlv->cancel_unicast.unused;                           /**< unused */

        len = PTP2_SIGNALING_TLV_MIN_LEN + PTP2_SIGNALING_TLV_CANCEL_UNICAST_LEN;

    /* acknowledge cancel unicast transmission */
    } else if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_ACK_CANCEL_UNICAST_TRANSMISSION) {
        
        /* push the rest */
        uint16_to_uint8(&(raw_packet->data[offset + PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_OFFSET_TYPE]),      &(ptp2_signaling_tlv->ack_cancel_unicast.type));                       /**< tlvType */
        uint16_to_uint8(&(raw_packet->data[offset + PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_OFFSET_LEN]),       &(ptp2_signaling_tlv->ack_cancel_unicast.len));                        /**< lengthField */
        raw_packet->data[offset + PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_OFFSET_MSG_TYPE]                      = ptp2_signaling_tlv->ack_cancel_unicast.msg.raw;                      /**< messageType + reserved */
        raw_packet->data[offset + PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_OFFSET_UNUSED]                        = ptp2_signaling_tlv->ack_cancel_unicast.unused;                       /**< unused */
        
        len = PTP2_SIGNALING_TLV_MIN_LEN + PTP2_SIGNALING_TLV_CANCEL_UNICAST_LEN;
    }

    if (packet->tail != NULL) {
        len += ptp2_signaling_tlv_header_encode(netif, packet, raw_packet, offset + len);
    }
    
    return len;
}

/****************************************************************************
 * ptp2_signaling_header_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 * @param  offset    offset from origin to ptp signaling packet
 ***************************************************************************/
header_t *
ptp2_signaling_tlv_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ptp2_signaling_tlv_header_t    *ptp2_signaling_tlv = ptp2_signaling_tlv_header_new();
    
    if (raw_packet->len < (offset + PTP2_SIGNALING_TLV_MIN_LEN)) {
        LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING_TLV, LOG_ERROR, ("decode PTPv2 signaling TLV header: size too small (present=%u, required=%u)", raw_packet->len, (offset + PTP2_SIGNALING_TLV_MIN_LEN)));
        PTP2_SIGNALING_TLV_FAILURE_EXIT;
    }

    /* pre-fetch */
    uint8_to_uint16(&(ptp2_signaling_tlv->type), &(raw_packet->data[offset + PTP2_SIGNALING_TLV_OFFSET_TYPE]));                                                                      /**< tlvType */
    uint8_to_uint16(&(ptp2_signaling_tlv->len),  &(raw_packet->data[offset + PTP2_SIGNALING_TLV_OFFSET_LEN]));                                                                       /**< lengthField */

    /* decide */
    LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING_TLV, LOG_DEBUG, ("decode PTPv2 signaling TLV header: type=%s len=%u", log_ptp2_signaling_tlv_type(ptp2_signaling_tlv->type), ptp2_signaling_tlv->len));

    /* request unicast transmission */
    if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION) {

        if (ptp2_signaling_tlv->len != PTP2_SIGNALING_TLV_REQUEST_UNICAST_LEN || raw_packet->len < (offset + PTP2_SIGNALING_TLV_REQUEST_UNICAST_LEN)) {
            LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING_TLV, LOG_ERROR, ("decode PTPv2 signaling TLV request unicast transmission header: size too small (present=%u, required=%u)", raw_packet->len, (offset + PTP2_SIGNALING_TLV_REQUEST_UNICAST_LEN)));
            PTP2_SIGNALING_TLV_FAILURE_EXIT;
        }

        /* fetch the rest */
        ptp2_signaling_tlv->request_unicast.msg.raw                        = raw_packet->data[offset + PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_MSG_TYPE];                          /**< messageType + reserved */
        ptp2_signaling_tlv->request_unicast.log_period                     = raw_packet->data[offset + PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_LOG_PERIOD];                        /**< logInterMessagePeriod */
        uint8_to_uint32(&(ptp2_signaling_tlv->request_unicast.duration),   &(raw_packet->data[offset + PTP2_SIGNALING_TLV_REQUEST_UNICAST_OFFSET_DURATION]));                        /**< durationField */

        offset += PTP2_SIGNALING_TLV_MIN_LEN + PTP2_SIGNALING_TLV_REQUEST_UNICAST_LEN;

    /* grant unicast transmission */
    } else if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_GRANT_UNICAST_TRANSMISSION) {

        if (ptp2_signaling_tlv->len != PTP2_SIGNALING_TLV_GRANT_UNICAST_LEN || raw_packet->len < (offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_LEN)) {
            LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING_TLV, LOG_ERROR, ("decode PTPv2 signaling TLV grant unicast transmission header: size too small (present=%u, required=%u)", raw_packet->len, (offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_LEN)));
            PTP2_SIGNALING_TLV_FAILURE_EXIT;
        }

        /* fetch the rest */
        ptp2_signaling_tlv->grant_unicast.msg.raw                          = raw_packet->data[offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_MSG_TYPE];                            /**< messageType + reserved */
        ptp2_signaling_tlv->grant_unicast.log_period                       = raw_packet->data[offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_LOG_PERIOD];                          /**< logInterMessagePeriod */
        ptp2_signaling_tlv->grant_unicast.renewal.raw                      = raw_packet->data[offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_RENEWAL];                             /**< renewalInvited */
        uint8_to_uint32(&(ptp2_signaling_tlv->grant_unicast.duration),     &(raw_packet->data[offset + PTP2_SIGNALING_TLV_GRANT_UNICAST_OFFSET_DURATION]));                          /**< durationField */

        offset += PTP2_SIGNALING_TLV_MIN_LEN + PTP2_SIGNALING_TLV_GRANT_UNICAST_LEN;

    /* cancel unicast transmission */
    } else if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION) {
        
        if (ptp2_signaling_tlv->len != PTP2_SIGNALING_TLV_CANCEL_UNICAST_LEN || raw_packet->len < (offset + PTP2_SIGNALING_TLV_CANCEL_UNICAST_LEN)) {
            LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING_TLV, LOG_ERROR, ("decode PTPv2 signaling TLV cancel unicast transmission header: size too small (present=%u, required=%u)", raw_packet->len, (offset + PTP2_SIGNALING_TLV_CANCEL_UNICAST_LEN)));
            PTP2_SIGNALING_TLV_FAILURE_EXIT;
        }

        /* fetch the rest */
        ptp2_signaling_tlv->cancel_unicast.msg.raw                         = raw_packet->data[offset + PTP2_SIGNALING_TLV_CANCEL_UNICAST_OFFSET_MSG_TYPE];                           /**< messageType + reserved */

        offset += PTP2_SIGNALING_TLV_MIN_LEN + PTP2_SIGNALING_TLV_CANCEL_UNICAST_LEN;

    /* acknowledge cancel unicast transmission */
    } else if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_ACK_CANCEL_UNICAST_TRANSMISSION) {

        if (ptp2_signaling_tlv->len != PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_LEN || raw_packet->len < (offset + PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_LEN)) {
            LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING_TLV, LOG_ERROR, ("decode PTPv2 signaling TLV acknowledge cancel unicast transmission header: size too small (present=%u, required=%u)", raw_packet->len, (offset + PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_LEN)));
            PTP2_SIGNALING_TLV_FAILURE_EXIT;
        }

        /* fetch the rest */
        ptp2_signaling_tlv->ack_cancel_unicast.msg.raw                     = raw_packet->data[offset + PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_OFFSET_MSG_TYPE];                       /**< messageType + reserved */

        offset += PTP2_SIGNALING_TLV_MIN_LEN + PTP2_SIGNALING_TLV_ACK_CANCEL_UNICAST_LEN;

    } else {
        LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING_TLV, LOG_DEBUG, ("decode PTPv2 signaling TLV header: unknow type, packet will be ignored"));
        PTP2_SIGNALING_TLV_FAILURE_EXIT;
    }
    
    
    return (header_t *) ptp2_signaling_tlv;
}

