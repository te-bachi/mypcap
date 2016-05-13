
#include "packet/packet.h"
#include "log.h"
#include "log_network.h"

#include <string.h>
#include <inttypes.h>

#define PTP2_SIGNALING_STORAGE_INIT_SIZE        2
#define PTP2_SIGNALING_FAILURE_EXIT             ptp2_signaling_header_free((header_t *) ptp2_signaling); \
                                                return NULL


static ptp2_signaling_header_t              ptp2_signaling[PTP2_SIGNALING_STORAGE_INIT_SIZE];
static uint32_t                             idx[PTP2_SIGNALING_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = HEADER_TYPE_PTP2_SIGNALING,
    .size               = sizeof(ptp2_signaling_header_t),
    .free               = ptp2_signaling_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) ptp2_signaling,
    .allocator_size     = PTP2_SIGNALING_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = PTP2_SIGNALING_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .init               = &entry
};

ptp2_signaling_header_t *
ptp2_signaling_header_new(void)
{
    ptp2_signaling_header_t *header = (ptp2_signaling_header_t *) header_storage_new(&storage);

    LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING, LOG_DEBUG, ("PTP2 signaling header new 0x%016" PRIxPTR, (uintptr_t) header));

    return header;
}

void
ptp2_signaling_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);

    LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING, LOG_DEBUG, ("PTP2 signaling header free 0x%016" PRIxPTR, (uintptr_t) header));

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
ptp2_signaling_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ptp2_signaling_header_t    *ptp2_signaling;
    packet_len_t                len;

    if (packet->tail->klass->type != HEADER_TYPE_PTP2_SIGNALING) {
        LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING, LOG_ERROR, ("%s header encode: next header is not a %s header but a %s header!",
                log_header_type(HEADER_TYPE_PTP2_SIGNALING),
                log_header_type(HEADER_TYPE_PTP2_SIGNALING),
                log_header_type(packet->tail->klass->type)));
        return 0;
    }

    ptp2_signaling = (ptp2_signaling_header_t *) packet->tail;
    packet->tail    = ptp2_signaling->header.next;
    
    len = ptp2_signaling_tlv_header_encode(netif, packet, raw_packet, offset + PTP2_SIGNALING_HEADER_TARGET_PORT_IDENT_LEN);

    if (len == 0) {
        return 0;
    }

    /* push */
    memcpy(&(raw_packet->data[offset + PTP2_SIGNALING_HEADER_OFFSET_TARGET_CLOCK_IDENT]), &(ptp2_signaling->target_port_identity.clock_identity.raw), PTP2_CLOCK_IDENTITY_LEN);  /**< targetClockIdentity */
    uint16_to_uint8(&(raw_packet->data[offset + PTP2_SIGNALING_HEADER_OFFSET_TARGET_PORT_NUMBER]), &(ptp2_signaling->target_port_identity.port_number));                         /**< targetPortNumber */

    len += PTP2_SIGNALING_HEADER_TARGET_PORT_IDENT_LEN;

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
ptp2_signaling_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ptp2_signaling_header_t *ptp2_signaling = ptp2_signaling_header_new();
    
    if (raw_packet->len < (offset + PTP2_SIGNALING_HEADER_TARGET_PORT_IDENT_LEN)) {
        LOG_PRINTLN(LOG_HEADER_PTP2_SIGNALING, LOG_ERROR, ("decode PTPv2 signaling packet: size too small (present=%u, required=%u)", raw_packet->len, (offset + PTP2_SIGNALING_HEADER_TARGET_PORT_IDENT_LEN)));
        PTP2_SIGNALING_FAILURE_EXIT;
    }
    
    /* pre-fetch */
    memcpy(&(ptp2_signaling->target_port_identity.clock_identity.raw), &(raw_packet->data[offset + PTP2_SIGNALING_HEADER_OFFSET_TARGET_CLOCK_IDENT]), PTP2_CLOCK_IDENTITY_LEN);  /**< targetClockIdentity */
    uint8_to_uint16(&(ptp2_signaling->target_port_identity.port_number), &(raw_packet->data[offset + PTP2_SIGNALING_HEADER_OFFSET_TARGET_PORT_NUMBER]));                         /**< targetPortNumber */
    
    /* first TLV */
    ptp2_signaling->header.next = ptp2_signaling_tlv_header_decode(netif, packet, raw_packet, offset + PTP2_SIGNALING_HEADER_TARGET_PORT_IDENT_LEN);
    
    if (ptp2_signaling->header.next == NULL) {
        PTP2_SIGNALING_FAILURE_EXIT;
    }

    return (header_t *) ptp2_signaling;
}

