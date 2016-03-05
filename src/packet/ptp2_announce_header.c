
#include "packet/packet.h"
#include "log.h"
#include "log_network.h"

#include <string.h>
#include <inttypes.h>

#define PTP2_ANNOUNCE_STORAGE_INIT_SIZE     2
#define PTP2_ANNOUNCE_FAILURE_EXIT          ptp2_announce_header_free((header_t *) ptp2_announce); \
                                            return NULL


static ptp2_announce_header_t               ptp2_announce[PTP2_ANNOUNCE_STORAGE_INIT_SIZE];
static uint32_t                             idx[PTP2_ANNOUNCE_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = HEADER_TYPE_PTP2_ANNOUNCE,
    .size               = sizeof(ptp2_announce_header_t),
    .free               = ptp2_announce_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) ptp2_announce,
    .allocator_size     = PTP2_ANNOUNCE_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = PTP2_ANNOUNCE_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .init               = &entry
};

ptp2_announce_header_t *
ptp2_announce_header_new(void)
{
    ptp2_announce_header_t *header = (ptp2_announce_header_t *) header_storage_new(&storage);

    LOG_PRINTLN(LOG_HEADER_PTP2_ANNOUNCE, LOG_DEBUG, ("PTP2 announce header new 0x%016" PRIxPTR, (unsigned long) header));

    return header;
}

void
ptp2_announce_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);

    LOG_PRINTLN(LOG_HEADER_PTP2_ANNOUNCE, LOG_DEBUG, ("PTP2 announce header free 0x%016" PRIxPTR, (unsigned long) header));

    header_storage_free(header);
}

/****************************************************************************
 * ptp2_announce_header_encode
 *
 * @param  this                     logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @param  offset     offset from origin to ptp announce packet
 * @return                          number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
ptp2_announce_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    return 0;
}

/****************************************************************************
 * ptp2_announce_header_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 * @param  offset     offset from origin to ptp announce packet
 ***************************************************************************/
header_t *
ptp2_announce_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ptp2_announce_header_t *ptp2_announce = ptp2_announce_header_new();
    
    if (raw_packet->len < (offset + PTP2_ANNOUNCE_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_PTP2_ANNOUNCE, LOG_ERROR, ("decode PTPv2 announce packet: size too small (present=%u, required=%u)", raw_packet->len, (offset + PTP2_ANNOUNCE_HEADER_LEN)));
        PTP2_ANNOUNCE_FAILURE_EXIT;
    }
    
    /* fetch */
    //memcpy(&(ptp2_announce->origin_timestamp.raw),  &(raw_packet->data[offset + PTP2_ANNOUNCE_HEADER_OFFSET_ORIGIN_TIMESTAMP]),   sizeof(ptp2_announce->origin_timestamp.raw));
    memcpy(&(ptp2_announce->current_utc_offset),    &(raw_packet->data[offset + PTP2_ANNOUNCE_HEADER_OFFSET_CURRENT_UTC_OFFSET]), sizeof(ptp2_announce->current_utc_offset));
    memcpy(&(ptp2_announce->gm_priority1),          &(raw_packet->data[offset + PTP2_ANNOUNCE_HEADER_OFFSET_GM_PRIORITY1]),       sizeof(ptp2_announce->gm_priority1));
    //memcpy(&(ptp2_announce->gm_clock_quality.raw),  &(raw_packet->data[offset + PTP2_ANNOUNCE_HEADER_OFFSET_GM_CLOCK_QUALITY]),   sizeof(ptp2_announce->gm_clock_quality.raw));
    memcpy(&(ptp2_announce->gm_priority2),          &(raw_packet->data[offset + PTP2_ANNOUNCE_HEADER_OFFSET_GM_PRIORITY2]),       sizeof(ptp2_announce->gm_priority2));
    memcpy(&(ptp2_announce->gm_identity),           &(raw_packet->data[offset + PTP2_ANNOUNCE_HEADER_OFFSET_GM_IDENTITY]),        sizeof(ptp2_announce->gm_identity));
    memcpy(&(ptp2_announce->steps_removed),         &(raw_packet->data[offset + PTP2_ANNOUNCE_HEADER_OFFSET_STEPS_REMOVED]),      sizeof(ptp2_announce->steps_removed));
    memcpy(&(ptp2_announce->time_source),           &(raw_packet->data[offset + PTP2_ANNOUNCE_HEADER_OFFSET_TIME_SOURCE]),        sizeof(ptp2_announce->time_source));

    
    return (header_t *) ptp2_announce;
}

