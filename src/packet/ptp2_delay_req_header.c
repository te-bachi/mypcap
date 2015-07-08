#include "packet/packet.h"
#include "log.h"

#include <string.h>
#include <inttypes.h>

#define PTP2_DELAY_REQ_STORAGE_INIT_SIZE        2
#define PTP2_DELAY_REQ_FAILURE_EXIT             ptp2_delay_req_header_free((header_t *) ptp2_delay_req); \
                                                return NULL


static ptp2_delay_req_header_t              ptp2_delay_req[PTP2_DELAY_REQ_STORAGE_INIT_SIZE];
static uint32_t                             idx[PTP2_DELAY_REQ_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = PACKET_TYPE_PTP2_DELAY_REQ,
    .size               = sizeof(ptp2_delay_req_header_t),
    .free               = ptp2_delay_req_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) ptp2_delay_req,
    .allocator_size     = PTP2_DELAY_REQ_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = PTP2_DELAY_REQ_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .init               = &entry
};

ptp2_delay_req_header_t *
ptp2_delay_req_header_new(void)
{
    ptp2_delay_req_header_t *header = (ptp2_delay_req_header_t *) header_storage_new(&storage);

    LOG_PRINTLN(LOG_HEADER_PTP2_DELAY_REQ, LOG_DEBUG, ("PTP2 delay req header new 0x%016" PRIxPTR, (unsigned long) header));

    return header;
}

void
ptp2_delay_req_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);

    LOG_PRINTLN(LOG_HEADER_PTP2_DELAY_REQ, LOG_DEBUG, ("PTP2 delay req header free 0x%016" PRIxPTR, (unsigned long) header));

    header_storage_free(header);
}

/****************************************************************************
 * ptp2_delay_req_header_encode
 *
 * @param  this                     logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @param  offset    offset from origin to ptp delay req packet
 * @return                          number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
ptp2_delay_req_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ptp2_delay_req_header_t    *ptp2_delay_req;
    packet_len_t                len;

    if (packet->tail->klass->type != PACKET_TYPE_PTP2_DELAY_REQ) {
        return 0;
    }

    ptp2_delay_req = (ptp2_delay_req_header_t *) packet->tail;
    packet->tail    = ptp2_delay_req->header.next;

    /* push */
    uint48_to_uint8(&(raw_packet->data[offset + PTP2_DELAY_REQ_HEADER_OFFSET_ORIGIN_TIMESTAMP_SECONDS]),        &(ptp2_delay_req->origin_timestamp.seconds));
    uint32_to_uint8(&(raw_packet->data[offset + PTP2_DELAY_REQ_HEADER_OFFSET_ORIGIN_TIMESTAMP_NANOSECONDS]),    &(ptp2_delay_req->origin_timestamp.nanoseconds));

    len += PTP2_DELAY_REQ_HEADER_LEN;

    return len;
}

/****************************************************************************
 * ptp2_delay_req_header_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 * @param  offset    offset from origin to ptp delay req packet
 ***************************************************************************/
header_t *
ptp2_delay_req_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ptp2_delay_req_header_t *ptp2_delay_req = ptp2_delay_req_header_new();

    if (raw_packet->len < (offset + PTP2_DELAY_REQ_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_PTP2_DELAY_REQ, LOG_ERROR, ("decode PTPv2 delay req packet: size too small (present=%u, required=%u)", raw_packet->len, (offset + PTP2_DELAY_REQ_HEADER_LEN)));
        PTP2_DELAY_REQ_FAILURE_EXIT;
    }

    /* fetch */
    uint8_to_uint48(&(ptp2_delay_req->origin_timestamp.seconds),        &(raw_packet->data[offset + PTP2_DELAY_REQ_HEADER_OFFSET_ORIGIN_TIMESTAMP_SECONDS]));
    uint8_to_uint32(&(ptp2_delay_req->origin_timestamp.nanoseconds),    &(raw_packet->data[offset + PTP2_DELAY_REQ_HEADER_OFFSET_ORIGIN_TIMESTAMP_NANOSECONDS]));

    return (header_t *) ptp2_delay_req;
}

