
#include "packet/packet.h"
#include "log.h"
#include "log_network.h"

#include <string.h>
#include <inttypes.h>

#define PTP2_DELAY_RESP_STORAGE_INIT_SIZE        2
#define PTP2_DELAY_RESP_FAILURE_EXIT             ptp2_delay_resp_header_free((header_t *) ptp2_delay_resp); \
                                                return NULL


static ptp2_delay_resp_header_t             ptp2_delay_resp[PTP2_DELAY_RESP_STORAGE_INIT_SIZE];
static uint32_t                             idx[PTP2_DELAY_RESP_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = HEADER_TYPE_PTP2_DELAY_RESP,
    .size               = sizeof(ptp2_delay_resp_header_t),
    .free               = ptp2_delay_resp_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) ptp2_delay_resp,
    .allocator_size     = PTP2_DELAY_RESP_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = PTP2_DELAY_RESP_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .init               = &entry
};

ptp2_delay_resp_header_t *
ptp2_delay_resp_header_new(void)
{
    ptp2_delay_resp_header_t *header = (ptp2_delay_resp_header_t *) header_storage_new(&storage);

    LOG_PRINTLN(LOG_HEADER_PTP2_DELAY_RESP, LOG_DEBUG, ("PTP2 delay resp header new 0x%016" PRIxPTR, (uintptr_t) header));

    return header;
}

void
ptp2_delay_resp_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);

    LOG_PRINTLN(LOG_HEADER_PTP2_DELAY_RESP, LOG_DEBUG, ("PTP2 delay resp header free 0x%016" PRIxPTR, (uintptr_t) header));

    header_storage_free(header);
}

/****************************************************************************
 * ptp2_delay_resp_header_encode
 *
 * @param  this                     logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @param  offset    offset from origin to ptp delay resp packet
 * @return                          number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
ptp2_delay_resp_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ptp2_delay_resp_header_t    *ptp2_delay_resp;
    packet_len_t                len;

    if (packet->tail->klass->type != HEADER_TYPE_PTP2_DELAY_RESP) {
        LOG_PRINTLN(LOG_HEADER_PTP2_DELAY_RESP, LOG_ERROR, ("%s header encode: next header is not a %s header but a %s header!",
                log_header_type(HEADER_TYPE_PTP2_DELAY_RESP),
                log_header_type(HEADER_TYPE_PTP2_DELAY_RESP),
                log_header_type(packet->tail->klass->type)));
        return 0;
    }

    ptp2_delay_resp = (ptp2_delay_resp_header_t *) packet->tail;
    packet->tail    = ptp2_delay_resp->header.next;

    /* push */
    uint48_to_uint8(&(raw_packet->data[offset + PTP2_DELAY_RESP_HEADER_OFFSET_RECEIVE_TIMESTAMP_SECONDS]),      &(ptp2_delay_resp->receive_timestamp.seconds));
    uint32_to_uint8(&(raw_packet->data[offset + PTP2_DELAY_RESP_HEADER_OFFSET_RECEIVE_TIMESTAMP_NANOSECONDS]),  &(ptp2_delay_resp->receive_timestamp.nanoseconds));
    memcpy(&(raw_packet->data[offset + PTP2_HEADER_OFFSET_SRC_CLOCK_IDENTITY]),                                 &(ptp2_delay_resp->requesting_port_identity.clock_identity), PTP2_CLOCK_IDENTITY_LEN);
    uint16_to_uint8(&(raw_packet->data[offset + PTP2_HEADER_OFFSET_SRC_PORT_NUMBER]),                           &(ptp2_delay_resp->requesting_port_identity.port_number));
    len += PTP2_DELAY_RESP_HEADER_LEN;

    return len;
}

/****************************************************************************
 * ptp2_delay_resp_header_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 * @param  offset    offset from origin to ptp delay resp packet
 ***************************************************************************/
header_t *
ptp2_delay_resp_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ptp2_delay_resp_header_t *ptp2_delay_resp = ptp2_delay_resp_header_new();

    if (raw_packet->len < (offset + PTP2_DELAY_RESP_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_PTP2_DELAY_RESP, LOG_ERROR, ("decode PTPv2 delay resp packet: size too small (present=%u, required=%u)", raw_packet->len, (offset + PTP2_DELAY_RESP_HEADER_LEN)));
        PTP2_DELAY_RESP_FAILURE_EXIT;
    }

    /* fetch */
    uint8_to_uint48(&(ptp2_delay_resp->receive_timestamp.seconds),              &(raw_packet->data[offset + PTP2_DELAY_RESP_HEADER_OFFSET_RECEIVE_TIMESTAMP_SECONDS]));
    uint8_to_uint32(&(ptp2_delay_resp->receive_timestamp.nanoseconds),          &(raw_packet->data[offset + PTP2_DELAY_RESP_HEADER_OFFSET_RECEIVE_TIMESTAMP_NANOSECONDS]));
    memcpy(&(ptp2_delay_resp->requesting_port_identity.clock_identity),         &(raw_packet->data[offset + PTP2_HEADER_OFFSET_SRC_CLOCK_IDENTITY]), PTP2_CLOCK_IDENTITY_LEN);
    uint8_to_uint16(&(ptp2_delay_resp->requesting_port_identity.port_number),   &(raw_packet->data[offset + PTP2_HEADER_OFFSET_SRC_PORT_NUMBER]));

    return (header_t *) ptp2_delay_resp;
}

