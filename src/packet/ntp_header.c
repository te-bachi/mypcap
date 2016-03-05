
#include "packet/packet.h"
#include "log.h"
#include "log_network.h"

#include <string.h>
#include <inttypes.h>

#define NTP_STORAGE_INIT_SIZE       2
#define NTP_FAILURE_EXIT            ntp_header_free((header_t *) ntp); \
                                    return NULL


static ntp_header_t                 ntp[NTP_STORAGE_INIT_SIZE];
static uint32_t                     idx[NTP_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = HEADER_TYPE_NTP,
    .size               = sizeof(ntp_header_t),
    .free               = ntp_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) ntp,
    .allocator_size     = NTP_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = NTP_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .init               = &entry
};

ntp_header_t *
ntp_header_new(void)
{
    ntp_header_t *header = (ntp_header_t *) header_storage_new(&storage);

    LOG_PRINTLN(LOG_HEADER_NTP, LOG_DEBUG, ("NTP header new 0x%016" PRIxPTR, (unsigned long) header));

    return header;
}

void
ntp_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);

    LOG_PRINTLN(LOG_HEADER_NTP, LOG_DEBUG, ("NTP header free 0x%016" PRIxPTR, (unsigned long) header));

    header_storage_free(header);
}

/****************************************************************************
 * ntp_header_encode
 *
 * @param  this                     logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @param  offset              offset from origin to ptp packet
 * @return                          number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
ntp_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ntp_header_t      *ntp;
    packet_len_t        len;

    if (packet->tail->klass->type != HEADER_TYPE_NTP) {
        LOG_PRINTLN(LOG_HEADER_NTP, LOG_ERROR, ("%s header encode: next header is not a %s header but a %s header!",
                log_header_type(HEADER_TYPE_NTP),
                log_header_type(HEADER_TYPE_NTP),
                log_header_type(packet->tail->klass->type)));
        return 0;
    }

    ntp             = (ntp_header_t *) packet->tail;
    packet->tail    = ntp->header.next;
    len             = 0;

    len = NTP_HEADER_MIN_LEN;

    raw_packet->data[offset + NTP_HEADER_OFFSET_FLAGS]                                             = ntp->flags_raw;
    raw_packet->data[offset + NTP_HEADER_OFFSET_PEER_CLOCK_STRATUM]                                = ntp->stratum;
    raw_packet->data[offset + NTP_HEADER_OFFSET_PEER_POLLING_INTERVAL]                             = ntp->polling_interval;
    raw_packet->data[offset + NTP_HEADER_OFFSET_PEER_CLOCK_PRECISION]                              = ntp->clock_precision;
    uint32_to_uint8(&(raw_packet->data[offset + NTP_HEADER_OFFSET_ROOT_DELAY]),                    &(ntp->root_delay));
    uint32_to_uint8(&(raw_packet->data[offset + NTP_HEADER_OFFSET_ROOT_DISPERSION]),               &(ntp->root_dispersion));
    memcpy(&(raw_packet->data[offset + NTP_HEADER_OFFSET_REFERENCE_ID]),                           &(ntp->reference_id), NTP_REFERENCE_ID_LEN);
    uint32_to_uint8(&(raw_packet->data[offset + NTP_HEADER_OFFSET_REFERENCE_TIMESTAMP_SEC]),       &(ntp->reference_timestamp.seconds));
    uint32_to_uint8(&(raw_packet->data[offset + NTP_HEADER_OFFSET_REFERENCE_TIMESTAMP_NANOSEC]),   &(ntp->reference_timestamp.nanoseconds));
    uint32_to_uint8(&(raw_packet->data[offset + NTP_HEADER_OFFSET_ORIGIN_TIMESTAMP_SEC]),          &(ntp->origin_timestamp.seconds));
    uint32_to_uint8(&(raw_packet->data[offset + NTP_HEADER_OFFSET_ORIGIN_TIMESTAMP_NANOSEC]),      &(ntp->origin_timestamp.nanoseconds));
    uint32_to_uint8(&(raw_packet->data[offset + NTP_HEADER_OFFSET_RECEIVE_TIMESTAMP_SEC]),         &(ntp->receive_timestamp.seconds));
    uint32_to_uint8(&(raw_packet->data[offset + NTP_HEADER_OFFSET_RECEIVE_TIMESTAMP_NANOSEC]),     &(ntp->receive_timestamp.nanoseconds));
    uint32_to_uint8(&(raw_packet->data[offset + NTP_HEADER_OFFSET_TRANSMIT_TIMESTAMP_SEC]),        &(ntp->transmit_timestamp.seconds));
    uint32_to_uint8(&(raw_packet->data[offset + NTP_HEADER_OFFSET_TRANSMIT_TIMESTAMP_NANOSEC]),    &(ntp->transmit_timestamp.nanoseconds));

    /* is there an ADVA TLV appended? */
    if (packet->tail->klass->type == HEADER_TYPE_ADVA_TLV) {
        len += adva_tlv_header_encode(netif, packet, raw_packet, offset + len);

        if (len == 0) {
            return 0;
        }
    }

    return len;
}

/****************************************************************************
 * ntp_header_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 * @param  offset              offset from origin to ptp packet
 ***************************************************************************/
header_t *
ntp_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ntp_header_t *ntp = ntp_header_new();

    if (raw_packet->len < (offset + NTP_HEADER_MIN_LEN)) {
        LOG_PRINTLN(LOG_HEADER_NTP, LOG_ERROR, ("decode NTP packet: size too small (present=%u, required=%u)", raw_packet->len, (offset + NTP_HEADER_MIN_LEN)));
        NTP_FAILURE_EXIT;
    }

    /* check length of packet to see, if extension fields,
     * message authentication code (MAC) or an
     * ADVA TLV is appended
     *
     * +   12 bytes = ADVA TLV
     * +   20 bytes = MAC
     * + > 36 bytes = extension field + MAC or more
     */

    /* fetch the rest */
    ntp->flags_raw                                             = raw_packet->data[offset + NTP_HEADER_OFFSET_FLAGS];
    ntp->stratum                                               = raw_packet->data[offset + NTP_HEADER_OFFSET_PEER_CLOCK_STRATUM];
    ntp->polling_interval                                      = raw_packet->data[offset + NTP_HEADER_OFFSET_PEER_POLLING_INTERVAL];
    ntp->clock_precision                                       = raw_packet->data[offset + NTP_HEADER_OFFSET_PEER_CLOCK_PRECISION];
    uint8_to_uint32(&(ntp->root_delay),                        &(raw_packet->data[offset + NTP_HEADER_OFFSET_ROOT_DELAY]));
    uint8_to_uint32(&(ntp->root_dispersion),                   &(raw_packet->data[offset + NTP_HEADER_OFFSET_ROOT_DISPERSION]));
    memcpy(&(ntp->reference_id),                               &(raw_packet->data[offset + NTP_HEADER_OFFSET_REFERENCE_ID]), NTP_REFERENCE_ID_LEN);
    uint8_to_uint32(&(ntp->reference_timestamp.seconds),       &(raw_packet->data[offset + NTP_HEADER_OFFSET_REFERENCE_TIMESTAMP_SEC]));
    uint8_to_uint32(&(ntp->reference_timestamp.nanoseconds),   &(raw_packet->data[offset + NTP_HEADER_OFFSET_REFERENCE_TIMESTAMP_NANOSEC]));
    uint8_to_uint32(&(ntp->origin_timestamp.seconds),          &(raw_packet->data[offset + NTP_HEADER_OFFSET_ORIGIN_TIMESTAMP_SEC]));
    uint8_to_uint32(&(ntp->origin_timestamp.nanoseconds),      &(raw_packet->data[offset + NTP_HEADER_OFFSET_ORIGIN_TIMESTAMP_NANOSEC]));
    uint8_to_uint32(&(ntp->receive_timestamp.seconds),         &(raw_packet->data[offset + NTP_HEADER_OFFSET_RECEIVE_TIMESTAMP_SEC]));
    uint8_to_uint32(&(ntp->receive_timestamp.nanoseconds),     &(raw_packet->data[offset + NTP_HEADER_OFFSET_RECEIVE_TIMESTAMP_NANOSEC]));
    uint8_to_uint32(&(ntp->transmit_timestamp.seconds),        &(raw_packet->data[offset + NTP_HEADER_OFFSET_TRANSMIT_TIMESTAMP_SEC]));
    uint8_to_uint32(&(ntp->transmit_timestamp.nanoseconds),    &(raw_packet->data[offset + NTP_HEADER_OFFSET_TRANSMIT_TIMESTAMP_NANOSEC]));

    return (header_t *) ntp;
}

