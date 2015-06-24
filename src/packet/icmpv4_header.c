
#include <string.h>
#include <inttypes.h>

#include "log.h"

#include "packet/packet.h"

#define ICMPV4_STORAGE_INIT_SIZE    2
#define ICMPV4_FAILURE_EXIT         icmpv4_header_free((header_t *) icmpv4); \
                                    return NULL


const static uint16_t           CHECKSUM_ZERO = 0x0000;

static icmpv4_header_t          icmpv4[ICMPV4_STORAGE_INIT_SIZE];
static uint32_t                 idx[ICMPV4_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = PACKET_TYPE_ICMPV4,
    .size               = sizeof(icmpv4_header_t),
    .free               = icmpv4_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) icmpv4,
    .allocator_size     = ICMPV4_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = ICMPV4_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .init               = &entry
};

const static uint16_t CHECKSUM_ZERO = 0x0000;

icmpv4_header_t *
icmpv4_header_new(void)
{
    icmpv4_header_t *header = (icmpv4_header_t *) header_storage_new(&storage);

    LOG_PRINTLN(LOG_HEADER_IPV4, LOG_DEBUG, ("ICMPv4 header new 0x%016" PRIxPTR, (unsigned long) header));

    return header;
}

void
icmpv4_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);

    LOG_PRINTLN(LOG_HEADER_IPV4, LOG_DEBUG, ("ICMPv4 header free 0x%016" PRIxPTR, (unsigned long) header));

    header_storage_free(header);
}

/****************************************************************************
 * icmp_packet_encode
 *
 * @param  packet                   logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @return uint32_t                 number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
icmpv4_packet_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    icmpv4_header_t    *icmpv4;
    packet_len_t        len;

    if (packet->tail->klass->type != PACKET_TYPE_ICMPV4) {
        return 0;
    }

    icmpv4          = (icmpv4_header_t *) packet->tail;
    packet->tail    = icmpv4->header.next;

    switch (icmpv4->type) {
        case ICMPV4_TYPE_ECHO_REQUEST:
        case ICMPV4_TYPE_ECHO_REPLY:    uint16_to_uint8(&(raw_packet->data[offset + ICMPV4_HEADER_OFFSET_ECHO_ID]),     &(icmpv4->echo.id));
                                        uint16_to_uint8(&(raw_packet->data[offset + ICMPV4_HEADER_OFFSET_ECHO_SEQNO]),  &(icmpv4->echo.seqno));
                                        memcpy(         &(raw_packet->data[offset + ICMPV4_HEADER_OFFSET_ECHO_DATA]),     icmpv4->echo.data, icmpv4->echo.len);
                                        break;

        default:                        LOG_PRINTLN(LOG_HEADER_ICMPV4, LOG_ERROR, ("encode ICMP packet: can't encode unknown type-field TYPE = 0x%02" PRIx8, icmpv4->type)); return 0;
    }

                      raw_packet->data[offset + ICMPV4_HEADER_OFFSET_TYPE]          = icmpv4->type;
                      raw_packet->data[offset + ICMPV4_HEADER_OFFSET_CODE]          = icmpv4->code;
    uint16_to_uint8(&(raw_packet->data[offset + ICMPV4_HEADER_OFFSET_CHECKSUM]),    &CHECKSUM_ZERO);

    /* calculate checksum over ICMP header + payload */
    icmpv4->checksum = raw_packet_calc_checksum((uint16_t *) &(raw_packet->data[offset]), (ICMPV4_HEADER_ECHO_MIN_LEN + icmpv4->echo.len));
    uint16_to_uint8(&(raw_packet->data[offset + ICMPV4_HEADER_OFFSET_CHECKSUM]),    &(icmpv4->checksum));

    return (ICMPV4_HEADER_ECHO_MIN_LEN + icmpv4->echo.len);
}

/****************************************************************************
 * icmp_packet_decode
 *
 * @param  packet                   logical packet to be written
 * @param  raw_packet               raw packet to be read
 ***************************************************************************/
header_t *
icmpv4_packet_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    icmpv4_header_t  *icmpv4 = icmpv4_header_new();

    if (raw_packet->len < (offset + ICMPV4_HEADER_MIN_LEN)) {
        LOG_PRINTLN(LOG_HEADER_ICMPV4, LOG_ERROR, ("decode ICMP packet: length too small (present=%" PRIx16 ", required=%" PRIx16 ")", raw_packet->len, offset + ICMPV4_HEADER_MIN_LEN));
        ICMPV4_FAILURE_EXIT;
    }

    icmpv4->type = raw_packet->data[offset + ICMPV4_HEADER_OFFSET_TYPE];

    switch (icmpv4->type) {
        case ICMPV4_TYPE_ECHO_REQUEST:
        case ICMPV4_TYPE_ECHO_REPLY:    if (raw_packet->len < (offset + ICMPV4_HEADER_ECHO_MIN_LEN)) {
                                            LOG_PRINTLN(LOG_HEADER_ICMPV4, LOG_ERROR, ("decode ICMP echo packet: length too small (present=%" PRIx16 ", required=%" PRIx16 ")", raw_packet->len, offset + ICMPV4_HEADER_ECHO_MIN_LEN));
                                            ICMPV4_FAILURE_EXIT;
                                        }
                                        icmpv4->echo.len = raw_packet->len - (offset + ICMPV4_HEADER_ECHO_MIN_LEN);
                                        uint8_to_uint16(&(icmpv4->echo.id),    &(raw_packet->data[offset + ICMPV4_HEADER_OFFSET_ECHO_ID]));
                                        uint8_to_uint16(&(icmpv4->echo.seqno), &(raw_packet->data[offset + ICMPV4_HEADER_OFFSET_ECHO_SEQNO]));
                                        memcpy(           icmpv4->echo.data,   &(raw_packet->data[offset + ICMPV4_HEADER_OFFSET_ECHO_DATA]), icmpv4->echo.len);
                                        break;

        default:                        LOG_PRINTLN(LOG_HEADER_ICMPV4, LOG_ERROR, ("decode ICMP packet: can't decode unknown type-field TYPE = 0x%02" PRIx8, icmpv4->type));
                                        ICMPV4_FAILURE_EXIT;
    }

                      icmpv4->code         = raw_packet->data[offset + ICMPV4_HEADER_OFFSET_CODE];
    uint8_to_uint16(&(icmpv4->checksum),   &(raw_packet->data[offset + ICMPV4_HEADER_OFFSET_CHECKSUM]));

    return (header_t *) icmpv4;
}

