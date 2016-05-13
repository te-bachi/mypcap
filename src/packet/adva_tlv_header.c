
#include "packet/packet.h"
#include "log.h"
#include "log_network.h"

#include <string.h>
#include <inttypes.h>

#define ADVA_TLV_STORAGE_INIT_SIZE      2
#define ADVA_TLV_FAILURE_EXIT           adva_tlv_header_free((header_t *) adva_tlv); \
                                        return NULL


static adva_tlv_header_t                adva_tlv[ADVA_TLV_STORAGE_INIT_SIZE];
static uint32_t                         idx[ADVA_TLV_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = HEADER_TYPE_ADVA_TLV,
    .size               = sizeof(adva_tlv_header_t),
    .free               = adva_tlv_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) adva_tlv,
    .allocator_size     = ADVA_TLV_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = ADVA_TLV_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .init               = &entry
};

adva_tlv_header_t *
adva_tlv_header_new(void)
{
    adva_tlv_header_t *header = (adva_tlv_header_t *) header_storage_new(&storage);

    LOG_PRINTLN(LOG_HEADER_NTP, LOG_DEBUG, ("NTP header new 0x%016" PRIxPTR, (uintptr_t) header));

    return header;
}

void
adva_tlv_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);

    LOG_PRINTLN(LOG_HEADER_NTP, LOG_DEBUG, ("NTP header free 0x%016" PRIxPTR, (uintptr_t) header));

    header_storage_free(header);
}

/****************************************************************************
 * adva_tlv_header_encode
 *
 * @param  this                     logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @param  offset              offset from origin to ptp packet
 * @return                          number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
adva_tlv_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    adva_tlv_header_t      *adva_tlv;

    if (packet->tail->klass->type != HEADER_TYPE_ADVA_TLV) {
        LOG_PRINTLN(LOG_HEADER_NTP, LOG_ERROR, ("%s header encode: next header is not a %s header but a %s header!",
                log_header_type(HEADER_TYPE_ADVA_TLV),
                log_header_type(HEADER_TYPE_ADVA_TLV),
                log_header_type(packet->tail->klass->type)));
        return 0;
    }

    adva_tlv        = (adva_tlv_header_t *) packet->tail;
    packet->tail    = adva_tlv->header.next;

    raw_packet->data[offset + ADVA_TLV_HEADER_OFFSET_TYPE]                              = adva_tlv->type;
    raw_packet->data[offset + ADVA_TLV_HEADER_OFFSET_LEN]                               = adva_tlv->len;
    raw_packet->data[offset + ADVA_TLV_HEADER_OFFSET_OPCODE_DOMAIN]                     = adva_tlv->opcode_domain;
    raw_packet->data[offset + ADVA_TLV_HEADER_OFFSET_FLOW_ID]                           = adva_tlv->flow_id;
    uint32_to_uint8(&(raw_packet->data[offset + ADVA_TLV_HEADER_OFFSET_TSG_II]),        &(adva_tlv->tsg_ii.raw));
    uint32_to_uint8(&(raw_packet->data[offset + ADVA_TLV_HEADER_OFFSET_TSG_I]),         &(adva_tlv->tsg_i.raw));

    return ADVA_TLV_HEADER_LEN;
}

/****************************************************************************
 * adva_tlv_header_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 * @param  offset              offset from origin to ptp packet
 ***************************************************************************/
header_t *
adva_tlv_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{

    return (header_t *) NULL;
}

