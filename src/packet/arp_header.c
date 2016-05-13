
#include "packet/packet.h"
#include "log.h"
#include "log_network.h"

#include <string.h>
#include <inttypes.h>

#define ARP_STORAGE_INIT_SIZE       2
#define ARP_FAILURE_EXIT            arp_header_free((header_t *) arp); \
                                    return NULL


static arp_header_t             arp[ARP_STORAGE_INIT_SIZE];
static uint32_t                 idx[ARP_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = HEADER_TYPE_ARP,
    .size               = sizeof(arp_header_t),
    .free               = arp_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) arp,
    .allocator_size     = ARP_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = ARP_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .init               = &entry
};

arp_header_t *
arp_header_new(void)
{
    arp_header_t *header = (arp_header_t *) header_storage_new(&storage);

    LOG_PRINTLN(LOG_HEADER_ARP, LOG_DEBUG, ("ARP header new 0x%016" PRIxPTR, (uintptr_t) header));

    return header;
}

void
arp_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);

    LOG_PRINTLN(LOG_HEADER_ARP, LOG_DEBUG, ("ARP header free 0x%016" PRIxPTR, (uintptr_t) header));

    header_storage_free(header);
}

/****************************************************************************
 * arp_header_encode
 *
 * @param  packet                   logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @return uint32_t                 number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
arp_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    arp_header_t       *arp;

    if (packet->tail->klass->type != HEADER_TYPE_ARP) {
        LOG_PRINTLN(LOG_HEADER_ARP, LOG_ERROR, ("%s header encode: next header is not a %s header but a %s header!",
                log_header_type(HEADER_TYPE_ARP),
                log_header_type(HEADER_TYPE_ARP),
                log_header_type(packet->tail->klass->type)));
        return 0;
    }
    arp             = (arp_header_t *) packet->tail;
    packet->tail    = arp->header.next;

    switch (arp->oper) {
        case ARP_OPER_REQUEST:
        case ARP_OPER_RESPONSE:         break;

        default:                        LOG_PRINTLN(LOG_HEADER_ARP, LOG_ERROR, ("encode ARP packet: can't encode unknown operation-field OPER = 0x%04" PRIx16, arp->oper));
                                        return 0;
    }

    uint16_to_uint8(&(raw_packet->data[offset + ARP_HEADER_OFFSET_HTYPE]), &(arp->htype));                          /**< Hardware type (HTYPE) */
    uint16_to_uint8(&(raw_packet->data[offset + ARP_HEADER_OFFSET_PTYPE]), &(arp->ptype));                          /**< Protocol type (PTYPE) */
                      raw_packet->data[offset + ARP_HEADER_OFFSET_HLEN]    = arp->hlen;                             /**< Hardware address length (HLEN) */
                      raw_packet->data[offset + ARP_HEADER_OFFSET_PLEN]    = arp->plen;                             /**< Protocol address length (PLEN) */
    uint16_to_uint8(&(raw_packet->data[offset + ARP_HEADER_OFFSET_OPER]),  &(arp->oper));                           /**< Operation (OPER) */
    memcpy(         &(raw_packet->data[offset + ARP_HEADER_OFFSET_SHA]),   arp->sha.addr, sizeof(arp->sha.addr));   /**< Sender hardware address (SHA) */
    memcpy(         &(raw_packet->data[offset + ARP_HEADER_OFFSET_SPA]),   arp->spa.addr, sizeof(arp->spa.addr));   /**< Sender protocol address (SPA) */
    memcpy(         &(raw_packet->data[offset + ARP_HEADER_OFFSET_THA]),   arp->tha.addr, sizeof(arp->tha.addr));   /**< Target hardware address (THA) */
    memcpy(         &(raw_packet->data[offset + ARP_HEADER_OFFSET_TPA]),   arp->tpa.addr, sizeof(arp->tpa.addr));   /**< Target protocol address (TPA) */

    return ARP_HEADER_LEN;
}

/****************************************************************************
 * arp_header_decode
 *
 * @param  packet                   logical packet to be written
 * @param  raw_packet               raw packet to be read
 ***************************************************************************/
header_t *
arp_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    arp_header_t *arp = arp_header_new();

    if (raw_packet->len < (offset + ARP_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_ARP, LOG_ERROR, ("decode ARP packet: length too small (present=%" PRIx16 ", required=%" PRIx16 ")", raw_packet->len, offset + ARP_HEADER_LEN));
        ARP_FAILURE_EXIT;
    }

    uint8_to_uint16(&(arp->oper),  &(raw_packet->data[offset + ARP_HEADER_OFFSET_OPER]));                            /**< Operation (OPER) */

    switch (arp->oper) {
        case ARP_OPER_REQUEST:
        case ARP_OPER_RESPONSE:         break;

        default:                        LOG_PRINTLN(LOG_HEADER_ARP, LOG_ERROR, ("decode ARP packet: can't decode unknown operation-field OPER = 0x%04" PRIx16, arp->oper));
                                        ARP_FAILURE_EXIT;
    }

    uint8_to_uint16(&(arp->htype), &(raw_packet->data[offset + ARP_HEADER_OFFSET_HTYPE]));                          /**< Hardware type (HTYPE) */
    uint8_to_uint16(&(arp->ptype), &(raw_packet->data[offset + ARP_HEADER_OFFSET_PTYPE]));                          /**< Protocol type (PTYPE) */
                    arp->hlen      = raw_packet->data[offset + ARP_HEADER_OFFSET_HLEN];                             /**< Hardware address length (HLEN) */
                    arp->plen      = raw_packet->data[offset + ARP_HEADER_OFFSET_PLEN];                             /**< Protocol address length (PLEN) */
    memcpy(         arp->sha.addr, &(raw_packet->data[offset + ARP_HEADER_OFFSET_SHA]), sizeof(arp->sha.addr));     /**< Sender hardware address (SHA) */
    memcpy(         arp->spa.addr, &(raw_packet->data[offset + ARP_HEADER_OFFSET_SPA]), sizeof(arp->spa.addr));     /**< Sender protocol address (SPA) */
    memcpy(         arp->tha.addr, &(raw_packet->data[offset + ARP_HEADER_OFFSET_THA]), sizeof(arp->tha.addr));     /**< Target hardware address (THA) */
    memcpy(         arp->tpa.addr, &(raw_packet->data[offset + ARP_HEADER_OFFSET_TPA]), sizeof(arp->tpa.addr));     /**< Target protocol address (TPA) */

    return (header_t *) arp;
}

