
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <pcap.h>

#include "log.h"
#include "log_network.h"

#include "packet/raw_packet.h"
#include "packet/packet.h"
#include "packet/port.h"

#define LINE_LEN 16

ptp2_clock_identity_t   create_clock_identity(const mac_address_t *mac);
packet_t               *create_ptp2_signaling_req(mac_address_t *slave_mac, ipv4_address_t *slave_ipv4);

ptp2_clock_identity_t
create_clock_identity(const mac_address_t *mac)
{
    ptp2_clock_identity_t clock_identity = { .raw = { mac->addr[0], mac->addr[1], mac->addr[2], 0xff, 0xfe, mac->addr[3], mac->addr[4], mac->addr[5]} };
    return clock_identity;
}

packet_t *
create_ptp2_signaling_req(mac_address_t *slave_mac, ipv4_address_t *slave_ipv4)
{
    packet_t                       *packet                  = packet_new();
    ethernet_header_t              *ether                   = ethernet_header_new();
    ipv4_header_t                  *ipv4                    = ipv4_header_new();
    udpv4_header_t                 *udpv4                   = udpv4_header_new();
    ptp2_header_t                  *ptp2                    = ptp2_header_new();
    ptp2_signaling_header_t        *ptp2_signaling          = ptp2_signaling_header_new();
    ptp2_signaling_tlv_header_t    *ptp2_signaling_tlv      = ptp2_signaling_tlv_header_new();

    //mac_address_t                   master_mac              = { .addr = { 0x00, 0x01, 0x20, 0x02, 0x00, 0x06 } };
    //ipv4_address_t                  master_ipv4             = { .addr = {   10,   16,  4,    5 } };
    //mac_address_t                   master_mac              = { .addr = { 0x00, 0x01, 0x20, 0x03, 0x57, 0xbd } };
    mac_address_t                   master_mac              = { .addr = { 0x00, 0x01, 0x20, 0x03, 0x00, 0x44 } };
    ipv4_address_t                  master_ipv4             = { .addr = { 192, 168, 4, 20 } };

    packet->head                                            = (header_t *) ether;
    ether->header.next                                      = (header_t *) ipv4;
    ipv4->header.next                                       = (header_t *) udpv4;
    udpv4->header.next                                      = (header_t *) ptp2;
    ptp2->header.next                                       = (header_t *) ptp2_signaling;
    ptp2_signaling->header.next                             = (header_t *) ptp2_signaling_tlv;

    /* Ethernet */
    ether->dest                                             = master_mac;
    ether->src                                              = *slave_mac;
    ether->type                                             = ETHERTYPE_IPV4;

    /* IPv4 */
    ipv4->version                                           = IPV4_HEADER_VERSION;
    ipv4->ihl                                               = IPV4_HEADER_IHL;
    ipv4->ecn                                               = 0;
    ipv4->dscp                                              = 0;
    ipv4->fragment_offset                                   = 0;
    ipv4->more_fragments                                    = 0;
    ipv4->dont_fragment                                     = 0;
    ipv4->reserved                                          = 0;
    ipv4->ttl                                               = 128;
    ipv4->protocol                                          = IPV4_PROTOCOL_UDP;
    ipv4->src                                               = *slave_ipv4;
    ipv4->dest                                              = master_ipv4;

    /* UDPv4 */
    udpv4->src_port                                         = PORT_PTP2_GENERAL;
    udpv4->dest_port                                        = PORT_PTP2_GENERAL;

    /* PTPv2 */
    ptp2->transport                                         = 0;
    ptp2->msg_type                                          = PTP2_MESSAGE_TYPE_SIGNALING;
    ptp2->version                                           = 2;
    ptp2->msg_len                                           = PTP2_HEADER_LEN + PTP2_SIGNALING_HEADER_TARGET_PORT_IDENT_LEN + PTP2_SIGNALING_TLV_MIN_LEN + PTP2_SIGNALING_TLV_REQUEST_UNICAST_LEN;
    ptp2->domain_number                                     = 4;
    ptp2->flags                                             = PTP2_FLAG_UNICAST;
    ptp2->correction                                        = PTP2_CORRECTION_NULL;
    ptp2->src_port_identity.clock_identity                  = create_clock_identity(slave_mac);
    ptp2->src_port_identity.port_number                     = 1;
    ptp2->seq_id                                            = 1;
    ptp2->control                                           = PTP2_CONTROL_OTHERS;
    ptp2->log_msg_interval                                  = 0x7f; /* unicast */

    /* PTPv2 signaling */
    ptp2_signaling->target_port_identity.clock_identity     = PTP2_CLOCK_IDENTITY_ALL;
    ptp2_signaling->target_port_identity.port_number        = 0xffff;

    /* PTPv2 signaling TLV */
    ptp2_signaling_tlv->request_unicast.type                = PTP2_SIGNALING_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION;
    ptp2_signaling_tlv->request_unicast.len                 = PTP2_SIGNALING_TLV_REQUEST_UNICAST_LEN;
    ptp2_signaling_tlv->request_unicast.msg.type            = PTP2_MESSAGE_TYPE_ANNOUNCE;
    ptp2_signaling_tlv->request_unicast.msg.unused          = 0;
    ptp2_signaling_tlv->request_unicast.log_period          = 0;
    ptp2_signaling_tlv->request_unicast.duration            = 3600;

    return packet;
}

int
main(int argc, char *argv[])
{
    netif_t                         netif;
    raw_packet_t                    raw_packet;
    packet_t                       *packet;
    header_t                       *header;
    ethernet_header_t              *ether;
    ipv4_header_t                  *ipv4;
    ptp2_header_t                  *ptp2;
    ptp2_signaling_tlv_header_t    *ptp2_signaling_tlv;
    uint64_t                        mac48;

    mac_address_t                   slave_mac   = { .addr = { 0x00, 0x80, 0xea, 0x39, 0x00, 0x1 } };
    ipv4_address_t                  slave_ipv4  = { .addr = {  192, 168, 5, 1} };
    //mac_address_t                   slave_mac   = { .addr = { 0x00, 0x80, 0xea, 0x4d, 0xc6, 0x51 } };
    //ipv4_address_t                  slave_ipv4  = { .addr = { 10, 4, 62, 122 } };

    if (argc != 2) {
        printf("usage: %s ifname\n", argv[0]);
        return -1;
    }

    if (!netif_init(&netif, argv[1])) {
        return false;
    }

    raw_packet_init(&raw_packet);
    packet = create_ptp2_signaling_req( &slave_mac, &slave_ipv4);

    header = packet->head;

    while (header->klass->type != HEADER_TYPE_ETHERNET) {
        header = header->next;
    }
    ether = (ethernet_header_t *) header;

    while (header->klass->type != HEADER_TYPE_IPV4) {
        header = header->next;
    }
    ipv4 = (ipv4_header_t *) header;

    while (header->klass->type != HEADER_TYPE_PTP2) {
        header = header->next;
    }
    ptp2 = (ptp2_header_t *) header;

    while (header->klass->type != HEADER_TYPE_PTP2_SIGNALING_TLV) {
        header = header->next;
    }
    ptp2_signaling_tlv = (ptp2_signaling_tlv_header_t *) header;

    for (int i = 0; i < 1024; i++) {
        bzero(&raw_packet, sizeof(raw_packet));

        for (int k = 0; k < 3; k++) {

            switch (k) {
                case 0:     ptp2_signaling_tlv->request_unicast.msg.type = PTP2_MESSAGE_TYPE_SYNC;
                            break;

                case 1:     ptp2_signaling_tlv->request_unicast.msg.type = PTP2_MESSAGE_TYPE_ANNOUNCE;
                            break;

                case 2:     ptp2_signaling_tlv->request_unicast.msg.type = PTP2_MESSAGE_TYPE_DELAY_RESP;
                            break;

                default:    printf("=== NOOOOO ======================================="); break;
            }

            /* encode */
            if (packet_encode(&netif, packet, &raw_packet)) {
                LOG_PRINTLN(LOG_PCAP, LOG_INFO, ("Successfully encoded packet"));
            } else {
                LOG_PRINTLN(LOG_PCAP, LOG_ERROR, ("Error encoding packet"));
            }

            LOG_RAW_PACKET(LOG_PCAP, LOG_DEBUG, &raw_packet, ("TX"));

            /* send */
            netif_frame_send(&netif, &raw_packet);

            usleep(150);
        }

        /* modify MAC address */
        uint8_to_uint48(&mac48, ether->src.addr);
        mac48 = mac48 + 1;
        uint48_to_uint8(ether->src.addr, &mac48);

        /* modify IPv4 address */
        ipv4->src.addr32 = htonl(ntohl(ipv4->src.addr32) + 1);

        /* modify source port identity */
        ptp2->src_port_identity.clock_identity = create_clock_identity(&(ether->src));
    }

    object_release(packet);

    return 0;
}
