
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

ptp2_clock_identity_t   create_clock_identity(mac_address_t *mac);
bool                    send_delayed_ptp2_delay_req(netif_t *netif, mac_address_t *slave_mac, ipv4_address_t *slave_ipv4);

ptp2_clock_identity_t
create_clock_identity(mac_address_t *mac)
{
    ptp2_clock_identity_t clock_identity = { .raw = { mac->addr[0], mac->addr[1], mac->addr[2], 0xff, 0xfe, mac->addr[3], mac->addr[4], mac->addr[5]} };
    return clock_identity;
}

bool
send_delayed_ptp2_delay_req(netif_t *netif, mac_address_t *slave_mac, ipv4_address_t *slave_ipv4)
{
    raw_packet_t                raw_packet;
    packet_t                   *packet          = packet_new();
    ethernet_header_t          *ether           = ethernet_header_new();
    ipv4_header_t              *ipv4            = ipv4_header_new();
    udpv4_header_t             *udpv4           = udpv4_header_new();
    ptp2_header_t              *ptp2            = ptp2_header_new();
    ptp2_delay_req_header_t    *ptp2_delay_req  = ptp2_delay_req_header_new();

    packet->head        = (header_t *) ether;
    ether->header.next  = (header_t *) ipv4;
    ipv4->header.next   = (header_t *) udpv4;
    udpv4->header.next  = (header_t *) ptp2;
    ptp2->header.next   = (header_t *) ptp2_delay_req;

    /* Ethernet */
    ether->dest             = netif->mac;
    ether->src              = *slave_mac;
    ether->type             = ETHERTYPE_IPV4;

    /* IPv4 */
    ipv4->version           = IPV4_HEADER_VERSION;
    ipv4->ihl               = IPV4_HEADER_IHL;
    ipv4->ecn               = 0;
    ipv4->dscp              = 0;
    ipv4->fragment_offset   = 0;
    ipv4->more_fragments    = 0;
    ipv4->dont_fragment     = 0;
    ipv4->reserved          = 0;
    ipv4->ttl               = 128;
    ipv4->protocol          = IPV4_PROTOCOL_UDP;
    ipv4->src               = *slave_ipv4;
    ipv4->dest              = netif->ipv4->address;

    /* UDPv4 */
    udpv4->src_port         = PORT_PTP2_GENERAL;
    udpv4->dest_port        = PORT_PTP2_GENERAL;

    /* PTPv2 */
    ptp2->transport                             = 0;
    ptp2->msg_type                              = PTP2_MESSAGE_TYPE_DELAY_REQ;
    ptp2->version                               = 2;
    ptp2->msg_len                               = PTP2_HEADER_LEN + PTP2_DELAY_REQ_HEADER_LEN;
    ptp2->domain_number                         = 4;
    ptp2->flags                                 = PTP2_FLAG_UNICAST;
    ptp2->correction                            = PTP2_CORRECTION_NULL;
    ptp2->src_port_identity.clock_identity      = create_clock_identity(slave_mac);
    ptp2->src_port_identity.port_number         = 1;
    ptp2->seq_id                                = 1;
    ptp2->control                               = PTP2_CONTROL_DELAY_REQ;
    ptp2->log_msg_interval                      = 0x7f; /* unicast */

    /* PTPv2 delay req */
    ptp2_delay_req->origin_timestamp.seconds        = 123;
    ptp2_delay_req->origin_timestamp.nanoseconds    = 456;

    /* encode */
    if (packet_encode(netif, packet, &raw_packet)) {
        LOG_PRINTLN(LOG_PCAP, LOG_INFO, ("Successfully encoded packet"));
    } else {
        LOG_PRINTLN(LOG_PCAP, LOG_ERROR, ("Error encoding packet"));
    }

    /* send */
    netif_frame_send(netif, &raw_packet);

    return true;
}

int
main(int argc, char *argv[])
{
    netif_t                         netif;
    pcap_t                         *pcap;
    char                            errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr             *pcap_header;
    const u_char                   *pkt_data;
//    u_int                   i = 0;
    int                             res;
    raw_packet_t                    raw_packet;
    packet_t                       *packet_sent;
    header_t                       *header;
    ethernet_header_t              *ether;
    ipv4_header_t                  *ipv4;

    mac_address_t                  *slave_mac;
    ipv4_address_t                 *slave_ipv4;

    if (argc != 3) {
        printf("usage: %s ifname filename\n", argv[0]);
        return -1;
    }

    /* Open a capture file */
    if ((pcap = pcap_open_offline(argv[2], errbuf)) == NULL) {
        LOG_PRINTLN(LOG_PCAP, LOG_ERROR, ("Error opening dump file: %s", errbuf));
        return -1;
    }

    if (!netif_init(&netif, argv[1])) {
        return false;
    }

    raw_packet_init(&raw_packet);

    /* Retrieve the packets from the file */
    while ((res = pcap_next_ex(pcap, &pcap_header, &pkt_data)) >= 0) {

        memcpy(raw_packet.data, pkt_data, pcap_header->caplen);
        raw_packet.len = pcap_header->caplen;

        LOG_RAW_PACKET(LOG_PCAP, LOG_INFO, &raw_packet, ("RX"));

        packet_sent = packet_decode(&netif, &raw_packet);
        log_packet(packet_sent);

        header = packet_sent->head;

        while (header->klass->type != PACKET_TYPE_ETHERNET) {
            header = header->next;
        }
        ether = (ethernet_header_t *) header;
        ether->dest.addr[5] = 0x06;

        for (int i = 0; i < 3; i++) {
            bzero(&raw_packet, sizeof(raw_packet));

            /* get MAC and IPv4 address */
            header = packet_sent->head;

            while (header->klass->type != PACKET_TYPE_ETHERNET) {
                header = header->next;
            }
            ether = (ethernet_header_t *) header;
            slave_mac = &(ether->src);

            while (header->klass->type != PACKET_TYPE_IPV4) {
                header = header->next;
            }
            ipv4 = (ipv4_header_t *) header;
            slave_ipv4 = &(ipv4->src);

            /* send a delayed delay_req */
            send_delayed_ptp2_delay_req(&netif, slave_mac, slave_ipv4);

            /* modify MAC and IPv4 address */
            uint64_t num;
            uint8_to_uint48(&num, ether->src.addr);
            num = num + 1;
            uint48_to_uint8(ether->src.addr, &num);

            ipv4->src.addr32 = htonl(ntohl(ipv4->src.addr32) + 1);
        }

        object_release(packet_sent);
    }


    if (res == -1) {
        printf("Error reading the packets: %s\n", pcap_geterr(pcap));
    }

    return 0;
}
