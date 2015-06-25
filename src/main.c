
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#include "log.h"
#include "log_network.h"

#include "packet/raw_packet.h"
#include "packet/packet.h"

#define LINE_LEN 16

int
main(int argc, char *argv[])
{
    netif_t                 netif;
    pcap_t                 *pcap;
    char                    errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr     *pcap_header;
    const u_char           *pkt_data;
//    u_int                   i = 0;
    int                     res;
    raw_packet_t            raw_packet;
    packet_t               *packet;
    header_t               *header;
    ethernet_header_t      *ether;
    ipv4_header_t          *ipv4;

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

        packet = packet_decode(&netif, &raw_packet);
        log_packet(packet);

        header = packet->head;

        while (header->klass->type != PACKET_TYPE_ETHERNET) {
            header = header->next;
        }
        ether = (ethernet_header_t *) header;
        ether->dest.addr[5] = 0x06;

        for (int i = 0; i < 128; i++) {
            bzero(&raw_packet, sizeof(raw_packet));

            if (packet_encode(&netif, packet, &raw_packet)) {
                LOG_PRINTLN(LOG_PCAP, LOG_INFO, ("Successfully encoded packet"));
            } else {
                LOG_PRINTLN(LOG_PCAP, LOG_ERROR, ("Error encoding packet"));
            }

            LOG_RAW_PACKET(LOG_PCAP, LOG_INFO, &raw_packet, ("TX"));

            netif_frame_send(&netif, &raw_packet);

            header = packet->head;

            while (header->klass->type != PACKET_TYPE_ETHERNET) {
                header = header->next;
            }
            ether = (ethernet_header_t *) header;
            uint64_t num;
            uint8_to_uint48(&num, ether->src.addr);
            num = num + 1;
            uint48_to_uint8(ether->src.addr, &num);

            while (header->klass->type != PACKET_TYPE_IPV4) {
                header = header->next;
            }
            ipv4 = (ipv4_header_t *) header;
            ipv4->src.addr32 = htonl(ntohl(ipv4->src.addr32) + 1);
            sleep(1);
        }

        object_release(packet);
//        /* print pkt timestamp and pkt len */
//        printf("%" PRId64 ":%" PRId64 " (%" PRIu32 ")\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
//
//        /* Print the packet */
//        for (i = 1; (i < header->caplen + 1); i++) {
//            printf("%.2x ", pkt_data[i-1]);
//            if ((i % LINE_LEN) == 0) {
//                printf("\n");
//            }
//        }
//
//        printf("\n\n");
    }


    if (res == -1) {
        printf("Error reading the packets: %s\n", pcap_geterr(pcap));
    }

    return 0;
    return 0;
}
