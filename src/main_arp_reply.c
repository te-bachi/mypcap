
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

mac_address_t           master_mac      = { .addr = { 0x00, 0x01, 0x20, 0x02, 0x00, 0x06 } };
ipv4_address_t          master_ipv4     = { { .addr = {   10,    4,   62,    101 } } };

packet_t               *create_ptp2_arp_reply(mac_address_t *arp_mac, ipv4_address_t *arp_ipv4);

packet_t *
create_ptp2_arp_reply(mac_address_t *arp_mac, ipv4_address_t *arp_ipv4)
{
    packet_t                       *packet                  = packet_new();
    ethernet_header_t              *ether                   = ethernet_header_new();
    arp_header_t                   *arp                     = arp_header_new();

    packet->head                                            = (header_t *) ether;
    ether->header.next                                      = (header_t *) arp;

    /* Ethernet */
    //ether->dest                                             = master_mac;
    //ether->src                                              = *slave_mac;
    ether->type                                             = ETHERTYPE_IPV4;

    /* ARP */
    

    return packet;
}

int
main(int argc, char *argv[])
{
    netif_t                         netif;
    raw_packet_t                    raw_packet;
    packet_t                       *packet;
    //header_t                       *header;
    mac_address_t                   mac = { .addr = { 0x00, 0x01, 0x20, 0x00, 0x00, 0x01 } };
    mac_address_t                   mac2;
    uint8_t                         mac_str[STR_MAC_ADDRESS_MAX_LEN];
    
    uint32_t                        num;
    uint8_t                         str[20] = "12345678";
    hexstr2num(&num, str, 8);
    printf("decimal = %" PRIu32 " hex = 0x%" PRIx32 "\n", num, num);
    
    
    if (mac_address_convert_to_string(&mac, mac_str)) {
        printf("tostring: true: %s\n", mac_str);
    } else {
        printf("tostring: false\n");
    }

    if (mac_address_convert_from_string(&mac2, mac_str)) {
        printf("fromstring: true: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
                mac2.addr[0], mac2.addr[1], mac2.addr[2],
                mac2.addr[3], mac2.addr[4], mac2.addr[5]);
    } else {
        printf("fromstring: false\n");
    }
    
    return 0;
    
    if (argc != 3) {
        printf("usage: %s ifname ip-address mac-address\n", argv[0]);
        return -1;
    }

    if (!netif_init(&netif, argv[1])) {
        return false;
    }

    raw_packet_init(&raw_packet);
    //packet = create_ptp2_signaling_req( &slave_mac, &slave_ipv4);


    object_release(packet);

    return 0;
}
