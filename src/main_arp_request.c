#include "config.h"
#include "config_file.h"
#include "log.h"
#include "log_network.h"

#include "packet/raw_packet.h"
#include "packet/packet.h"
#include "packet/port.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <linux/limits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define OPT_REQUIRED     (void *) 1
#define OPT_UNRECOGNISED (void *) 2

void usage(int argc, char *argv[], const char *msg);
bool do_simulation(config_t *config);
packet_t *create_arp_request(netif_t *netif, uint16_t vid, mac_address_t *peer_mac, ipv4_address_t *peer_ipv4);

const char arp_request_with_suffix[] = {
    0x00, 0x01, 0x20, 0x03, 0x62, 0xd0, 0x00, 0x80, 0x16, 0x92, 0x14, 0x5d, 0x81, 0x00, 0xa3, 0xee,
    0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x80, 0x16, 0x92, 0x14, 0x5d,
    0x0a, 0xd9, 0x00, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xd9, 0x00, 0xc3, 0x06, 0x00,
    0x28, 0x00, 0x20, 0x00, 0x1d, 0x00, 0x01, 0x00, 0x00, 0x70, 0x04, 0xdd, 0x01, 0x00, 0x04, 0xdd,
    0xa7, 0xbc, 0x0e, 0x05
};

packet_t *
create_arp_request(netif_t *netif, uint16_t vid, mac_address_t *peer_mac, ipv4_address_t *peer_ipv4)
{
    packet_t                       *packet                  = packet_new();
    ethernet_header_t              *ether                   = ethernet_header_new();
    arp_header_t                   *arp                     = arp_header_new();
    
    /* Ethernet */
    packet->head                                            = (header_t *) ether;
    ether->dest                                             = *peer_mac;
    ether->src                                              = netif->mac;
    ether->type                                             = ETHERTYPE_VLAN;
    
    /* VLAN */
    ether->vlan.vid                                         = vid;
    ether->vlan.dei                                         = 0;
    ether->vlan.pcp                                         = 5;
    ether->vlan.type                                        = ETHERTYPE_ARP;
    
    /* ARP */
    ether->header.next                                      = (header_t *) arp;
    arp->htype                                              = ARP_HTYPE_ETHERNET;   /* Hardware type (HTYPE)            */
    arp->ptype                                              = ARP_PTYPE_IPV4;       /* Protocol type (PTYPE)            */
    arp->hlen                                               = ARP_HLEN_ETHERNET;    /* Hardware address length (HLEN)   */
    arp->plen                                               = ARP_PLEN_IPV4;        /* Protocol address length (PLEN)   */
    arp->oper                                               = ARP_OPER_REQUEST;     /* Operation (OPER)                 */
    arp->sha                                                = netif->mac;           /* Sender hardware address (SHA)    */
    arp->spa                                                = netif->ipv4->address; /* Sender protocol address (SPA)    */
    arp->tha                                                = MAC_ADDRESS_NULL;     /* Target hardware address (THA)    */
    arp->tpa                                                = *peer_ipv4;           /* Target protocol address (TPA)    */
    
    return packet;
}

bool
do_simulation(config_t *config)
{
    netif_t                         netif;
    raw_packet_t                    raw_packet;
    packet_t                       *packet;
    uint32_t                        i;
    //uint32_t                        k;
    
    if (config->netif_size < 1 || config->netif[0].vlan_size < 1 || 
        !config->netif[0].vlan[0].ntp_configured || config->netif[0].vlan[0].ntp.client_size < 1) {
        LOG_PRINTLN(LOG_SIM, LOG_ERROR, ("No ARP config in configuration file! Abort"));
        return false;
    }
    
    if (!netif_init(&netif, config->netif[0].name)) {
        return false;
    }
    
    raw_packet_init(&raw_packet);
    
    LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Create ARP request"));
    packet = create_arp_request(&netif,
                                config->netif[0].vlan[0].vid,
                                &(config->netif[0].vlan[0].ntp.client[0].mac_address),
                                &(config->netif[0].vlan[0].ntp.client[0].ipv4_address));
    
    LOG_PACKET(LOG_SIM, LOG_INFO, packet, ("TX packet"));
    
    /* encode */
    LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Encode packet"));
    if (packet_encode(&netif, packet, &raw_packet)) {
        LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Successfully encoded packet"));
    } else {
        LOG_PRINTLN(LOG_SIM, LOG_ERROR, ("Error encoding packet"));
        object_release(packet);
        return false;
    }
    for (i = 0; i < 0xff; i++) {
        raw_packet.data[raw_packet.len] = i;
        raw_packet.len++;
        LOG_RAW_PACKET(LOG_SIM, LOG_INFO, &raw_packet, ("TX raw"));
        
        /* send */
        netif_frame_send(&netif, &raw_packet);
        usleep(50000);
    }
    object_release(packet);
    
    return true;
}

/****************************************************************************
 * main
 *
 * @param argc argument count
 * @param argv argument list
 * @return int return code
 ***************************************************************************/
int
main(int argc, char *argv[])
{
    config_t    config;
    char        config_file[NAME_MAX+1];
    bool        fflag = false;  /* option: config-file */
    
    int         opt;            /* argument for getopt() as a single integer */
    
    /* program without arguments */
    if (argc == 1) {
        usage(argc, argv, NULL);
    }
    
    
    /* first character ':' of getopt()'s optstring sets opterr=0 and
       returns ':' to indicate a missing option argument
       or '?' to indicate a unrecognised option */
    while ((opt = getopt(argc, argv, ":l:df:")) != -1) {
        switch (opt) {
                
            /* option: config-file */
            case 'f':
                strcpy(config_file, optarg);
                fflag = true;
                break;
                
            /* missing option argument */
            case ':':
                usage(argc, argv, OPT_REQUIRED);
                break;
                
            /* unrecognised option */
            case '?':
                usage(argc, argv, OPT_UNRECOGNISED);
                break;
                
            default:
                usage(argc, argv, NULL);
        }
    }
    
    log_init();
    
    /* option: config-file */
    if (!fflag) {
        strcpy(config_file, CONFIG_FILE_NAME);
    }
    
    LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Using config-file \"%s\"", config_file));
    if (!config_file_parse(config_file, &config)) {
        printf("Error in parsing the file!\n");
        exit(EXIT_FAILURE);
    }
    
    do_simulation(&config);
    fprintf(stderr, "Exit!\n");
    
    return 0;
}

void
usage(int argc, char *argv[], const char *msg)
{
   fprintf(stderr, "ARP Request\n");
   fprintf(stderr, "Usage: %s [-f <config-file>]\n", argv[0]);
   
   if (msg == OPT_REQUIRED) {
       fprintf(stderr, "\nOption -%c requires an operand\n", optopt);
   } else if (msg == OPT_UNRECOGNISED) {
       fprintf(stderr, "\nUnrecognised option: -%c\n", optopt);
   } else if (msg != NULL) {
       fprintf(stderr, "\n%s\n", msg);
   }
   
   exit(EXIT_FAILURE);
}
