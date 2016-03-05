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


packet_t *create_ntp_req(config_ntp_peer_t *server, config_ntp_peer_t *client);

packet_t *
create_ntp_req(config_ntp_peer_t *server, config_ntp_peer_t *client)
{
    packet_t                       *packet                  = packet_new();
    ethernet_header_t              *ether                   = ethernet_header_new();
    ipv4_header_t                  *ipv4                    = ipv4_header_new();
    udpv4_header_t                 *udpv4                   = udpv4_header_new();
    ntp_header_t                   *ntp                     = ntp_header_new();
    adva_tlv_header_t              *adva_tlv                = adva_tlv_header_new();

    packet->head                                            = (header_t *) ether;
    ether->header.next                                      = (header_t *) ipv4;
    ipv4->header.next                                       = (header_t *) udpv4;
    udpv4->header.next                                      = (header_t *) ntp;
    ntp->header.next                                        = (header_t *) adva_tlv;

    /* Ethernet */
    ether->dest                                             = server->mac_address;
    ether->src                                              = client->mac_address;
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
    ipv4->src                                               = client->ipv4_address;
    ipv4->dest                                              = server->ipv4_address;

    /* UDPv4 */
    udpv4->src_port                                         = PORT_NTP;
    udpv4->dest_port                                        = PORT_NTP;

    /* NTP */
    ntp->leap_indicator                                     = NTP_LEAP_INDICATOR_NO_WARNING;
    ntp->version                                            = NTP_VERSION_4;
    ntp->mode                                               = NTP_MODE_CLIENT;
    ntp->stratum                                            = 2;
    ntp->polling_interval                                   = 6;
    ntp->clock_precision                                    = -22;
    ntp->root_delay                                         = 0;
    ntp->root_dispersion                                    = 0;
    ntp->reference_id[0]                                    = 'G';
    ntp->reference_id[1]                                    = 'P';
    ntp->reference_id[2]                                    = 'S';
    ntp->reference_id[3]                                    = '\0';
    ntp->reference_timestamp.seconds                        = 123;
    ntp->reference_timestamp.nanoseconds                    = 456;
    ntp->origin_timestamp.seconds                           = 123;
    ntp->origin_timestamp.nanoseconds                       = 456;
    ntp->receive_timestamp.seconds                          = 123;
    ntp->receive_timestamp.nanoseconds                      = 456;
    ntp->transmit_timestamp.seconds                         = 123;
    ntp->transmit_timestamp.nanoseconds                     = 456;

    adva_tlv->type                                          = ADVA_TLV_TYPE_NTP;
    adva_tlv->len                                           = ADVA_TLV_HEADER_LEN;
    adva_tlv->opcode                                        = ADVA_TLV_OPCODE_FORWARD_TO_NP;
    adva_tlv->domain                                        = 0;
    adva_tlv->flow_id                                       = 0;
    adva_tlv->tsg_ii.raw                                    = 0x11223344;
    adva_tlv->tsg_i.raw                                     = 0xaabbccdd;

    return packet;
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
//    bool        dflag = false;  /* option: daemonize */
//    bool        lflag = false;  /* option: log level */
    bool        fflag = false;  /* option: config-file */
    //log_level_t level  = 0;
    
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
                
//            /* option: log level */
//            case 'l':
//                if (strlen(optarg) != 1 || !isdigit(optarg[0])) {
//                    usage(argc, argv, "Log-Level should be a number");
//                }
//
//                level = atoi(optarg);
//
//                if (level < LOG_NONE_PRIVATE || level > LOG_DEBUG_PRIVATE) {
//                    usage(argc, argv, "Log-Level should be between 0 (None) and 5 (Debug)");
//                }
//
//                lflag = true;
//
//                break;
                
//            /* option: daemonize */
//            case 'd':
//                dflag = true;
//                break;
                
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
    
//    /* option: log level */
//    if (!lflag) {
//        level = LOG_WARN_PRIVATE;
//    }
    
    log_init();
    
//    /* option: interface */
//    if (!iflag) {
//        usage(argc, argv, "No interface specified");
//    }
    
    /* option: config-file */
    if (!fflag) {
        strcpy(config_file, CONFIG_FILE_NAME);
    }
    
//    /* option: daemonize */
//    if (dflag) {
//        if (!Daemon_daemonize()) {
//            Daemon_removePid();
//            exit(EXIT_FAILURE);
//        }
//    }
    
    
    LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Using config-file \"%s\"", config_file));
    if (!config_file_parse(config_file, &config)) {
        printf("Error in parsing the file!\n");
        exit(EXIT_FAILURE);
    }
    
    {
        netif_t                         netif;
        raw_packet_t                    raw_packet;

        if (!netif_init(&netif, config.netif[0].name)) {
            return false;
        }

        raw_packet_init(&raw_packet);

        for (int i = 0; i < config.netif_size; i++) {
            printf("netif '%s'\n", config.netif[i].name);
            for (int j = 0; j < config.netif[i].vlan_size; j++) {
                printf("    vlan '%d'\n", config.netif[i].vlan[j].vid);
                if (config.netif[i].vlan[j].gateway_configured) {
                    LOG_MAC(&(config.netif[i].vlan[j].gateway.mac_address), mac_str);
                    LOG_IPV4(&(config.netif[i].vlan[j].gateway.ipv4_address), ipv4_str);
                    printf("        gateway %s %s\n", mac_str, ipv4_str);
                }

                if (config.netif[i].vlan[j].ptp_configured) {
                    for (int k = 0; k < config.netif[i].vlan[j].ptp.slave_size; k++) {

                    }
                }

                if (config.netif[i].vlan[j].ntp_configured) {
                    {
                        LOG_MAC(&(config.netif[i].vlan[j].ntp.server.mac_address), mac_str);
                        LOG_IPV4(&(config.netif[i].vlan[j].ntp.server.ipv4_address), ipv4_str);
                        printf("        server %s %s\n", mac_str, ipv4_str);
                    }
                    for (int k = 0; k < config.netif[i].vlan[j].ntp.client_size; k++) {
                        LOG_MAC(&(config.netif[i].vlan[j].ntp.client[k].mac_address), mac_str);
                        LOG_IPV4(&(config.netif[i].vlan[j].ntp.client[k].ipv4_address), ipv4_str);
                        printf("        client %s %s\n", mac_str, ipv4_str);

                        {
                            packet_t                       *packet;
                            packet = create_ntp_req(&(config.netif[i].vlan[j].ntp.server), &(config.netif[i].vlan[j].ntp.client[k]));

                            /* encode */
                            if (packet_encode(&netif, packet, &raw_packet)) {
                                LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Successfully encoded packet"));
                            } else {
                                LOG_PRINTLN(LOG_SIM, LOG_ERROR, ("Error encoding packet"));
                            }

                            LOG_RAW_PACKET(LOG_SIM, LOG_INFO, &raw_packet, ("TX"));

                            /* send */
                            netif_frame_send(&netif, &raw_packet);

                            object_release(packet);

                        }
                    }
                }
            }
        }
    }
    fprintf(stderr, "Exit!\n");
    
    return 0;
}

void
usage(int argc, char *argv[], const char *msg)
{
   fprintf(stderr, CONFIG_PROGRAM_DESC " " CONFIG_PROGRAM_VERSION "\n");
   fprintf(stderr, "Usage: %s [-d] [-f <config-file>] [-l <number>] -i ifname\n", argv[0]);
   
   if (msg == OPT_REQUIRED) {
       fprintf(stderr, "\nOption -%c requires an operand\n", optopt);
   } else if (msg == OPT_UNRECOGNISED) {
       fprintf(stderr, "\nUnrecognised option: -%c\n", optopt);
   } else if (msg != NULL) {
       fprintf(stderr, "\n%s\n", msg);
   }
   
   exit(EXIT_FAILURE);
}
