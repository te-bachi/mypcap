#include "config.h"
#include "config_file.h"
#include "log.h"
#include "log_network.h"

#include "packet/raw_packet.h"
#include "packet/packet.h"
#include "packet/port.h"

#include <pthread.h>
#include <signal.h>

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <linux/limits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#define OPT_REQUIRED     (void *) 1
#define OPT_UNRECOGNISED (void *) 2

typedef struct _thread_context_t {
    pthread_t   id;
    config_t   *config;
    netif_t    *netif;
} thread_context_t;

struct sock_filter filter[] = {
    /* Make sure this is an IP packet... */
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 8),

    /* Make sure it's a UDP packet... */
    BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 6),

    /* Make sure this isn't a fragment... */
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),
    BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0),

    /* Get the IP header length... */
    BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 14),

    /* Make sure it's to the right port... */
    BPF_STMT(BPF_LD + BPF_H + BPF_IND, 14),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, PORT_NTP, 0, 1),

    /* If we passed all the tests, ask for the whole packet. */
    BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

    /* Otherwise, drop it. */
    BPF_STMT(BPF_RET+BPF_K, 0),
};

static inline void  get_ostime(struct timespec *tsp);
packet_t           *create_ntp_req(config_ntp_t *ntp_config, uint32_t id, config_ntp_peer_t *server, config_ntp_peer_t *client, uint32_t idx);
void *              receive_thread(void *param);
void *              transmit_thread(void *param);
bool                ntp_tps(const char *config_file);
void                ctrl_c(int signal);
void                usage(int argc, char *argv[], const char *msg);

static volatile bool running = true;

static inline void
get_ostime(struct timespec *tsp)
{
    int     rc;

    rc = clock_gettime(CLOCK_REALTIME, tsp);
    if (rc < 0) {

        LOG_ERRNO(LOG_SIM, LOG_INFO, errno, ("read system clock failed"));
        exit(1);
    }
}


packet_t *
create_ntp_req(config_ntp_t *ntp_config, uint32_t id, config_ntp_peer_t *server, config_ntp_peer_t *client, uint32_t idx)
{
    packet_t                       *packet                  = packet_new();
    ethernet_header_t              *ether                   = ethernet_header_new();
    ipv4_header_t                  *ipv4                    = ipv4_header_new();
    udpv4_header_t                 *udpv4                   = udpv4_header_new();
    ntp_header_t                   *ntp                     = ntp_header_new();

    struct timespec                 tsp;

    /* Ethernet */
    packet->head                                            = (header_t *) ether;
    ether->dest                                             = server->mac_address;
    ether->src                                              = client->mac_address;
    ether->type                                             = ETHERTYPE_IPV4;

    /* IPv4 */
    ether->header.next                                      = (header_t *) ipv4;
    ipv4->version                                           = IPV4_HEADER_VERSION;
    ipv4->ihl                                               = IPV4_HEADER_IHL;
    ipv4->ecn                                               = 0;
    ipv4->dscp                                              = 0;
    ipv4->id                                                = id;
    ipv4->fragment_offset                                   = 0;
    ipv4->more_fragments                                    = 0;
    ipv4->dont_fragment                                     = 0;
    ipv4->reserved                                          = 0;
    ipv4->ttl                                               = 128;
    ipv4->protocol                                          = IPV4_PROTOCOL_UDP;
    ipv4->src                                               = client->ipv4_address;
    ipv4->dest                                              = server->ipv4_address;

    /* UDPv4 */
    ipv4->header.next                                       = (header_t *) udpv4;
    udpv4->src_port                                         = 40581;
    udpv4->dest_port                                        = PORT_NTP;

    /* NTP */
    udpv4->header.next                                      = (header_t *) ntp;
    ntp->leap_indicator                                     = NTP_LEAP_INDICATOR_NO_WARNING;
    ntp->version                                            = NTP_VERSION_4;
    ntp->mode                                               = NTP_MODE_CLIENT;
    ntp->stratum                                            = 0;
    ntp->polling_interval                                   = 0;
    ntp->clock_precision                                    = 0;
    ntp->root_delay                                         = 0x0000000;
    ntp->root_dispersion                                    = 0x00000000;

    ntp->reference_id[0]                                    = 0;
    ntp->reference_id[1]                                    = 0;
    ntp->reference_id[2]                                    = 0;
    ntp->reference_id[3]                                    = 0;
    ntp->reference_timestamp.seconds                        = 0;
    ntp->reference_timestamp.nanoseconds                    = 0;
    ntp->origin_timestamp.seconds                           = 0;
    ntp->origin_timestamp.nanoseconds                       = 0;
    ntp->receive_timestamp.seconds                          = 0;
    ntp->receive_timestamp.nanoseconds                      = 0;

    get_ostime(&tsp);
    ntp->transmit_timestamp.seconds                         = tsp.tv_sec + 2208988800UL;
    ntp->transmit_timestamp.nanoseconds                     = TVNTOF(tsp.tv_nsec);

    LOG_PACKET(LOG_SIM, LOG_INFO, packet, ("TX"));

    return packet;
}

void *
receive_thread(void *param)
{
    thread_context_t   *context = (thread_context_t *) param;
    netif_t            *netif   = context->netif;
    raw_packet_t        raw_packet;
    packet_t           *packet;

    while (running) {
        if (netif_frame_receive(netif, &raw_packet)) {

            /* decode */
            packet = packet_decode(netif, &raw_packet);
            if (packet != NULL) {
                if (packet_includes_by_layer(packet, HEADER_TYPE_ETHERNET,  HEADER_LAYER_2) &&
                    packet_includes_by_layer(packet, HEADER_TYPE_IPV4,      HEADER_LAYER_3) &&
                    packet_includes_by_layer(packet, HEADER_TYPE_UDPV4,     HEADER_LAYER_4) &&
                    packet_includes_by_layer(packet, HEADER_TYPE_NTP,       HEADER_LAYER_5)) {

                    LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Successfully decoded packet"));
                    object_release(packet);
                }
            } else {
                LOG_PRINTLN(LOG_SIM, LOG_ERROR, ("Error decoding packet"));
            }
        }
    }

    return NULL;
}

void *
transmit_thread(void *param)
{
    thread_context_t   *context = (thread_context_t *) param;
    config_t           *config  = context->config;
    netif_t            *netif   = context->netif;
    raw_packet_t        raw_packet;
    packet_t           *packet;
    uint32_t            id = 0;
    ipv4_header_t      *ipv4;
    ntp_header_t       *ntp;
    struct timespec     tsp;

    raw_packet_init(&raw_packet);

    /* netif */
    for (int i = 0; i < config->netif_size; i++) {
        LOG_PRINTLN(LOG_SIM, LOG_INFO, ("netif '%s'", config->netif[i].name));

        /* vlan */
        for (int j = 0; j < config->netif[i].vlan_size; j++) {
            LOG_PRINTLN(LOG_SIM, LOG_INFO, ("    vlan '%d'", config->netif[i].vlan[j].vid));
            if (config->netif[i].vlan[j].gateway_configured) {
                LOG_MAC(&(config->netif[i].vlan[j].gateway.mac_address), mac_str);
                LOG_IPV4(&(config->netif[i].vlan[j].gateway.ipv4_address), ipv4_str);
                LOG_PRINTLN(LOG_SIM, LOG_INFO, ("        gateway %s %s", mac_str, ipv4_str));
            }

            /* ntp */
            if (config->netif[i].vlan[j].ntp_configured) {
                {
                    LOG_MAC(&(config->netif[i].vlan[j].ntp.server.mac_address), mac_str);
                    LOG_IPV4(&(config->netif[i].vlan[j].ntp.server.ipv4_address), ipv4_str);
                    LOG_PRINTLN(LOG_SIM, LOG_INFO, ("        server %s %s", mac_str, ipv4_str));
                }
                /* ntp client */
                for (int k = 0; k < config->netif[i].vlan[j].ntp.client_size; k++) {
                    LOG_MAC(&(config->netif[i].vlan[j].ntp.client[k].mac_address), mac_str);
                    LOG_IPV4(&(config->netif[i].vlan[j].ntp.client[k].ipv4_address), ipv4_str);
                    LOG_PRINTLN(LOG_SIM, LOG_INFO, ("        client %s %s", mac_str, ipv4_str));

                    {
                        /* swap client/server */
                        packet  = create_ntp_req(&(config->netif[i].vlan[j].ntp), id++, &(config->netif[i].vlan[j].ntp.client[k]), &(config->netif[i].vlan[j].ntp.server), k);
                        ipv4    = (ipv4_header_t *) packet_search_header(packet, HEADER_TYPE_IPV4);
                        ntp     = (ntp_header_t *) packet_search_header(packet, HEADER_TYPE_NTP);


                        while (running) {
                            /* encode */
                            if (!packet_encode(netif, packet, &raw_packet)) {
                                LOG_PRINTLN(LOG_SIM, LOG_ERROR, ("Error encoding packet"));
                                return NULL;
                            }

                            /* send */
                            netif_frame_send(netif, &raw_packet);

                            ipv4->id = k;

                            get_ostime(&tsp);
                            ntp->transmit_timestamp.seconds     = tsp.tv_sec + 2208988800UL;
                            ntp->transmit_timestamp.nanoseconds = TVNTOF(tsp.tv_nsec);
                        }
                        object_release(packet);
                    }
                }
            }
        }
    }

    return NULL;
}

void
ctrl_c(int signal)
{
    running = false;
}

bool
ntp_tps(const char *config_file)
{
    config_t            config;
    netif_t             netif;
    thread_context_t    receive = {
            .id     = 0,
            .config = &config,
            .netif  = &netif
    };
    thread_context_t    transmit = {
            .id     = 0,
            .config = &config,
            .netif  = &netif
    };

    log_init();
    log_set_all(LOG_ERROR);

    LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Using config-file \"%s\"", config_file));
    if (!config_file_parse(config_file, &config)) {
        LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Error in parsing the file!\n"));
        exit(EXIT_FAILURE);
    }

    if (!netif_init_bpf(&netif, config.netif[0].name, filter, sizeof(filter) / sizeof(struct sock_filter))) {
        return false;
    }

    signal(SIGINT, ctrl_c);

    pthread_create(&receive.id, NULL, receive_thread, &receive);
    pthread_create(&transmit.id, NULL, transmit_thread, &transmit);

    pthread_join(receive.id, NULL);
    pthread_join(transmit.id, NULL);

    pthread_exit(NULL);

    return true;
}

int
main(int argc, char *argv[])
{
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

    /* option: config-file */
    if (!fflag) {
        strcpy(config_file, CONFIG_FILE_NAME);
    }

    ntp_tps(config_file);

    fprintf(stderr, "Exit!\n");

    return 0;
}

void
usage(int argc, char *argv[], const char *msg)
{
   fprintf(stderr, "NTP TPS (transaction per second)\n");
   fprintf(stderr, "Usage: %s -f <config-file>]\n", argv[0]);

   if (msg == OPT_REQUIRED) {
       fprintf(stderr, "\nOption -%c requires an operand\n", optopt);
   } else if (msg == OPT_UNRECOGNISED) {
       fprintf(stderr, "\nUnrecognised option: -%c\n", optopt);
   } else if (msg != NULL) {
       fprintf(stderr, "\n%s\n", msg);
   }

   exit(EXIT_FAILURE);
}
