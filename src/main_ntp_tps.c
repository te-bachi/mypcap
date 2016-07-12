#include "config.h"
#include "config_file.h"
#include "log.h"
#include "log_network.h"

#include "packet/raw_packet.h"
#include "packet/packet.h"
#include "packet/port.h"

#include <pthread.h>
#include <semaphore.h>
#include <signal.h>

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
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
    pthread_t           id;
    config_t           *config;
    bool                ip_src_increment;
    uint16_t            ip_src_max;
    uint16_t            packet_gap;
    uint16_t            max_packets_sec;
    uint16_t            total_packets;
    netif_t            *netif;
    //pthread_mutex_t    *mutex;
    //pthread_cond_t     *cond_limit;
    //pthread_cond_t     *cond_max;
    pthread_barrier_t  *barrier;
    sem_t              *sem_max;
    sem_t              *sem_print;
    uint16_t            port;
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
packet_t           *create_ntp_req(config_ntp_t *ntp_config, uint16_t port, uint32_t id, config_ntp_peer_t *server, config_ntp_peer_t *client, uint32_t idx);
void *              receive_thread(void *param);
void *              transmit_thread(void *param);
void *              process(void *param);
bool                ntp_tps(const char *config_file, uint16_t port, uint16_t ip_src_max, uint16_t packet_gap, uint16_t max_packets_sec, uint16_t total_packets);
void                ctrl_c(int signal);
void                usage(int argc, char *argv[], const char *msg);
bool                parse_uint16(const char *argument, const char *str, uint16_t *result, void (*callback)(int));

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
create_ntp_req(config_ntp_t *ntp_config, uint16_t port, uint32_t id, config_ntp_peer_t *server, config_ntp_peer_t *client, uint32_t idx)
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
    udpv4->src_port                                         = port;
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
    struct timespec     tsp;
    time_t              seconds;
    uint32_t            count;

    seconds = 0;
    count   = 0;

    while (running) {
        if (netif_frame_receive(netif, &raw_packet)) {
            count++;
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
//        } else {
//            pthread_mutex_lock(context->mutex);
//            pthread_cond_signal(context->cond_limit);
//            pthread_mutex_unlock(context->mutex);
//        }

        get_ostime(&tsp);

        if (tsp.tv_sec > seconds) {
            sem_post(context->sem_max);
            pthread_barrier_wait(context->barrier);
            sem_wait(context->sem_print);
//            pthread_mutex_lock(context->mutex);
            printf("RX: %" PRIu32 "\n", count);
//            pthread_cond_signal(context->cond_limit);
//            pthread_cond_signal(context->cond_max);
//            pthread_mutex_unlock(context->mutex);

            seconds = tsp.tv_sec;
            count   = 0;
        }
    }
    sem_post(context->sem_max);
    printf("RX: %" PRIu32 "\n", count);
//    pthread_mutex_lock(context->mutex);
//    pthread_cond_signal(context->cond_limit);
//    pthread_cond_signal(context->cond_max);
//    pthread_mutex_unlock(context->mutex);

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
    time_t              seconds;
    uint32_t            count;
    uint32_t            total_count;

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
                        packet  = create_ntp_req(&(config->netif[i].vlan[j].ntp), context->port, id++, &(config->netif[i].vlan[j].ntp.client[k]), &(config->netif[i].vlan[j].ntp.server), k);
                        ipv4    = (ipv4_header_t *) packet_search_header(packet, HEADER_TYPE_IPV4);
                        ntp     = (ntp_header_t *) packet_search_header(packet, HEADER_TYPE_NTP);
                        seconds = 0;
                        count   = 0;

                        while (running && (context->total_packets == 0 || total_count < context->total_packets)) {
                            if (count < context->max_packets_sec) {
                                /* encode */
                                if (!packet_encode(netif, packet, &raw_packet)) {
                                    LOG_PRINTLN(LOG_SIM, LOG_ERROR, ("Error encoding packet"));
                                    return NULL;
                                }

                                /* send */
                                netif_frame_send(netif, &raw_packet);
                                count++;
                                total_count++;
                                ipv4->id = k;
//                                if (count % 2 == 0) {
//                                    pthread_mutex_lock(context->mutex);
//                                    pthread_cond_wait(context->cond_limit, context->mutex);
//                                    pthread_mutex_unlock(context->mutex);
//                                }
                            } else {
                                sem_wait(context->sem_max);
//                                pthread_mutex_lock(context->mutex);
//                                pthread_cond_wait(context->cond_max, context->mutex);
//                                pthread_mutex_unlock(context->mutex);
                            }

                            get_ostime(&tsp);
                            ntp->transmit_timestamp.seconds     = tsp.tv_sec + 2208988800UL;
                            ntp->transmit_timestamp.nanoseconds = TVNTOF(tsp.tv_nsec);
                            if (context->ip_src_increment) {
                                if (ntohl(ipv4->src.addr32) > (ntohl(config->netif[i].vlan[j].ntp.server.ipv4_address.addr32) + context->ip_src_max)) {
                                    ipv4->src = config->netif[i].vlan[j].ntp.server.ipv4_address;
                                } else {
                                    ipv4->src.addr32 = htonl(ntohl(ipv4->src.addr32) + 1);
                                }
                            }

                            if (tsp.tv_sec > seconds) {
                                pthread_barrier_wait(context->barrier);
//                                pthread_mutex_lock(context->mutex);
                                printf("TX: %" PRIu32 "\n", count);
                                sem_post(context->sem_print);
//                                pthread_mutex_unlock(context->mutex);

                                seconds = tsp.tv_sec;
                                count   = 0;
                            } else {
                                usleep(context->packet_gap);
                            }
                        }
                        printf("TX: %" PRIu32 "\n", count);
                        running = false;
                        pthread_barrier_destroy(context->barrier);
                        sem_post(context->sem_print);

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
ntp_tps(const char *config_file, uint16_t port, uint16_t ip_src_max, uint16_t packet_gap, uint16_t max_packets_sec, uint16_t total_packets)
{
    config_t            config;
    netif_t             netif;
//    pthread_mutex_t     mutex;
//    pthread_cond_t      cond_limit;
//    pthread_cond_t      cond_max;
    pthread_barrier_t   barrier;
    sem_t               sem_max;
    sem_t               sem_print;
    bool                single_thread = false;
    pthread_t           receive;
    pthread_t           transmit;

    thread_context_t    context = {
            .config             = &config,
            .ip_src_increment   = ip_src_max > 0 ? true : false,
            .ip_src_max         = ip_src_max,
            .packet_gap         = packet_gap,
            .max_packets_sec    = max_packets_sec,
            .total_packets      = total_packets,
            .netif              = &netif,
//            .mutex              = &mutex,
//            .cond_limit         = &cond_limit,
//            .cond_max           = &cond_max,
            .barrier            = &barrier,
            .sem_max            = &sem_max,
            .sem_print          = &sem_print,
            .port               = port
    };

    printf("  Config file                 = %s\n", config_file);
    printf("  UDP port                    = %d\n", port);
    printf("  Max. IPv4-address increment = %d\n", ip_src_max);
    printf("  Gap between packets (us)    = %d\n", packet_gap);
    printf("  Max. packets per second     = %d\n", max_packets_sec);
    printf("  Total packets               = %d\n", total_packets);

    log_init();
    log_set_all(LOG_ERROR);

    LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Using config-file \"%s\"", config_file));
    if (!config_file_parse(config_file, &config)) {
        LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Error in parsing the file!\n"));
        exit(EXIT_FAILURE);
    }

    if (!netif_init_bpf(&netif, config.netif[0].name, port, filter, sizeof(filter) / sizeof(struct sock_filter))) {
        return false;
    }

    signal(SIGINT, ctrl_c);

    if (single_thread) {
        process(&context);
    } else {
//        pthread_mutex_init(&mutex, NULL);
//        pthread_cond_init(&cond_limit, NULL);
//        pthread_cond_init(&cond_max, NULL);
        pthread_barrier_init(&barrier, NULL, 2 /* number of threads: transmit + receive */);
        sem_init(&sem_max, 0, 0);
        sem_init(&sem_print, 0, 0);

        pthread_create(&receive, NULL, receive_thread, &context);
        pthread_create(&transmit, NULL, transmit_thread, &context);

        pthread_join(receive, NULL);
        pthread_join(transmit, NULL);

        pthread_exit(NULL);
    }

    return true;
}

int
main(int argc, char *argv[])
{
    char        config_file[NAME_MAX+1];
    bool        fflag           = false;  /* option: config-file */

    uint16_t    port            = 40123;
    uint16_t    ip_src_max      = 0;
    uint16_t    packet_gap      = 60;
    uint16_t    max_packets_sec = 7000;
    uint16_t    total_packets   = 0;

    int         opt;            /* argument for getopt() as a single integer */



    /* program without arguments */
    if (argc == 1) {
        usage(argc, argv, NULL);
    }

    /* first character ':' of getopt()'s optstring sets opterr=0 and
       returns ':' to indicate a missing option argument
       or '?' to indicate a unrecognised option */
    while ((opt = getopt(argc, argv, ":hf:i:g:m:p:t:")) != -1) {
        switch (opt) {

            /* option: help */
            case 'h':
                usage(argc, argv, NULL);
                exit(0);

            /* option: config-file */
            case 'f':
                strcpy(config_file, optarg);
                fflag           = true;
                break;

            /* option: UDP port */
            case 'p':
                parse_uint16("p", optarg, &port, exit);
                break;

            /* option: incrementing IPv4-addresses */
            case 'i':
                parse_uint16("i", optarg, &ip_src_max, exit);
                break;

            /* option: gap between packets in microseconds */
            case 'g':
                parse_uint16("g", optarg, &packet_gap, exit);
                break;

            /* option: max. packet per second */
            case 'm':
                parse_uint16("m", optarg, &max_packets_sec, exit);
                break;

            /* option: exit after sending a certain amount packets */
            case 't':
                parse_uint16("t", optarg, &total_packets, exit);
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

    ntp_tps(config_file, port, ip_src_max, packet_gap, max_packets_sec, total_packets);

    fprintf(stderr, "Exit!\n");

    return 0;
}

void
usage(int argc, char *argv[], const char *msg)
{
   fprintf(stderr, "NTP TPS (transaction per second)\n");
   fprintf(stderr, "Usage: %s [-f <config-file>]\n", argv[0]);
   fprintf(stderr, "          [-p <UDP port>]\n");
   fprintf(stderr, "          [-i <max increment>]\n");
   fprintf(stderr, "          [-g <gap between packets in us>]\n");
   fprintf(stderr, "          [-m <max packets per second>]\n");
   fprintf(stderr, "          [-t <total packets>]\n");

   if (msg == OPT_REQUIRED) {
       fprintf(stderr, "\nOption -%c requires an operand\n", optopt);
   } else if (msg == OPT_UNRECOGNISED) {
       fprintf(stderr, "\nUnrecognised option: -%c\n", optopt);
   } else if (msg != NULL) {
       fprintf(stderr, "\n%s\n", msg);
   }

   exit(EXIT_FAILURE);
}

bool
parse_uint16(const char *argument, const char *str, uint16_t *result, void (*callback)(int))
{
    char *end;

    const long value = strtol(str, &end, 10 /* = decimal conversion */ );

    if (end == str) {
        printf("argument %s with value %s is not a decimal number\n", argument, str);
        goto parse_uint16_failed;
    } else if (*end != '\0') {
        printf("argument %s with value %s has extra characters\n", argument, str);
        goto parse_uint16_failed;
    } else if (value > UINT16_MAX) {
        printf("argument %s with value %s is out of range\n", argument, str);
        goto parse_uint16_failed;
    }

    *result = value;
    return true;

parse_uint16_failed:
    if (callback != NULL) {
        callback(-1);
    }
    return false;
}



void *
process(void *param)
{
    thread_context_t   *context = (thread_context_t *) param;
    config_t           *config  = context->config;
    netif_t            *netif   = context->netif;
    raw_packet_t        raw_packet;
    packet_t           *tx_packet;
    packet_t           *rx_packet;
    uint32_t            id = 0;
    ipv4_header_t      *ipv4;
    ntp_header_t       *ntp;
    struct timespec     tsp;
    time_t              seconds;
    uint32_t            rx_count;
    uint32_t            tx_count;

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
                        tx_packet   = create_ntp_req(&(config->netif[i].vlan[j].ntp), context->port, id++, &(config->netif[i].vlan[j].ntp.client[k]), &(config->netif[i].vlan[j].ntp.server), k);
                        ipv4        = (ipv4_header_t *) packet_search_header(tx_packet, HEADER_TYPE_IPV4);
                        ntp         = (ntp_header_t *) packet_search_header(tx_packet, HEADER_TYPE_NTP);
                        seconds     = 0;
                        rx_count    = 0;
                        tx_count    = 0;

                        while (running) {
                            if (tx_count < 6000) {
                                /* encode */
                                if (!packet_encode(netif, tx_packet, &raw_packet)) {
                                    LOG_PRINTLN(LOG_SIM, LOG_ERROR, ("Error encoding packet"));
                                    return NULL;
                                }

                                /* send */
                                netif_frame_send(netif, &raw_packet);
                                tx_count++;
                                ipv4->id = k;
                            }

                            if (netif_frame_ready(netif)) {
                                if (netif_frame_receive(netif, &raw_packet)) {
                                    rx_count++;
                                    /* decode */
                                    rx_packet = packet_decode(netif, &raw_packet);
                                    if (rx_packet != NULL) {
                                        if (packet_includes_by_layer(rx_packet, HEADER_TYPE_ETHERNET,  HEADER_LAYER_2) &&
                                            packet_includes_by_layer(rx_packet, HEADER_TYPE_IPV4,      HEADER_LAYER_3) &&
                                            packet_includes_by_layer(rx_packet, HEADER_TYPE_UDPV4,     HEADER_LAYER_4) &&
                                            packet_includes_by_layer(rx_packet, HEADER_TYPE_NTP,       HEADER_LAYER_5)) {

                                            LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Successfully decoded packet"));
                                            object_release(rx_packet);
                                        }
                                    } else {
                                        LOG_PRINTLN(LOG_SIM, LOG_ERROR, ("Error decoding packet"));
                                    }
                                }
                            }

                            get_ostime(&tsp);
                            ntp->transmit_timestamp.seconds     = tsp.tv_sec + 2208988800UL;
                            ntp->transmit_timestamp.nanoseconds = TVNTOF(tsp.tv_nsec);

                            if (tsp.tv_sec > seconds) {
                                printf("RX: %" PRIu32 "\n", rx_count);
                                printf("TX: %" PRIu32 "\n", tx_count);

                                seconds     = tsp.tv_sec;
                                rx_count    = 0;
                                tx_count    = 0;
                            }

                            usleep(100);
                        }
                        object_release(tx_packet);
                    }
                }
            }
        }
    }

    return NULL;
}
