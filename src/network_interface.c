#include "network_interface.h"
#include "log.h"
#include "log_network.h"

#include "packet/port.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <inttypes.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>

#if __FreeBSD__
#include <net/if_dl.h>
#include <net/if_var.h>
#include <net/if_vlan_var.h>
#elif __linux__
#include <netpacket/packet.h>
#include <linux/if_link.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#endif

#include <ifaddrs.h>


#define NETIF_SELECT_WAIT_SECS              0
#define NETIF_SELECT_WAIT_USECS             1000

#define INADDR(x)   ((struct sockaddr_in  *) x)
#define INADDR6(x)  ((struct sockaddr_in6 *) x)
#define LADDR(x)    ((struct sockaddr_dl  *) x)
#if __linux__
#define LLADDR(x)   ((struct sockaddr_ll  *) x)
#endif

static vlan_t       *netif_create_vlan(void);
static ipv4_alias_t *netif_create_ipv4_alias(void);
static ipv6_alias_t *netif_create_ipv6_alias(void);


static bool netif_clear_receive_buffer(netif_t *netif);

bool
netif_init(netif_t *netif, const char *name)
{
    return netif_init_bpf(netif, name, 0, NULL, 0);
}

bool
netif_init_port(netif_t *netif, const char *name, uint16_t port)
{
    return netif_init_bpf(netif, name, port, NULL, 0);
}

bool
#if __FreeBSD__
netif_init_bpf(netif_t *netif, const char *name, uint16_t port, struct bpf_insn *filter)
#elif __linux__
netif_init_bpf(netif_t *netif, const char *name, uint16_t port, struct sock_filter *filter, int filter_len)
#endif
{
    bool                        result = true;
    struct ifaddrs             *ifas;
    struct ifaddrs             *ifa;

#if __FreeBSD__
    struct ifreq                ifr;            /* ioctl call to get VID */
    struct vlanreq              vreq;           /* ioctl call to get VID */
#elif __linux__
    struct ifreq                ifr;            /* ioctl call to get MAC address*/
    struct rtnl_link_stats     *stats;
    struct vlan_ioctl_args      ifv;            /* ioctl call to get VID */
    struct sockaddr_ll          addr;           /* to bind packet socket to interface */
    struct sockaddr_in          dummy_addr;     /* to bind dummy socket to interface */
    struct sock_fprog           prog;           /* to attach to filter */
#endif

    
    /* string copy name */
    strncpy(netif->name, name, NETIF_NAME_SIZE);
    
    /* set to zero */
    memcpy(netif->mac.addr, MAC_ADDRESS_NULL.addr, MAC_ADDRESS_LEN);
    netif->vlan = NULL;
    netif->ipv4 = NULL;
    netif->ipv6 = NULL;

    /*** get the index of the interface ***/
    netif->index = if_nametoindex(netif->name);

    if (netif->index == 0) {
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_ERROR, ("interface '%s' is not known", netif->name));
        return false;
    }
    
    /* create socket */
    if ((netif->socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        LOG_ERRNO(LOG_NETWORK_INTERFACE, LOG_ERROR, errno, ("socket failed"));
        return false;
    }
    
    /* get interface addresses */
    if (getifaddrs(&ifas) != 0) {
         LOG_ERRNO(LOG_NETWORK_INTERFACE, LOG_ERROR, errno, ("getifaddrs failed"));
        return false;
    }
    
    for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr)           == NULL) continue;
        if ((ifa->ifa_flags & IFF_UP) == 0)    continue;
        
        
        /* network interface name matches */
        if (strcmp(name, ifa->ifa_name) == 0) {
            
            switch (ifa->ifa_addr->sa_family) {
                case AF_INET:   netif_add_ipv4_address(netif,      IPV4_ADDRESS(&(INADDR(ifa->ifa_addr)->sin_addr)),
                                                                   IPV4_ADDRESS(&(INADDR(ifa->ifa_netmask)->sin_addr)),
                                                                   IPV4_ADDRESS(&(INADDR(ifa->ifa_broadaddr)->sin_addr)),
                                                                   NULL);
                                break;
                
                case AF_INET6:  netif_add_ipv6_address(netif,      IPV6_ADDRESS(&(INADDR6(ifa->ifa_addr)->sin6_addr)),
                                                                   IPV6_ADDRESS(&(INADDR6(ifa->ifa_netmask)->sin6_addr)),
                                                                   IPV6_STATE_VALID);
                                break;

#if __FreeBSD__
                case AF_LINK:   netif_add_mac_address(netif,       MAC_ADDRESS(LLADDR(LADDR(ifa->ifa_addr))));
                                
                                bzero((char *) &ifr, sizeof(ifr));
                                bzero((char *) &vreq, sizeof(vreq));
                                strncpy(ifr.ifr_name, netif->name, NETIF_NAME_SIZE);
                                ifr.ifr_data = (caddr_t) &vreq;
                                if (ioctl(sockfd, SIOCGETVLAN, &ifr) != -1) {
                                    netif_add_vid(netif, vreq.vlr_tag);
                                }
                                break;
#elif __linux__
                case AF_PACKET: stats = ifa->ifa_data;
                                LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_DEBUG, ("tx packet: %" PRIu32 " rx packet: %" PRIu32 " tx bytes: %" PRIu32 " rx bytes: %" PRIu32,
                                                                               stats->tx_packets, stats->rx_packets, stats->tx_bytes, stats->rx_bytes));

                                /* get MAC address, see netdevice(7) */
                                bzero((char *) &ifr, sizeof(ifr));
                                strncpy(ifr.ifr_name, netif->name, NETIF_NAME_SIZE);
                                if (ioctl(netif->socket, SIOCGIFHWADDR, &ifr) != -1) {
                                    netif_add_mac_address(netif,   MAC_ADDRESS(LLADDR(LADDR(ifr.ifr_hwaddr.sa_data))));
                                    bzero((char *) &ifv, sizeof(ifv));
                                    ifv.cmd = GET_VLAN_VID_CMD;
                                    strncpy(ifv.device1, netif->name, sizeof(ifv.device1));
                                    if (ioctl(netif->socket, SIOCGIFVLAN, &ifv) != -1) {
                                        netif_add_vid(netif, ifv.u.VID);
                                    }
                                } else {
                                    LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_ERROR, ("couldn't get MAC address"));
                                    result = false;
                                    goto netif_init_exit;
                                }
                                break;
#endif
                default:        continue;
            }
        }
    }
    

    /* bind packet socket to interface */
    bzero(&addr, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex  = netif->index;

    if (bind(netif->socket, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(netif->socket);
        LOG_ERRNO(LOG_NETWORK_INTERFACE, LOG_ERROR, errno, ("can't bind packet socket to interface"));
        return false;
    }


#if __FreeBSD__

#elif __linux__
    if (filter != NULL) {
        prog.filter = filter;
        prog.len    = filter_len;
        if (setsockopt(netif->socket, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
            close(netif->socket);
            LOG_ERRNO(LOG_NETWORK_INTERFACE, LOG_ERROR, errno, ("can't add BPF filter"));
            return false;
        }
    }
#endif

    if (netif->ipv4 != NULL && port > 0) {
        /* create dummy socket ***/
        if ((netif->dummy_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            close(netif->socket);
            LOG_ERRNO(LOG_NETWORK_INTERFACE, LOG_ERROR, errno, ("can't create dummy socket"));
            return false;
        }

        /* bind dummy socket to interface */
        bzero(&dummy_addr, sizeof(dummy_addr));
        dummy_addr.sin_family      = AF_INET;
        dummy_addr.sin_addr.s_addr = netif->ipv4->address.addr32;
        dummy_addr.sin_port        = htons(port);

        if (bind(netif->dummy_socket, (struct sockaddr *) &dummy_addr, sizeof(dummy_addr)) < 0) {
            close(netif->socket);
            close(netif->dummy_socket);
            LOG_ERRNO(LOG_NETWORK_INTERFACE, LOG_ERROR, errno, ("can't bind dummy socket to interface"));
            return false;
        }
    }

    /* clear receive buffer */
    if (!netif_clear_receive_buffer(netif)) {
        return false;
    }


netif_init_exit:
    freeifaddrs(ifas);
    
    return result;
}

static vlan_t *
netif_create_vlan(void)
{
    return (vlan_t *) malloc(sizeof(vlan_t));
}

static ipv4_alias_t *
netif_create_ipv4_alias(void)
{
    return (ipv4_alias_t *) malloc(sizeof(ipv4_alias_t));
}

static ipv6_alias_t *
netif_create_ipv6_alias(void)
{
    return (ipv6_alias_t *) malloc(sizeof(ipv6_alias_t));
}

bool
netif_add_mac_address(netif_t *netif, const mac_address_t *mac)
{
    if (LOG_ENABLE(LOG_NETWORK_INTERFACE, LOG_INFO)) {
        LOG_MAC(mac, mac_str);
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_mac_address:        mac = %s", mac_str));
    }
    netif->mac = *mac;
    
    return true;
}

bool
netif_add_vid(netif_t *netif, const uint16_t vid)
{
    vlan_t *vlan;
    
    if (LOG_ENABLE(LOG_NETWORK_INTERFACE, LOG_INFO)) {
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_vlan:               vid = %u", vid));
    }
    
    if (netif->vlan != NULL) {
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_WARNING, ("overwrite VLAN       vid = %u", netif->vlan->vid));
    }
    
    vlan = netif_create_vlan();
    netif->vlan = vlan;
    
    return true;
}

bool
netif_add_ipv4_address(netif_t *netif, const ipv4_address_t *address, const ipv4_address_t *netmask, const ipv4_address_t *broadcast, const ipv4_address_t *gateway)
{
    ipv4_alias_t *ipv4;
    
    if (LOG_ENABLE(LOG_NETWORK_INTERFACE, LOG_INFO)) {
        LOG_IPV4(address,   address_str);
        LOG_IPV4(broadcast, broadcast_str);
        LOG_IPV4(netmask,   netmask_str);
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_ipv4_address:   address = %s", address_str));
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_ipv4_address:   netmask = %s", netmask_str));
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_ipv4_address: broadcast = %s", broadcast_str));
    }
    
    /**
     * Concatinate:
     *    _____________      __________________
     *   |             |    |                  |
     *   | netif->ipv4 |===>| old ipv4 or NULL |
     *   |_____________|    |__________________|
     *    _____________      __________      __________________
     *   |             |    |          |    |                  |
     *   | netif->ipv4 |===>| new ipv4 |===>| old ipv4 or NULL |
     *   |_____________|    |__________|    |__________________|
     */
    ipv4            = netif_create_ipv4_alias();
    ipv4->next      = netif->ipv4;
    netif->ipv4     = ipv4;
    
    ipv4->address   = address   != NULL ? *address   : IPV4_ADDRESS_NULL;
    ipv4->netmask   = netmask   != NULL ? *netmask   : IPV4_ADDRESS_NULL;
    ipv4->broadcast = broadcast != NULL ? *broadcast : IPV4_ADDRESS_NULL;
    ipv4->gateway   = gateway   != NULL ? *gateway   : IPV4_ADDRESS_NULL;

    return true;
}

bool
netif_add_ipv6_address(netif_t *netif, const ipv6_address_t *address, const ipv6_address_t *netmask, const ipv6_state_t state)
{
    ipv6_alias_t *ipv6;
    
    if (LOG_ENABLE(LOG_NETWORK_INTERFACE, LOG_INFO)) {
        LOG_IPV6(address, address_str);
        LOG_IPV6(netmask, netmask_str);
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_ipv6_address:   address = %s", address_str));
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_ipv6_address:   netmask = %s", netmask_str));
    }
    
    /**
     * Concatinate:
     *    _____________      __________________
     *   |             |    |                  |
     *   | netif->ipv6 |===>| old ipv6 or NULL |
     *   |_____________|    |__________________|
     *    _____________      __________      __________________
     *   |             |    |          |    |                  |
     *   | netif->ipv6 |===>| new ipv6 |===>| old ipv6 or NULL |
     *   |_____________|    |__________|    |__________________|
     */
    ipv6            = netif_create_ipv6_alias();
    ipv6->next      = netif->ipv6;
    netif->ipv6     = ipv6;

    ipv6->address   = address   != NULL ? *address   : IPV6_ADDRESS_NULL;
    ipv6->netmask   = netmask   != NULL ? *netmask   : IPV6_ADDRESS_NULL;
    ipv6->state     = state;
    
    return true;
}

bool
netif_add_vlan(netif_t *netif, vlan_t *vlan)
{
    if (netif->vlan != NULL) {
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_WARNING, ("overwrite VLAN       vid = %u", netif->vlan->vid));
    }
    
    netif->vlan = vlan;
    
    return true;
}

bool
netif_add_ipv4_alias(netif_t *netif, ipv4_alias_t *ipv4)
{
    ipv4->next  = netif->ipv4;
    netif->ipv4 = ipv4;
    
    return true;
}

bool
netif_add_ipv6_alias(netif_t *netif, ipv6_alias_t *ipv6)
{
    ipv6->next  = netif->ipv6;
    netif->ipv6 = ipv6;
    
    return true;
}

static bool
netif_clear_receive_buffer(netif_t *netif)
{
    raw_packet_t        raw_packet;
    bool                running = true;
    uint32_t            counter = 0;
    ssize_t             len;

    raw_packet_init(&raw_packet);

    /* receive data from receive buffer until buffer is empty */
    while (running) {
        len = recv(netif->socket, raw_packet.data, sizeof(raw_packet.data), MSG_DONTWAIT);
        switch (len) {
            case -1:
                /* no data received */
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_DEBUG, ("receive buffer cleared!"));
                    return true;
                }

                /* other errors */
                LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_DEBUG, ("can't clear receive buffer: %s", strerror(errno)));
                running = false;
                break;

            case 0:
                /* peer closed connection */
                LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_DEBUG, ("can't clear receive buffer: Hey! Socket should be connectionless!"));
                running = false;
                break;

            default:
                /* handle received data */
                counter++;
                LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_DEBUG, ("receive buffer: clear frame nr. %u", counter));
                break;
        }
    }

    return false;
}

/**
 * @brief  This function is used to receive a Layer 2 RAW-Frame.
 */
bool
netif_frame_receive(netif_t *netif, raw_packet_t *raw_packet)
{
    if (netif_frame_select(netif, NETIF_SELECT_WAIT_USECS)) {
        if ((raw_packet->len = recv(netif->socket, raw_packet->data, ETH_MAX_FRAME_SIZE, 0 /* no flags */)) < 0) {
            LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_ERROR, ("can't receive packet: %s", strerror(errno)));
            return false;
        }
        return true;
    }

    return false;
}

/**
 * @brief
 */
bool
netif_frame_select(netif_t *netif, uint32_t timeout)
{
    fd_set              readfds;  /* list of monitored file descriptors */
    int                 numfds;   /* number of ready file descriptors */
    struct timeval      tv = {              /* time structure used in select() */
        .tv_sec  = 0,
        .tv_usec = timeout
    };

    FD_ZERO(&readfds);
    FD_SET(netif->socket, &readfds);

    /* wait until a "file descriptor" is ready (returns immediately after ready)
       or wait until time is up. Return value is number of ready
       "file descriptors", 0 (time is up) or -1 (error) */
    numfds = select(netif->socket + 1, &readfds, NULL, NULL, &tv);
    switch (numfds) {
        /* error */
        case -1:
            LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_ERROR, ("can't monitor socket: %s", strerror(errno)));
            return false;

        /* time up */
        case 0:
            break;

        /* fd ready */
        default:
            return true;
    }

    return false;
}

/**
 * @brief  sends layer 2 frame
 */
void
netif_frame_send(netif_t *netif, raw_packet_t *raw_packet)
{
    if (send(netif->socket, raw_packet->data, raw_packet->len, 0 /* no flags */) < 0) {
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_ERROR, ("can't send packet: %s", strerror(errno)));
    }
}
