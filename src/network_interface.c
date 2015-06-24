#include "packet/network_interface.h"
#include "log.h"
#include "log_network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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
#include <linux/if_link.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#endif

#include <ifaddrs.h>

#define INADDR(x)   ((struct sockaddr_in  *) x)
#define INADDR6(x)  ((struct sockaddr_in6 *) x)
#define LADDR(x)    ((struct sockaddr_dl  *) x)
#if __linux__
#define LLADDR(x)   ((struct sockaddr_ll  *) x)
#endif

static vlan_t       *netif_create_vlan(void);
static ipv4_alias_t *netif_create_ipv4_alias(void);
static ipv6_alias_t *netif_create_ipv6_alias(void);

bool
netif_init(netif_t *netif, const char *name)
{
    bool                        result = true;
    int                         sockfd;
    struct ifaddrs             *ifas;
    struct ifaddrs             *ifa;
    struct ifreq                ifr;

#if __FreeBSD__
    struct vlanreq              vreq;
#elif __linux__
    struct rtnl_link_stats     *stats;
    struct vlan_ioctl_args      ifv;
#endif

    
    /* string copy name */
    strncpy(netif->name, name, NETIF_NAME_SIZE);
    
    /* set to zero */
    memcpy(netif->mac.addr, MAC_ADDRESS_NULL.addr, MAC_ADDRESS_LEN);
    netif->vlan = NULL;
    netif->ipv4 = NULL;
    netif->ipv6 = NULL;
    
    /* create socket (required for ioctl) */
    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
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

                                bzero((char *) &ifr, sizeof(ifr));
                                strncpy(ifr.ifr_name, netif->name, NETIF_NAME_SIZE);
                                if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != -1) {
                                    netif_add_mac_address(netif,   MAC_ADDRESS(LLADDR(LADDR(ifr.ifr_hwaddr.sa_data))));
                                    bzero((char *) &ifv, sizeof(ifv));
                                    ifv.cmd = GET_VLAN_VID_CMD;
                                    strncpy(ifv.device1, netif->name, sizeof(ifv.device1));
                                    if (ioctl(sockfd, SIOCGIFVLAN, &ifv) != -1) {
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
    
    ipv4 = netif_create_ipv4_alias();
    ipv4->next  = netif->ipv4;
    netif->ipv4 = ipv4;
    
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
    
    ipv6 = netif_create_ipv6_alias();
    ipv6->next  = netif->ipv6;
    netif->ipv6 = ipv6;
    
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

