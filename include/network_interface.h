#ifndef __NETWORK_INTERFACE_H__
#define __NETWORK_INTERFACE_H__

#include <stdint.h>
#include <stdbool.h>

#include "packet/raw_packet.h"
#include "packet/net_address.h"

#if __FreeBSD__

#elif __linux__
#include <linux/filter.h>
#endif

#define NETIF_NAME_SIZE             16

#define NETIF_FLAG_UP               0x00000000
#define NETIF_FLAG_PROMISCUOUS      0x00000000

typedef enum _ipv6_state_t {
    IPV6_STATE_INVALID              = 0x00,
    IPV6_STATE_TENTATIVE            = 0x08,
    IPV6_STATE_TENTATIVE_1          = 0x09, /* 1 probe sent */
    IPV6_STATE_TENTATIVE_2          = 0x0a, /* 2 probes sent */
    IPV6_STATE_TENTATIVE_3          = 0x0b, /* 3 probes sent */
    IPV6_STATE_TENTATIVE_4          = 0x0c, /* 4 probes sent */
    IPV6_STATE_TENTATIVE_5          = 0x0d, /* 5 probes sent */
    IPV6_STATE_TENTATIVE_6          = 0x0e, /* 6 probes sent */
    IPV6_STATE_TENTATIVE_7          = 0x0f, /* 7 probes sent */
    IPV6_STATE_VALID                = 0x10,
    IPV6_STATE_PREFERRED            = 0x30,
    IPV6_STATE_DEPRECATED           = 0x50,
} ipv6_state_t;

typedef struct _netif_list_t        netif_list_t;
typedef struct _netif_t             netif_t;

typedef struct _vlan_t              vlan_t;
typedef struct _ipv4_alias_t        ipv4_alias_t;
typedef struct _ipv6_alias_t        ipv6_alias_t;

struct _netif_list_t {
    uint32_t                size;
    netif_t                *head;
    netif_t                *tail;
};

struct _netif_t {
    char                    name[NETIF_NAME_SIZE];
    int                     index;
    mac_address_t           mac;
    uint32_t                flags;
    int                     socket;
    int                     dummy_socket;
    
    vlan_t                 *vlan;
    ipv4_alias_t           *ipv4;
    ipv6_alias_t           *ipv6;
    
    netif_t                *next;   /**< linked list */
};

struct _vlan_t {
    union {
        uint16_t        tci;            /* Tag Control Information */
        struct {
            uint16_t    vid : 12;       /* VLAN Identifier */
            uint16_t    dei : 1;        /* Drop Eligible Indicator (former CFI - Canonical Format Indicator) */
            uint16_t    pcp : 3;        /* Priority Code Point (= Priority) */
        };
    };
};

struct _ipv4_alias_t {
    ipv4_address_t          address;
    ipv4_address_t          broadcast;
    ipv4_address_t          netmask;
    ipv4_address_t          gateway;
    ipv4_alias_t           *next;   /**< linked list */
};

struct _ipv6_alias_t {
    ipv6_address_t          address;
    ipv6_address_t          netmask;
    uint8_t                 prefixlen;
    ipv6_state_t            state;
    ipv6_alias_t           *next;   /**< linked list */
};

bool                netif_list_init         (netif_list_t *list);
bool                netif_list_add          (netif_list_t *list, netif_t *netif);

bool                netif_init              (netif_t *netif, const char *name);
bool                netif_init_port         (netif_t *netif, const char *name, uint16_t port);
#if __FreeBSD__
bool                netif_init_bpf          (netif_t *netif, const char *name, uint16_t port, struct bpf_insn *filter, int filter_len);
#elif __linux__
bool                netif_init_bpf          (netif_t *netif, const char *name, uint16_t port, struct sock_filter *filter, int filter_len);
#endif
bool                netif_add_mac_address   (netif_t *netif, const mac_address_t *mac);

/* allocates structure internally */
bool                netif_add_vid           (netif_t *netif, const uint16_t vid);
bool                netif_add_ipv4_address  (netif_t *netif, const ipv4_address_t *address, const ipv4_address_t *netmask, const ipv4_address_t *broadcast, const ipv4_address_t *gateway);
bool                netif_add_ipv6_address  (netif_t *netif, const ipv6_address_t *address, const ipv6_address_t *netmask, const ipv6_state_t state);

/* pass reference to structure. structure allocation must be externally made */
bool                netif_add_vlan          (netif_t *netif, vlan_t *vlan);
bool                netif_add_ipv4_alias    (netif_t *netif, ipv4_alias_t *ipv4);
bool                netif_add_ipv6_alias    (netif_t *netif, ipv6_alias_t *ipv6);

static inline bool  netif_frame_ready       (netif_t *netif);
bool                netif_frame_select      (netif_t *netif, uint32_t timeout);
bool                netif_frame_receive     (netif_t *netif, raw_packet_t *raw_packet);
void                netif_frame_send        (netif_t *netif, raw_packet_t *raw_packet);


static inline bool
netif_frame_ready(netif_t *netif) {
    return netif_frame_select(netif, 0);
}

#endif

