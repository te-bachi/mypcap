#ifndef __CONFIG_FILE_H__
#define __CONFIG_FILE_H__

#include <stdint.h>
#include <stdbool.h>

#include "packet/net_address.h"

#define CONFIG_FILE_LINE_SIZE       128+1

#define CONFIG_NETIF_NAME_MAX_SIZE  16
#define CONFIG_NETIF_MAX_SIZE       1
#define CONFIG_VLAN_MAX_SIZE        8
#define CONFIG_PTP_SLAVE_MAX_SIZE   32
#define CONFIG_NTP_CLIENT_MAX_SIZE  32

typedef struct _config_t            config_t;
typedef struct _config_netif_t      config_netif_t;
typedef struct _config_vlan_t       config_vlan_t;
typedef struct _config_ptp_t        config_ptp_t;
typedef struct _config_ntp_t        config_ntp_t;
typedef struct _config_gateway_t    config_gateway_t;
typedef struct _config_ptp_node_t   config_ptp_node_t;
typedef struct _config_ntp_peer_t   config_ntp_peer_t;

struct _config_ntp_peer_t {
    mac_address_t                   mac_address;
    ipv4_address_t                  ipv4_address;
};

struct _config_ptp_node_t {
    mac_address_t                   mac_address;
    ipv4_address_t                  ipv4_address;
};

struct _config_gateway_t {
    mac_address_t                   mac_address;
    ipv4_address_t                  ipv4_address;
    bool                            active;
};

struct _config_ptp_t {
    uint16_t                        domain;
    config_ptp_node_t               server;
    config_ptp_node_t               slave[CONFIG_PTP_SLAVE_MAX_SIZE];
    uint32_t                        slave_size;
};

struct _config_ntp_t {
    bool                            adva_tlv;
    config_ntp_peer_t               server;
    config_ntp_peer_t               client[CONFIG_NTP_CLIENT_MAX_SIZE];
    uint32_t                        client_size;
};

struct _config_vlan_t {
    uint16_t                        vid;
    bool                            gateway_configured;
    bool                            ptp_configured;
    bool                            ntp_configured;
    config_gateway_t                gateway;
    config_ptp_t                    ptp;
    config_ntp_t                    ntp;
};

struct _config_netif_t {
    char                            name[CONFIG_NETIF_NAME_MAX_SIZE];
    config_vlan_t                   vlan[CONFIG_VLAN_MAX_SIZE];
    uint32_t                        vlan_size;
};

struct _config_t {
    config_netif_t                  netif[CONFIG_VLAN_MAX_SIZE];
    uint32_t                        netif_size;
};

typedef enum _config_line_result_t {
    CONFIG_LINE_NONE = 0,
    CONFIG_LINE_EOL,
    CONFIG_LINE_TOKEN,
    CONFIG_LINE_ERROR
} config_line_result_t;

typedef struct _config_line_t config_line_t;
struct _config_line_t {
    char            text[CONFIG_FILE_LINE_SIZE];    /* line data */
    uint32_t        number;                         /* line number */
    uint32_t        length;                         /* length of line */
    uint32_t        position;                       /* current position in line */
    uint32_t        saved_position;                 /* saved position in line before next token */
};

typedef struct _config_token_t config_token_t;
struct _config_token_t {
    char            text[CONFIG_FILE_LINE_SIZE];
    uint32_t        position;
};

bool config_file_parse(const char *filename, config_t *config);

#endif

