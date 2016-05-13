#ifndef __ARP_TABLE_H__
#define __ARP_TABLE_H__

#include <stdint.h>
#include <stdbool.h>

#include "packet/packet.h"
#include "packet/net_address.h"
#include "network_interface.h"

#define ARP_TABLE_TASK_REFRESH     1000        /**< refresh timeout: 1 sec. */
#define ARP_TABLE_MAX_ENTRIES      128         /**< maximal number of entries */
#define ARP_TABLE_MAX_CB_MULTIPLY  5           /**< cb entries multiplier */



typedef enum _node_address_state_t {
    NODE_ADDRESS_STATE_INCOMPLETE,
    NODE_ADDRESS_STATE_PROBE,
    NODE_ADDRESS_STATE_REACHABLE,
    NODE_ADDRESS_STATE_FAILED,
    NODE_ADDRESS_STATE_STATIC
} node_address_state_t;

typedef struct _node_address_t {
    netif_t                    *netif;
    node_address_state_t        state;
    mac_address_t               mac;
    ipv4_address_t              ipv4;
} node_address_t;

/**
 * Callback function
 *
 * @param   param               argument
 * @param   state               current ARP entry state
 * @param   ipv4_subnet         IPv4 subnet address
 * @param   ipv4_slave          IPv4 slave address
 * @param   mac                 updated MAC address
 */
//typedef void (*arp_table_callback_fn) (mac_address_t *mac, ipv4_address_t *ipv4, void *param);
typedef void (*arp_table_callback_fn) (node_address_t *addr, void *param);


/**
 * ARP Entry Callback
 */
typedef struct _arp_entry_cb_t arp_entry_cb_t;
struct _arp_entry_cb_t {
    uint16_t                    idx;                    /**< index in the array */
    uint16_t                    xxx;                    /**< 32-bit alignment */
    arp_table_callback_fn  callback;               /**< callback function to call if updated */
    void                       *param;                  /**< parameter passed to callback function */
    arp_entry_cb_t        *next;                   /**< next fn in list */
};

/**
 * ARP Entry
 */
typedef struct _arp_entry_t {
    node_address_t              addr;
    ipv4_address_t              ipv4_gateway;

    arp_entry_cb_t        *cb_start;               /**< Address of first callback */
} arp_entry_t;

/**
 * ARP LUT Entry
 *
 * if a LUT entry exists an ARP entry exits, too.
 */
typedef struct _arp_lut_entry_t {
    netif_t                    *netif;
    ipv4_address_t              ipv4;                   /**< IPv4 address that is sorted */
    uint16_t                    idx;                    /**< array index of ARP entry */
    uint32_t                    timestamp;              /**< time of last update */
    uint32_t                    retry_count;            /**< when a timeout is reached, increase retry counter */
} arp_lut_entry_t;

/**
 * ARP Table
 */
typedef struct _arp_table_t {

    arp_lut_entry_t        lut_entry[ARP_TABLE_MAX_ENTRIES];
    uint16_t                    lut_entry_size;
    arp_entry_t            arp_entry[ARP_TABLE_MAX_ENTRIES];
    uint16_t                    arp_entry_size;

    /* callback management */
    arp_entry_cb_t         arp_entry_cb[ARP_TABLE_MAX_CB_MULTIPLY * ARP_TABLE_MAX_ENTRIES];                  /**< array of CB structs */
    uint16_t                    arp_entry_cb_size;                                                                          /**< size of the CB struct array; how many are actually used */
    uint16_t                    arp_entry_cb_available_idx[ARP_TABLE_MAX_CB_MULTIPLY * ARP_TABLE_MAX_ENTRIES];    /**< index array: list all available CBs */
    uint16_t                    arp_entry_cb_available_idx_size;                                                            /**< size of the index array */

} arp_table_t;

bool    arp_table_init                 (arp_table_t *arp_table);
bool    arp_table_gratuitous_arp_send  (arp_table_t *arp_table, netif_t *netif, uint16_t oper);
void    arp_table_log                  (arp_table_t *arp_table);
void    arp_table_log_lut_entries      (arp_table_t *arp_table);
void    arp_table_log_arp_entries      (arp_table_t *arp_table);
bool    arp_table_node_register        (arp_table_t *arp_table, node_address_t *addr, arp_table_callback_fn callback, void *param);
bool    arp_table_node_unregister      (arp_table_t *arp_table, node_address_t *addr, arp_table_callback_fn callback);
bool    arp_table_update_entry         (arp_table_t *arp_table, netif_t *netif, ipv4_address_t *ipv4, const mac_address_t *mac); /* true = update also slave table, false = no entry in LUT found --> dischard */
bool    arp_table_reply_request        (arp_table_t *arp_table, netif_t *netif, packet_t *request, packet_t *response);


const char *log_node_address_state     (node_address_state_t state);

#endif
