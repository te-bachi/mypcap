#include "arp_table.h"
#include "log.h"
#include "log_network.h"

#include "packet/packet.h"

#include <inttypes.h>

#define ARP_ENTRY_TIME_THRESHOLD   30000       /**< refresh entry after 60 sec. */

#define ARP_ENTRY_TIMEOUT_SHORT    1000
#define ARP_ENTRY_TIMEOUT_MIDDLE   7000
#define ARP_ENTRY_TIMEOUT_LONG     20000

#define ARP_ENTRY_MAX_RETRY_SHORT  3
#define ARP_ENTRY_MAX_RETRY_MIDDLE 6

#define ARP_TABLE_FLAGS_NONE               0x00
#define ARP_TABLE_FLAGS_UPDATE_MAC_ADDRESS 0x01
#define ARP_TABLE_FLAGS_CALL_CALLBACK      0x02

/**
 *   LUT table (sorted)
 *   _______ _____ _____________ _________________ ___________
 *  |       |     |             |                 |           |
 *  | Index | VID |IPv4 Address | ARP Entry Index | Timestamp |
 *  |_______|_____|_____________|_________________|___________|
 *  |   0   |  0  | 10.0.0.1    |        0        |           |
 *  |   1   |  0  | 10.0.0.5    |        5        |           |
 *  |   2   |  0  | 10.0.10.10  |       10        |           |
 *  |   3   |  0  | 10.0.10.11  |       11        |           |
 *  |   4   |  0  | 10.0.10.12  |       12        |           |
 *  |   5   |  1  | 10.0.0.1    |        0        |           |
 *  |   6   |  1  | 10.0.0.5    |        5        |           |
 *  |   7   |  1  | 10.0.10.10  |       10        |           |
 *  |   8   |  1  | 10.0.10.11  |       11        |           |
 *  |   9   |  1  | 10.0.10.12  |       12        |           |
 *  |_______|_____|_____________|_________________|___________|
 *
 *   ARP table (unsort)
 *   _______ _____ _____________ ______________ _____________
 *  |       |     |             |              |             |
 *  | Index | VID | MAC address | IPv4 Gateway | IPv4 Slave  |
 *  |_______|_____|_____________|______________|_____________|
 *  |   0   | 0   | 01:02:03:.. | 10.0.0.1     | 192.168.0.4 | <-- Slave in another subnet
 *  |   1   | 0   | 01:02:03:.. | 10.0.0.1     | 192.168.0.2 |     using gateway 10.0.0.1
 *  |   2   | 0   | 01:02:03:.. | 10.0.0.1     | 192.168.0.3 |
 *  |   3   | 0   | 01:02:03:.. | 10.0.0.1     | 192.168.0.1 |
 *  |   4   | 0   | 01:02:03:.. | 10.0.0.1     | 192.168.0.5 |
 *  |   5   | 0   | aa:bb:cc:.. | 10.0.0.5     | 14.50.0.20  | <-- Slave in another subnet
 *  |   6   | 0   | aa:bb:cc:.. | 10.0.0.5     | 14.50.0.24  |     using gateway 10.0.0.5
 *  |   7   | 0   | aa:bb:cc:.. | 10.0.0.5     | 14.50.0.22  |
 *  |   8   | 0   | aa:bb:cc:.. | 10.0.0.5     | 14.50.0.23  |
 *  |   9   | 0   | aa:bb:cc:.. | 10.0.0.5     | 14.50.0.21  |
 *  |  10   | 0   | ff:00:01:.. | 10.0.10.10   | 10.0.10.11  | <-- Slave in the same subnet
 *  |  11   | 0   | ff:00:02:.. | 10.0.10.11   | 10.0.10.10  |
 *  |  12   | 0   | ff:00:03:.. | 10.0.10.12   | 10.0.10.12  |
 *  |  13   | 1   | ee:ff:01:.. | 10.0.0.1     | 192.168.0.4 |
 *  |  14   | 1   | dd:ee:99:.. | 10.0.0.5     | 14.50.0.20  |
 *  |  15   | 1   | cc:dd:01:.. | 10.0.10.10   | 10.0.10.11  |
 *  |  16   | 1   | cc:dd:02:.. | 10.0.10.11   | 10.0.10.10  |
 *  |  17   | 1   | cc:dd:03:.. | 10.0.10.12   | 10.0.10.12  |
 *  |_______|_____|_____________|______________|_____________|
 *                                                   ^
 *                                                   |
 *                                   This column is used to update a slave
 *                                   table entry (update MAC address)
 */

static arp_entry_cb_t *arp_table_cb_alloc             (arp_table_t *arp_table);
static void                 arp_table_cb_free              (arp_table_t *arp_table, arp_entry_cb_t *cb);

static bool                 arp_table_calc_subnet          (arp_table_t *arp_table, node_address_t *addr, ipv4_address_t *ipv4_gateway);
static void                 arp_table_update_arp_entries   (arp_table_t *arp_table, uint16_t idx_lut_entry, const mac_address_t *mac, node_address_state_t state, uint32_t flags);
static bool                 arp_table_entry_create         (arp_table_t *arp_table, netif_t *netif, uint16_t *idx_lut_entry, uint16_t *idx_arp_entry, ipv4_address_t *ipv4_gateway);
static bool                 arp_table_entry_append         (arp_table_t *arp_table, netif_t *netif, uint16_t idx_lut_entry, uint16_t *idx_arp_entry, node_address_t *addr, bool *already_registered);
static bool                 arp_table_entry_remove         (arp_table_t *arp_table, uint16_t idx_lut_entry, node_address_t *addr, arp_table_callback_fn callback);
static int8_t               arp_table_lut_compare          (arp_table_t *arp_table, int16_t idx, netif_t *netif, ipv4_address_t *ipv4_gateway);
static uint16_t             arp_table_lut_ipv4_search      (arp_table_t *arp_table, netif_t *netif, ipv4_address_t *ipv4_gateway, arp_lut_entry_t **lut_entry);
//static bool                 arp_table_task_refresh         (void *ref, void *param);
static bool                 arp_table_send_request         (arp_table_t *arp_table, netif_t *netif, arp_lut_entry_t *lut_entry, arp_entry_t *arp_entry);

bool
arp_table_init(arp_table_t *arp_table)
{
    uint16_t idx;

    arp_table->lut_entry_size                    = 0;
    arp_table->arp_entry_size                    = 0;

    arp_table->arp_entry_cb_size                 = 0;
    arp_table->arp_entry_cb_available_idx_size   = sizeof(((arp_table_t *)0)->arp_entry_cb_available_idx) / sizeof(uint16_t);

    /* put entry index into entry to fill it back when freed (available indexes) */
    for (idx = 0; idx < arp_table->arp_entry_cb_available_idx_size; idx++) {
        arp_table->arp_entry_cb_available_idx[idx] = idx;
        arp_table->arp_entry_cb[idx].idx = idx;
    }

    return true;
}

void
arp_table_log(arp_table_t *arp_table)
{
    uint32_t i;
    uint32_t k;

    /* iterate over LUT entries */
    LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("LUT table size = %" PRIu16, arp_table->lut_entry_size));
    for (i = 0; i < arp_table->lut_entry_size; i++) {
        LOG_IPV4(&(arp_table->lut_entry[i].ipv4), ipv4_gateway_str);
        LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("[%2" PRIu32 "] %-15s idx=%" PRIu16 " %-15s", i, ipv4_gateway_str, arp_table->lut_entry[i].idx, log_node_address_state(arp_table->arp_entry[arp_table->lut_entry[i].idx].addr.state)));

        /* for every LUT entry, print all corresponding ARP entries */
        k = arp_table->lut_entry[i].idx;
        do {
            LOG_IPV4(&(arp_table->arp_entry[k].addr.ipv4), ipv4_slave_str);
            LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("    [%2" PRIu32 "] %-15s", k, ipv4_slave_str));
            k++;
        } while (k < arp_table->arp_entry_size &&
                arp_table->arp_entry[k - 1].addr.netif->vlan->vid == arp_table->arp_entry[k].addr.netif->vlan->vid &&
                ipv4_address_equal(&(arp_table->arp_entry[k - 1].ipv4_gateway), &(arp_table->arp_entry[k].ipv4_gateway)));
    }
}

void
arp_table_log_lut_entries(arp_table_t *arp_table)
{
    uint32_t i;

    /* iterate over LUT entries */
    LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("LUT table size = %" PRIu16, arp_table->lut_entry_size));
    for (i = 0; i < arp_table->lut_entry_size; i++) {
        LOG_IPV4(&(arp_table->lut_entry[i].ipv4), ipv4_gateway_str);
        LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("[%2" PRIu32 "] %s idx=%" PRIu16, i, ipv4_gateway_str, arp_table->lut_entry[i].idx));
    }
}

void
arp_table_log_arp_entries(arp_table_t *arp_table)
{
    uint32_t i;

    /* iterate over LUT entries */
    LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("ARP table size = %" PRIu16, arp_table->arp_entry_size));
    for (i = 0; i < arp_table->arp_entry_size; i++) {
        LOG_IPV4(&(arp_table->arp_entry[i].ipv4_gateway), ipv4_gateway_str);
        LOG_IPV4(&(arp_table->arp_entry[i].addr.ipv4),  ipv4_slave_str);
        LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("[%2" PRIu32 "] %-15s %-15s %s", i, ipv4_gateway_str, ipv4_slave_str, log_node_address_state(arp_table->arp_entry[i].addr.state)));
    }
}

/**
 * Calculate if the IPv4 address 'addr' is in the same subnet as the master or
 * if not, how to find a gateway to that address.
 *
 * @param   addr                node address to calculate if it's in the same or a different subnet
 * @param   ipv4_gateway        returns the corresponding IPv4 address that is directly connected to the master
 * @return                      true if the function found a gateway or is directly connected, false otherwise
 */
static bool
arp_table_calc_subnet(arp_table_t *arp_table, node_address_t *addr, ipv4_address_t *ipv4_gateway)
{
//    netif_t                    *netif = addr->netif;
//    ipv4_address_t              node_net;
//    ipv4_address_t              gateway_net;
//
//    /* compute slave network */
//    node_net.addr32     = addr->ipv4.addr32         & netif->ipv4.netmask.addr32;
//
//    /* compute gateway network */
//    gateway_net.addr32  = netif->ipv4.gateway.addr32 & netif->ipv4.netmask.addr32;

//    if (LOG_ENABLE(LOG_ARP_TABLE, LOG_DEBUG)) {
//        LOG_IPV4(&(netif->ipv4.subnet), local_net_str);
//        LOG_IPV4(&node_net,        slave_net_str);
//        LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("calc subnet of IPv4 node: port net = %s, slave net = %s", local_net_str, slave_net_str));
//    }
//
//    /* in the same network => use direct */
//    if (ipv4_address_equal(&(node_net), &(netif->ipv4.subnet))) {
//        LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("calc subnet of IPv4 node: in the same network!"));
//        *ipv4_gateway = addr->ipv4;
//
//    /* in another network + gateway set => use default gateway */
//    } else if (ipv4_address_equal(&(gateway_net), &(netif->ipv4.subnet))) {
//        LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("calc subnet of IPv4 node: in another network => use custom gateway!"));
//        *ipv4_gateway = netif->ipv4.gateway;
//
//    /* gateway in another network !? => complain */
//    } else {
//        LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("calc subnet of IPv4 node: gateway in another network => no route to gateway"));
//        return false;
//    }

    return true;
}

/**
 * Register a new node or replace an existing node with state and callback functions
 *
 * @param   addr                a
 * @param   arp_table_callback  a
 * @param   param               a
 * @return                      a
 */
bool
arp_table_node_register(arp_table_t *arp_table, node_address_t *addr, arp_table_callback_fn callback, void *param)
{

    ipv4_address_t              ipv4_gateway;

    arp_entry_t           *arp_entry;
    arp_lut_entry_t       *lut_entry = NULL;
    arp_entry_cb_t        *arp_entry_cb;
    uint16_t                    idx_arp_entry;
    uint16_t                    idx_lut_entry;
    bool                        already_registered = false;

    /* */
    if (!arp_table_calc_subnet(arp_table, addr, &ipv4_gateway)) {
        return false;
    }

    /* is the gateway IPv4 address already in the lookup-table (LUT) ? */
    idx_lut_entry = arp_table_lut_ipv4_search(arp_table, addr->netif, &(ipv4_gateway), &lut_entry);

    /* found => prepend new ARP entry from current index  */
    if (lut_entry != NULL) {
        /* returns the index of the newly created ARP entry (= idx_arp_entry) */
        if (!arp_table_entry_append(arp_table, addr->netif, idx_lut_entry, &idx_arp_entry, addr, &already_registered)) {
            return false;
        }

    /* not found => create new ARP entry + LUT entry */
    } else {
        /* returns the index of the newly created LUT- (= idx_lut_entry) and ARP entry (= idx_arp_entry) */
        if (!arp_table_entry_create(arp_table, addr->netif, &idx_lut_entry, &idx_arp_entry, &(ipv4_gateway))) {
            return false;
        }
    }

    /* get ARP entry from ARP table*/
    lut_entry       = &(arp_table->lut_entry[idx_lut_entry]);
    arp_entry       = &(arp_table->arp_entry[idx_arp_entry]);

    arp_entry_cb    = arp_table_cb_alloc(arp_table);
    if (arp_entry_cb == NULL) {
        LOG_PRINTLN(LOG_ARP_TABLE, LOG_ERROR, ("no more ARP entry callback structs allowed!"));
        return false; //
    }

    arp_entry_cb->callback  = callback;
    arp_entry_cb->param     = param;
    arp_entry_cb->next      = NULL;

    /* node NOT already registered? */
    if (!already_registered) {

        /* increment ARP entry size */
        arp_table->arp_entry_size++;

        arp_entry->addr                 = *addr;
        arp_entry->addr.state           = NODE_ADDRESS_STATE_INCOMPLETE;
        arp_entry->ipv4_gateway         = ipv4_gateway;

        arp_entry->cb_start             = arp_entry_cb;
        //arp_entry->cb_count            = 1;

    /* only if node is already registered... */
    } else {
        arp_entry_cb_t     *arp_entry_cb_last;

        /* go to the last callback entry */
        arp_entry_cb_last = arp_entry->cb_start;
        while (arp_entry_cb_last->next != NULL) {
            arp_entry_cb_last = arp_entry_cb_last->next;
        };
        arp_entry_cb_last->next = arp_entry_cb;

        /* increment callback count */
        // arp_entry->cb_count++;

        /* ... call specific callback function */
        // TODO: callback list
        //(*entry_cb)(&(arp_entry->addr), *entry_param);
    }

    /* register the first time an IPv4 gateway address (timestamp == 0) => send ARP request */
    if (lut_entry->timestamp == 0) {
        if (!arp_table_send_request(arp_table, addr->netif, lut_entry, arp_entry)) {
            return false;
        }
    }

    return true;
}

bool
arp_table_node_unregister(arp_table_t *arp_table, node_address_t *addr, arp_table_callback_fn callback)
{
    ipv4_address_t              ipv4_gateway;
    arp_lut_entry_t       *lut_entry = NULL;
    uint16_t                    idx_lut_entry;

    if (LOG_ENABLE(LOG_ARP_TABLE, LOG_INFO)) {
        LOG_IPV4(&(addr->ipv4), ipv4_node_str);
        LOG_PRINTLN(LOG_ARP_TABLE, LOG_INFO, ("unregistering %s ...", ipv4_node_str));
    }

    /* if calculation of subnet fails, return */
    if (!arp_table_calc_subnet(arp_table, addr, &ipv4_gateway)) {
        return false;
    }

    /* is the gateway address already in the lookup-table (LUT) ? */
    idx_lut_entry = arp_table_lut_ipv4_search(arp_table, addr->netif, &(ipv4_gateway), &lut_entry);

    /* found => remove ARP entry from current index  */
    if (lut_entry != NULL) {
        if (!arp_table_entry_remove(arp_table, idx_lut_entry, addr, callback)) {
            if (LOG_ENABLE(LOG_ARP_TABLE, LOG_ERROR)) {
                LOG_IPV4(&ipv4_gateway, ipv4_gateway_str);
                LOG_PRINTLN(LOG_ARP_TABLE, LOG_ERROR, ("can't remove registered %s!", ipv4_gateway_str));
            }

            return false;
        }
    /* not found => fail! */
    } else {
        if (LOG_ENABLE(LOG_ARP_TABLE, LOG_WARNING)) {
            LOG_IPV4(&ipv4_gateway, ipv4_gateway_str);
            LOG_PRINTLN(LOG_ARP_TABLE, LOG_WARNING, ("unregistering %s, but it's not registered!", ipv4_gateway_str));
        }
        return false;
    }
    LOG_PRINTLN(LOG_ARP_TABLE, LOG_INFO, ("... done!"));

    return true;
}

/**
 * Updates a LUT entry and the linked ARP entries. Called from PTP port or packet analyzer.
 *
 * @param   ipv4_gateway        directly connected IPv4 address (in the same subnet as the master),
 *                              that sends back an ARP response
 * @param   mac                 MAC address to the corresponding IPv4 address in an ARP response
 */
bool
arp_table_update_entry(arp_table_t *arp_table, netif_t *netif, ipv4_address_t *ipv4_gateway, const mac_address_t *mac)
{
    arp_lut_entry_t   *lut_entry = NULL;
    uint16_t                idx_lut_entry;

//    /* is the gateway address already in the lookup-table (LUT) ? */
//    idx_lut_entry = arp_table_lut_ipv4_search(arp_table, netif, ipv4_gateway, &lut_entry);

    /* found => assign MAC address + call callback function for every ARP entry */
    if (lut_entry != NULL) {
//        /* update timestamp */
//        lut_entry->timestamp = interval_timer_hal_get_milliseconds() + ARP_ENTRY_TIME_THRESHOLD;

        /* reset retry counter */
        lut_entry->retry_count = 0;

        /* update all ARP entries */
        arp_table_update_arp_entries(arp_table, idx_lut_entry, mac, NODE_ADDRESS_STATE_REACHABLE,
                                          ARP_TABLE_FLAGS_UPDATE_MAC_ADDRESS | ARP_TABLE_FLAGS_CALL_CALLBACK);
    /* not found => return */
    } else {
        if (LOG_ENABLE(LOG_ARP_TABLE, LOG_INFO)) {
            LOG_IPV4(ipv4_gateway, ipv4_gateway_str);
            LOG_PRINTLN(LOG_ARP_TABLE, LOG_INFO, ("%s is not known in the ARP table", ipv4_gateway_str));
        }
        return false;
    }

    return true;
}


// TODO: callback list

static arp_entry_cb_t *
arp_table_cb_alloc(arp_table_t *arp_table)
{
    arp_entry_cb_t    *arp_entry_cb = NULL;
    uint16_t                idx;

    if (arp_table->arp_entry_cb_available_idx_size > 0) {
        idx             = arp_table->arp_entry_cb_available_idx[arp_table->arp_entry_cb_available_idx_size - 1];  /**< roll up from behind */
        arp_entry_cb    = &arp_table->arp_entry_cb[idx];                                                         /**< sizeof(arp_entry_cb_t) should be 32-bit aligned */
        arp_table->arp_entry_cb_available_idx_size--;
    }

    return arp_entry_cb;
}

static void
arp_table_cb_free(arp_table_t *arp_table, arp_entry_cb_t *cb)
{
    arp_table->arp_entry_cb_available_idx[arp_table->arp_entry_cb_available_idx_size] = cb->idx;
    arp_table->arp_entry_cb_available_idx_size++;

}

/**
 * Updates all ARP entries of a specific LUT entry
 *
 * @param   idx_lut_entry       a
 * @param   mac                 a
 * @param   state               a
 * @param   flags               a
 */
static void
arp_table_update_arp_entries(arp_table_t *arp_table, uint16_t idx_lut_entry, const mac_address_t *mac, node_address_state_t state, uint32_t flags)
{
    arp_lut_entry_t   *lut_entry = &(arp_table->lut_entry[idx_lut_entry]);
    arp_entry_t       *arp_entry;
    arp_entry_cb_t    *arp_entry_cb;
    uint16_t                idx_arp_entry;

    idx_arp_entry = lut_entry->idx;
    do {
        arp_entry = &(arp_table->arp_entry[idx_arp_entry]);

        /* update state */
        arp_entry->addr.state   = state;

        /* update MAC address */
        if (state == NODE_ADDRESS_STATE_FAILED) {
            /* reset MAC address */
            arp_entry->addr.mac  = MAC_ADDRESS_NULL;
        } else if (flags & ARP_TABLE_FLAGS_UPDATE_MAC_ADDRESS) {
            arp_entry->addr.mac = *mac;
        }

        /* call callback function */
        if (flags & ARP_TABLE_FLAGS_CALL_CALLBACK) {

            if (LOG_ENABLE(LOG_ARP_TABLE, LOG_INFO)) {
                LOG_IPV4(&(arp_entry->ipv4_gateway), ipv4_gateway_str);
                LOG_IPV4(&(arp_entry->addr.ipv4),    ipv4_node_str);
                LOG_PRINTLN(LOG_ARP_TABLE, LOG_INFO, ("update node address: gateway = %-16s node = %-16s state = %-10s",
                                                                      ipv4_gateway_str,
                                                                      ipv4_node_str,
                                                                      log_node_address_state(arp_entry->addr.state)));
            }

            /* start from ARP entry */
            arp_entry_cb = arp_entry->cb_start;
            while (arp_entry_cb != NULL) {

                /* call callback */
                arp_entry_cb->callback(&(arp_entry->addr), arp_entry_cb->param);

                /* next in list */
                arp_entry_cb = arp_entry_cb->next;
            };
        }

        idx_arp_entry++;
    } while (idx_arp_entry < arp_table->arp_entry_size &&
             arp_table->arp_entry[idx_arp_entry - 1].addr.netif->vlan->vid == arp_table->arp_entry[idx_arp_entry].addr.netif->vlan->vid &&
             ipv4_address_equal(&(arp_table->arp_entry[idx_arp_entry - 1].ipv4_gateway),
                                &(arp_table->arp_entry[idx_arp_entry].ipv4_gateway)));
}

/**
 * Create a LUT entry and an ARP entry in one shot.
 *
 * Example:
 *
 * Before:
 *
 *   LUT table (sorted)
 *   _______ ______________ _________________
 *  |       |              |                 |
 *  | Index | IPv4 Address | ARP Entry Index |
 *  |_______|______________|_________________|
 *  |   0   |  10.0.0.1    |        0        |
 *  |   1   |  10.0.0.5    |        1        |
 *  |_______|______________|_________________|
 *
 *   ARP table (unsorted)
 *   _______ _____________ ______________ _____________
 *  |       |             |              |             |
 *  | Index | MAC address | IPv4 Gateway | IPv4 Slave  |
 *  |_______|_____________|______________|_____________|
 *  |   0   | 01:02:03:.. | 10.0.0.1     | 192.168.0.5 |
 *  |   1   | aa:bb:cc:.. | 10.0.0.5     | 14.50.0.20  |
 *  |_______|_____________|______________|_____________|
 *
 * New/Changed:
 *
 *   ARP entry
 *    | Index | MAC address | IPv4 Gateway | IPv4 Slave  |
 *   *|   2   | 00:00:00:.. | 10.0.0.4     | 60.0.22.33  |* <== ARP index at the end of the list
 *
 *   LUT entry
 *    | Index | IPv4 Address | ARP Entry Index |
 *   *|   1   |  10.0.0.4    |        2        |* <== LUT index of the last search is used
 *    |  *2*  |  10.0.0.5    |        1        |  <== Subsequent LUT entries are moved down
 *
 * Afterwards:
 *
 *   LUT table (sorted)
 *   _______ ______________ _________________
 *  |       |              |                 |
 *  | Index | IPv4 Address | ARP Entry Index |
 *  |_______|______________|_________________|
 *  |   0   |  10.0.0.1    |        0        |
 *  |   1   |  10.0.0.4    |        2        |
 *  |   2   |  10.0.0.5    |        1        |
 *  |_______|______________|_________________|
 *
 *   ARP table (unsorted)
 *   _______ _____________ ______________ _____________
 *  |       |             |              |             |
 *  | Index | MAC address | IPv4 Gateway | IPv4 Slave  |
 *  |_______|_____________|______________|_____________|
 *  |   0   | 01:02:03:.. | 10.0.0.1     | 192.168.0.5 |
 *  |   1   | aa:bb:cc:.. | 10.0.0.5     | 14.50.0.20  |
 *  |   2   | 00:00:00:.. | 10.0.0.4     | 60.0.22.33  |
 *  |_______|_____________|______________|_____________|
 *
 *
 */
static bool
arp_table_entry_create(arp_table_t *arp_table, netif_t *netif, uint16_t *idx_lut_entry, uint16_t *idx_arp_entry, ipv4_address_t *ipv4_gateway) /**< caution: 'idx_arp_entry' is not the same as 'idx_lut_entry' */
{
    arp_lut_entry_t  *lut_entry;

    /* maximal size reached? */
    if (arp_table->arp_entry_size >= ARP_TABLE_MAX_ENTRIES || arp_table->lut_entry_size >= ARP_TABLE_MAX_ENTRIES) {
        LOG_PRINTLN(LOG_ARP_TABLE, LOG_ERROR, ("can't create new entries: ARP table is full."));
        return false;
    }

    /* use a not used ARP entry => create new ARP entry index */
    *idx_arp_entry           = arp_table->arp_entry_size;

    /* squeeze in LUT entry */
    if (arp_table->lut_entry_size > 0) {
        /* fine adjust: compare existing lut entry with new one */
        if (arp_table_lut_compare(arp_table, *idx_lut_entry, netif, ipv4_gateway) > 0) {
            /* if it's after the existing lut entry => increment search-index by one */
            (*idx_lut_entry)++;
        }

        /* shift all entries between LUT entry index and table size by one */
        for (uint16_t idx = arp_table->lut_entry_size; idx > *idx_lut_entry; idx--) {
            arp_table->lut_entry[idx] = arp_table->lut_entry[idx - 1];
        }
    }

    /* create LUT entry */
    lut_entry              = &(arp_table->lut_entry[*idx_lut_entry]);
    lut_entry->netif       = netif;
    lut_entry->ipv4        = *ipv4_gateway;
    lut_entry->idx         = *idx_arp_entry;
    lut_entry->timestamp   = 0;
    lut_entry->retry_count = 0;

    /* increment LUT entry size */
    arp_table->lut_entry_size++;

    return true;
}

/**
 * Create only an ARP entry (the index of it).
 * Old ARP entries are moved.
 *
 * Example:
 *
 * Before:
 *
 *   LUT table (sorted)
 *   _______ ______________ _________________
 *  |       |              |                 |
 *  | Index | IPv4 Address | ARP Entry Index |
 *  |_______|______________|_________________|
 *  |   0   |  10.0.0.1    |        0        |
 *  |   1   |  10.0.0.5    |        1        |
 *  |_______|______________|_________________|
 *
 *   ARP table (unsorted)
 *   _______ _____________ ______________ _____________
 *  |       |             |              |             |
 *  | Index | MAC address | IPv4 Gateway | IPv4 Slave  |
 *  |_______|_____________|______________|_____________|
 *  |   0   | 01:02:03:.. | 10.0.0.1     | 192.168.0.5 |
 *  |   1   | aa:bb:cc:.. | 10.0.0.5     | 14.50.0.20  |
 *  |_______|_____________|______________|_____________|
 *
 * New/Changed:
 *
 *   ARP entry
 *    | Index | MAC address | IPv4 Gateway | IPv4 Slave  |
 *   *|   0   | 00:00:00:.. | 10.0.0.1     | 192.168.0.6 |* <== ARP index in variable of LUT entry
 *    |  *1*  | 01:02:03:.. | 10.0.0.1     | 192.168.0.5 |  <== Subsequent ARP entries are moved down
 *    |  *2*  | aa:bb:cc:.. | 10.0.0.5     | 14.50.0.20  |
 *
 * Afterwards:
 *
 *   LUT table (sorted)
 *   _______ ______________ _________________
 *  |       |              |                 |
 *  | Index | IPv4 Address | ARP Entry Index |
 *  |_______|______________|_________________|
 *  |   0   |  10.0.0.1    |        0        |
 *  |   1   |  10.0.0.4    |        2        |
 *  |   2   |  10.0.0.5    |        1        |
 *  |_______|______________|_________________|
 *
 *   ARP table (unsorted)
 *   _______ _____________ ______________ _____________
 *  |       |             |              |             |
 *  | Index | MAC address | IPv4 Gateway | IPv4 Slave  |
 *  |_______|_____________|______________|_____________|
 *  |   0   | 01:02:03:.. | 10.0.0.1     | 192.168.0.5 |
 *  |   1   | aa:bb:cc:.. | 10.0.0.5     | 14.50.0.20  |
 *  |   2   | 00:00:00:.. | 10.0.0.4     | 60.0.22.33  |
 *  |_______|_____________|______________|_____________|
 *
 *
 * @param   idx_lut_entry       a
 * @param   idx_arp_entry       a
 * @param   ipv4_node           a
 * @return                      a
 */
static bool
arp_table_entry_append(arp_table_t *arp_table, netif_t *netif, uint16_t idx_lut_entry, uint16_t *idx_arp_entry, node_address_t *addr, bool *already_registered) /**< caution: 'idx_arp_entry' is not the same as 'idx_lut_entry' */
{
    arp_lut_entry_t   *lut_entry;
    uint16_t                idx;

    /* maximal size reached? */
    if (arp_table->arp_entry_size >= ARP_TABLE_MAX_ENTRIES || arp_table->lut_entry_size >= ARP_TABLE_MAX_ENTRIES) {
        LOG_PRINTLN(LOG_ARP_TABLE, LOG_ERROR, ("can't create new ARP entry: ARP table is full."));
        return false;
    }

    /* read ARP entry index from existing LUT entry*/
    lut_entry       = &(arp_table->lut_entry[idx_lut_entry]);
    *idx_arp_entry  = lut_entry->idx;   /**< start of entries with the same gateway */

    /* is the node already registered? */
    idx = *idx_arp_entry;
    do {
        /* compare existing node with potential new node */
        if (ipv4_address_equal(&(arp_table->arp_entry[idx].addr.ipv4), &(addr->ipv4))) {
            /* found existing node => return with existing index */
            *idx_arp_entry      = idx;
            *already_registered = true;

            return true;
        }
        idx++;
    /* loop while we don't reach another gateway (VID + IPv4) */
    } while (idx < arp_table->arp_entry_size &&
             arp_table->arp_entry[idx - 1].addr.netif->vlan->vid == arp_table->arp_entry[idx].addr.netif->vlan->vid &&
             ipv4_address_equal(&(arp_table->arp_entry[idx - 1].ipv4_gateway),
                                &(arp_table->arp_entry[idx].ipv4_gateway)));

    /* shift all entries between ARP entry index and table size by one */
    for (idx = arp_table->arp_entry_size; idx > *idx_arp_entry; idx--) {
        arp_table->arp_entry[idx] = arp_table->arp_entry[idx - 1];
    }

    /* update LUT table ARP indexes */
    for (idx = 0; idx < arp_table->lut_entry_size; idx++) {
        if (arp_table->lut_entry[idx].idx > *idx_arp_entry) {
            arp_table->lut_entry[idx].idx++;
        }
    }

    return true;
}

/**
 * Removes one ARP entry of a corresponding LUT entry if all callback function states are false.
 * If it's the last ARP entry of a LUT entry, remove also the LUT entry.
 *
 * @param   idx_lut_entry       index of a LUT entry
 * @param   type                what sort of callback type: PING_TABLE, STATIC_SLAVE or USER
 * @param   ipv4_node           IPv4 address to lookup
 * @return                      true if a callback function state is set to false or the whole ARP entry is removed,
 *                              false if no corresponding IPv4 address is found in the table
 */
static bool
arp_table_entry_remove(arp_table_t *arp_table, uint16_t idx_lut_entry, node_address_t *addr, arp_table_callback_fn callback)
{
    arp_lut_entry_t   *lut_entry;
    arp_entry_t       *arp_entry   = NULL;
    arp_entry_cb_t    *arp_entry_cb;
    arp_entry_cb_t    *arp_entry_cb_prev;
    uint16_t                idx_arp_entry;
    uint16_t                idx;
    bool                    callback_found = false;
    bool                    remove_lut  = false;

    /* read ARP entry index from existing LUT entry*/
    lut_entry       = &(arp_table->lut_entry[idx_lut_entry]);
    idx_arp_entry  = lut_entry->idx;   /**< start of entries with the same gateway */

    /* is the node already registered? => a LUT entry could have multiple ARP entries! */
    do {
        /* compare existing node with potential new node */
        if (LOG_ENABLE(LOG_ARP_TABLE, LOG_VERBOSE)) {
            bool eq = ipv4_address_equal(&(addr->ipv4), &(arp_table->arp_entry[idx_arp_entry].addr.ipv4));
            LOG_IPV4(&(addr->ipv4),                                    ipv4_remove);
            LOG_IPV4(&(arp_table->arp_entry[idx_arp_entry].addr.ipv4), ipv4_table);
            LOG_PRINTLN(LOG_ARP_TABLE, LOG_VERBOSE, ("[%" PRIu16 "][%" PRIu16 "] %s == %s --> %s", idx_lut_entry, idx_arp_entry, ipv4_remove, ipv4_table, eq ? "true" : "false"));
        }
        if (ipv4_address_equal(&(addr->ipv4), &(arp_table->arp_entry[idx_arp_entry].addr.ipv4))) {
            arp_entry = &(arp_table->arp_entry[idx_arp_entry]);
            LOG_PRINTLN(LOG_ARP_TABLE, LOG_VERBOSE, ("found!"));
            break;
        }
        idx_arp_entry++;
    /* loop while we don't reach another gateway (VID + IPv4) */
    } while (idx_arp_entry < arp_table->arp_entry_size &&
             arp_table->arp_entry[idx_arp_entry - 1].addr.netif->vlan->vid == arp_table->arp_entry[idx_arp_entry].addr.netif->vlan->vid &&
             ipv4_address_equal(&(arp_table->arp_entry[idx_arp_entry - 1].ipv4_gateway),
                                &(arp_table->arp_entry[idx_arp_entry].ipv4_gateway)));

    /* if NOT found, return! */
    if (arp_entry == NULL) {
        LOG_PRINTLN(LOG_ARP_TABLE, LOG_VERBOSE, ("no arp entry found!"));
        return false;
    }

    // TODO: callback list

    /* find the callback */
    arp_entry_cb = arp_entry->cb_start;
    while (arp_entry_cb != NULL) {
        /* callback matches => remove it */
        if (arp_entry_cb->callback == callback) {

            /* mark as found */
            callback_found = true;

            /* first entry */
            if (arp_entry_cb == arp_entry->cb_start) {
                arp_entry->cb_start     = arp_entry_cb->next;
            /* middle entry */
            } else if (arp_entry_cb->next != NULL) {
                arp_entry_cb_prev->next = arp_entry_cb->next;
            /* last entry */
            } else {
                arp_entry_cb_prev->next = NULL;
            }

            /* free callback */
            arp_table_cb_free(arp_table, arp_entry_cb);

            /* break loop */
            break;
        }

        /* next entry */
        arp_entry_cb_prev   = arp_entry_cb;
        arp_entry_cb        = arp_entry_cb->next;
    }

    if (!callback_found) {
        LOG_PRINTLN(LOG_ARP_TABLE, LOG_VERBOSE, ("no callback found!"));
        return false;
    }

    /* the last callback was removed: free the entry */
    if (arp_entry->cb_start == NULL) {
        LOG_PRINTLN(LOG_ARP_TABLE, LOG_VERBOSE, ("last callback on this ARP entry"));

        /* LUT index is pointing to the removed entry? */
        if (lut_entry->idx == idx_arp_entry) {

            /* no other ARP entries with the same gateway? => remove ARP entry + LUT entry */
            if ((idx_arp_entry + 1) >= arp_table->arp_entry_size ||
                 arp_table->arp_entry[idx_arp_entry].addr.netif->vlan->vid != arp_table->arp_entry[idx_arp_entry + 1].addr.netif->vlan->vid ||
                 !ipv4_address_equal(&(arp_table->arp_entry[idx_arp_entry].ipv4_gateway),
                                     &(arp_table->arp_entry[idx_arp_entry + 1].ipv4_gateway))) {
                remove_lut = true;
            }

        /* LUT index is NOT pointing to the removed entry => other entries are above */
        } else {
            //
        }

        /* next ARP entry overwrites current ARP entry */
        for (idx = idx_arp_entry; idx < (arp_table->arp_entry_size - 1); idx++) {
            arp_table->arp_entry[idx] = arp_table->arp_entry[idx + 1];
        }

        arp_table->arp_entry_size--;

        /* update LUT table ARP indexes */
        for (idx = 0; idx < arp_table->lut_entry_size; idx++) {
            if (arp_table->lut_entry[idx].idx > idx_arp_entry) {
                arp_table->lut_entry[idx].idx--;
            }
        }

        if (remove_lut) {
            /* next LUT entry overwrites current LUT entry */
            for (idx = idx_lut_entry; idx < (arp_table->lut_entry_size - 1); idx++) {
                arp_table->lut_entry[idx] = arp_table->lut_entry[idx + 1];
            }

            arp_table->lut_entry_size--;
        }
    }

    return true;
}

static int8_t
arp_table_lut_compare(arp_table_t *arp_table, int16_t idx, netif_t *netif, ipv4_address_t *ipv4_gateway)
{
//    if (netif->vlan->vid < arp_table->lut_entry[idx].netif->vlan->vid)    return -1;
//    if (netif->vlan->vid > arp_table->lut_entry[idx].netif->vlan->vid)    return  1;

    return ipv4_address_compare(ipv4_gateway, &(arp_table->lut_entry[idx].ipv4));
}

/**
 * Get index of index table by comparing address with address table
 *
 * @param   ipv4            lookup this address
 * @param   lut_ipv4_found  return the lut-entry if found, or NULL if not found
 * @return                  array-index of lut-table, if found or the neares index, so the lut-entry could be created
 */
static uint16_t
arp_table_lut_ipv4_search(arp_table_t *arp_table, netif_t *netif, ipv4_address_t *ipv4_gateway, arp_lut_entry_t **lut_entry)
{
    /* binary search to find given lut entry */
    if (arp_table->lut_entry_size > 0) {
        int16_t    idx_min = 0;
        int16_t    idx_max = arp_table->lut_entry_size - 1;
        int16_t    idx_mid = 0;
        int16_t    idx_mid_old;
        int8_t     cmp;

        while (true) {

            /* find middle */
            idx_mid_old = idx_mid;
            idx_mid     = idx_min + ((idx_max - idx_min) / 2);

            /* didn't find slave */
            if (idx_max < idx_min) {
                (*lut_entry) = NULL;
                return idx_mid_old;
            }

            cmp = arp_table_lut_compare(arp_table, idx_mid, netif, ipv4_gateway);

            /* comparator found lut entry */
            if (cmp == 0) {
                (*lut_entry) = &(arp_table->lut_entry[idx_mid]);
                return idx_mid;

            /* comparator found upper search field */
            } else if (cmp < 0) {
                idx_max = idx_mid - 1;

            /* comparator found lower search field */
            } else {
                idx_min = idx_mid + 1;
            }
        }
    }

    /* return index 0 */
    return 0;
}

/**
 * Refresh task
 *
 */
//static bool
//arp_table_task_refresh(void *ref, void *param)
//{
//    arp_table_t           *arp_table = (arp_table_t *) ref;
//    //uint32_t                    time_ms = interval_timer_hal_get_milliseconds();
//    uint32_t                    time_ms = 0;
//    arp_lut_entry_t       *lut_entry;
//    arp_entry_t           *arp_entry;
//    uint32_t                    i;
//
//    LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("refresh task"));
//
//    for (i = 0; i < arp_table->lut_entry_size; i++) {
//        lut_entry = &(arp_table->lut_entry[i]);
//
//        /* */
//        if (((int32_t) (lut_entry->timestamp - time_ms)) < 0) {
//
//            /* increase retry counter */
//            (lut_entry->retry_count)++;
//
//            /* take the first ARP entry */
//            arp_entry = &(arp_table->arp_entry[lut_entry->idx]);
//
//            /* evaluate old state */
//            switch (arp_entry->addr.state) {
//
//                /* no ARP response received (from the gateway!) after a while => failed */
//                case NODE_ADDRESS_STATE_INCOMPLETE:
//                case NODE_ADDRESS_STATE_PROBE:
//                case NODE_ADDRESS_STATE_FAILED:
//                    arp_table_send_request(arp_table, lut_entry->netif, lut_entry, arp_entry);
//                    arp_table_update_arp_entries(arp_table, i, &MAC_ADDRESS_NULL, NODE_ADDRESS_STATE_FAILED,
//                                                      ARP_TABLE_FLAGS_CALL_CALLBACK | ARP_TABLE_FLAGS_UPDATE_MAC_ADDRESS);
//                    break;
//
//                /* last time ARP response received (from the gateway!) => probe again */
//                case NODE_ADDRESS_STATE_REACHABLE:
//                    arp_table_send_request(arp_table, lut_entry->netif, lut_entry, arp_entry);
//                    arp_table_update_arp_entries(arp_table, i, NULL, NODE_ADDRESS_STATE_PROBE, ARP_TABLE_FLAGS_NONE);
//                    break;
//
//                default:
//                    break;
//            }
//        }
//    }
//
//    if (LOG_ENABLE(LOG_ARP_TABLE, LOG_DEBUG)) {
//        arp_table_log(arp_table);
//    }
//
//    return true;
//}

/**
 * Sends a gratuitous ARP (assemble, encode and send)
 *
 * @param   oper    operation request or reply
 * @return          true if the packet is sent, false otherwise
 */
bool
arp_table_gratuitous_arp_send(arp_table_t *arp_table, netif_t *netif, uint16_t oper)
{
    packet_t           *request    = packet_new();
    ethernet_header_t  *ether      = ethernet_header_new();
    arp_header_t       *arp        = arp_header_new();
    raw_packet_t        raw_request;

    request->head                  = (header_t *) ether;
    ether->header.next             = (header_t *) arp;

    if (LOG_ENABLE(LOG_ARP_TABLE, LOG_DEBUG)) {
        LOG_IPV4(&(netif->ipv4->address), ipv4_str);
        LOG_PRINTLN(LOG_ARP_TABLE, LOG_DEBUG, ("send Gratuitous ARP from interface VID=%" PRIu16 " address=%s", netif->vlan->vid, ipv4_str));
    }

    /* Ethernet */
    ether->dest                     = MAC_ADDRESS_BROADCAST;
    ether->src                      = netif->mac;
    ether->type                     = ETHERTYPE_ARP;

    /* VLAN */
    if (netif->vlan->vid != 0) {

        /* move ethertype to vlan-tag */
        ether->vlan.type            = ether->type;

        /* set ethertype to VLAN */
        ether->type                 = ETHERTYPE_VLAN;

        /* set VID and PCP */
        ether->vlan.vid             = netif->vlan->vid;
        ether->vlan.dei             = netif->vlan->dei;
        ether->vlan.pcp             = netif->vlan->pcp;
    }

    /* ARP */
    arp->htype                      = ARP_HTYPE_ETHERNET;
    arp->ptype                      = ARP_PTYPE_IPV4;
    arp->hlen                       = ARP_HLEN_ETHERNET;
    arp->plen                       = ARP_PLEN_IPV4;
    arp->oper                       = oper;

    arp->sha                        = netif->mac;
    arp->spa                        = netif->ipv4->address;

    arp->tha                        = MAC_ADDRESS_BROADCAST;
    arp->tpa                        = netif->ipv4->address;

    if (!packet_encode(netif, request, &raw_request)) {
        return false;
    }

    netif_frame_send(netif, &raw_request);

    return true;
}

/**
 * Sends
 */
static bool
arp_table_send_request(arp_table_t *arp_table, netif_t *netif, arp_lut_entry_t *lut_entry, arp_entry_t *arp_entry)
{
    packet_t           *request    = packet_new();
    ethernet_header_t  *ether      = ethernet_header_new();
    arp_header_t       *arp        = arp_header_new();
    raw_packet_t        raw_request;

    request->head                  = (header_t *) ether;
    ether->header.next             = (header_t *) arp;

    /* evaluate timeout */
//    if (lut_entry->retry_count < ARP_ENTRY_MAX_RETRY_SHORT) {
//        if (LOG_ENABLE(LOG_ARP_TABLE, LOG_INFO)) {
//            LOG_IPV4(&(lut_entry->ipv4), ipv4_str);
//            LOG_PRINTLN(LOG_ARP_TABLE, LOG_INFO, ("set timeout of direct node %s to short", ipv4_str));
//        }
//        lut_entry->timestamp = interval_timer_hal_get_milliseconds() + ARP_ENTRY_TIMEOUT_SHORT;
//    } else if (lut_entry->retry_count >= ARP_ENTRY_MAX_RETRY_SHORT && lut_entry->retry_count < ARP_ENTRY_MAX_RETRY_MIDDLE) {
//        if (LOG_ENABLE(LOG_ARP_TABLE, LOG_INFO)) {
//            LOG_IPV4(&(lut_entry->ipv4), ipv4_str);
//            LOG_PRINTLN(LOG_ARP_TABLE, LOG_INFO, ("set timeout of direct node %s to middle", ipv4_str));
//        }
//        lut_entry->timestamp = interval_timer_hal_get_milliseconds() + ARP_ENTRY_TIMEOUT_MIDDLE;
//    } else {
//        if (LOG_ENABLE(LOG_ARP_TABLE, LOG_INFO)) {
//            LOG_IPV4(&(lut_entry->ipv4), ipv4_str);
//            LOG_PRINTLN(LOG_ARP_TABLE, LOG_INFO, ("set timeout of direct node %s to long", ipv4_str));
//        }
//        lut_entry->timestamp = interval_timer_hal_get_milliseconds() + ARP_ENTRY_TIMEOUT_LONG;
//    }

    /* Ethernet */

    ether->dest                      = MAC_ADDRESS_BROADCAST;
    ether->src                       = netif->mac;
    ether->type                      = ETHERTYPE_ARP;

    /* VLAN */
    if (netif->vlan->vid != 0) {

        /* move ethertype to vlan-tag */
        ether->vlan.type             = ether->type;

        /* set ethertype to VLAN */
        ether->type                  = ETHERTYPE_VLAN;

        /* set VID and PCP */
        ether->vlan.vid              = netif->vlan->vid;
        ether->vlan.dei              = netif->vlan->dei;
        ether->vlan.pcp              = netif->vlan->pcp;
    }

    /* ARP */
    arp->htype                       = ARP_HTYPE_ETHERNET;
    arp->ptype                       = ARP_PTYPE_IPV4;
    arp->hlen                        = ARP_HLEN_ETHERNET;
    arp->plen                        = ARP_PLEN_IPV4;
    arp->oper                        = ARP_OPER_REQUEST;
    arp->sha                         = netif->mac;
    arp->spa                         = netif->ipv4->address;
    arp->tha                         = MAC_ADDRESS_NULL;
    //arp->tpa                         = arp_entry->ipv4_gateway;

    LOG_PACKET(LOG_ARP_TABLE, LOG_VERBOSE, request, ("TX"));

    if (!packet_encode(netif, request, &raw_request)) {
        return false;
    }

    netif_frame_send(netif, &raw_request);

    return true;
}

bool
arp_table_reply_request(arp_table_t *arp_table, netif_t *netif, packet_t *request, packet_t *response)
{
    ethernet_header_t  *ether      = ethernet_header_new();
    arp_header_t       *arp        = arp_header_new();

    response->head                 = (header_t *) ether;
    ether->header.next             = (header_t *) arp;

    /* Ethernet */

    //ether->dest                    = request->ether.src;
    ether->src                     = netif->mac;
    ether->type                    = ETHERTYPE_ARP;

    /* VLAN */
    //if (request->ether->vlan.vid != 0) {

        /* move ethertype to vlan-tag */
        ether->vlan.type           = ether->type;

        /* set ethertype to VLAN */
        ether->type                 = ETHERTYPE_VLAN;

        /* set VID and PCP */
        ether->vlan.vid            = netif->vlan->vid;
        ether->vlan.dei            = netif->vlan->dei;
        ether->vlan.pcp            = netif->vlan->pcp;
    //}

    /* ARP */
    arp->htype                      = ARP_HTYPE_ETHERNET;
    arp->ptype                      = ARP_PTYPE_IPV4;
    arp->hlen                       = ARP_HLEN_ETHERNET;
    arp->plen                       = ARP_PLEN_IPV4;
    arp->oper                       = ARP_OPER_RESPONSE;
    arp->sha                        = netif->mac;
    arp->spa                        = netif->ipv4->address;
    //arp->tha                        = request->arp.sha;
    //arp->tpa                        = request->arp.spa;

    return true;
}



const char *
log_node_address_state(node_address_state_t state)
{
    switch (state) {
        case NODE_ADDRESS_STATE_INCOMPLETE:    return "INCOMPLETE";
        case NODE_ADDRESS_STATE_PROBE:         return "PROBE";
        case NODE_ADDRESS_STATE_REACHABLE:     return "REACHABLE";
        case NODE_ADDRESS_STATE_FAILED:        return "FAILED";
        case NODE_ADDRESS_STATE_STATIC:        return "STATIC";
        default:                               return "UNKNOW";
    }
}

