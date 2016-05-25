#include "log_network.h"
#include "log_dns.h"
#include "log_ptp2.h"
#include "log_ntp.h"
#include "log_adva_tlv.h"
#include "packet/port.h"

#include <stddef.h>
#include <inttypes.h>

/*** PACKETS + HEADERS  ******************************************************/

void
log_raw_packet(const raw_packet_t *raw_packet)
{
    uint32_t i;
    uint32_t j;

    LOG_PRINTF(LOG_STREAM, "raw packet (size = %u)\n", raw_packet->len);

    // for every character in the data-array
    for (i = 0; i < raw_packet->len ; i++) {

        // if one line of hex printing is complete...
        if (i != 0 && i % 16 == 0) {
            LOG_PRINTF(LOG_STREAM, "         ");

            for (j = i - 16; j < i; j++) {

                // if its a number or alphabet
                if (raw_packet->data[j] >= 32 && raw_packet->data[j] <= 128) {
                    LOG_PRINTF(LOG_STREAM, "%c", (unsigned char) raw_packet->data[j]);

                // otherwise print a dot
                } else {
                    LOG_PRINTF(LOG_STREAM, ".");
                }
            }
            LOG_PRINTF(LOG_STREAM, "\n");
        }

        if (i % 8 == 0) {
            if (i % 16 == 0) {
                LOG_PRINTF(LOG_STREAM, "   ");
           } else {
               LOG_PRINTF(LOG_STREAM, " ");
           }
        }
        LOG_PRINTF(LOG_STREAM, " %02" PRIX8, raw_packet->data[i]);

        // print the last spaces
        if (i == raw_packet->len - 1) {

            // extra spaces
            for ( j = 0; j < 15 - i % 16; j++) {
                LOG_PRINTF(LOG_STREAM, "   ");
            }

            // add extra space between the two 8-byte blocks
            if (15 - i % 16 >= 8) {
                LOG_PRINTF(LOG_STREAM, " ");
            }

            LOG_PRINTF(LOG_STREAM, "         ");

            for ( j = i - i % 16; j <= i; j++) {
                if (raw_packet->data[j] >= 32 && raw_packet->data[j] <= 128) {
                    LOG_PRINTF(LOG_STREAM, "%c", (unsigned char) raw_packet->data[j]);
                } else {
                    LOG_PRINTF(LOG_STREAM, ".");
                }
            }
            LOG_PRINTF(LOG_STREAM, "\n");
        }
    }
}


void
log_packet(const packet_t *packet)
{
    header_t    *header;
    
    header = packet->head;
    
    while (header != NULL) {
        switch (header->klass->type) {
            case HEADER_TYPE_ETHERNET:              log_ethernet_header             ((const ethernet_header_t *)            header);    break;
            case HEADER_TYPE_ARP:                   log_arp_header                  ((const arp_header_t *)                 header);    break;
            case HEADER_TYPE_IPV4:                  log_ipv4_header                 ((const ipv4_header_t *)                header);    break;
            case HEADER_TYPE_UDPV4:                 log_udpv4_header                ((const udpv4_header_t *)               header);    break;
            case HEADER_TYPE_DNS:                   log_dns_header                  ((const dns_header_t *)                 header);    break;
            case HEADER_TYPE_PTP2:                  log_ptp2_header                 ((const ptp2_header_t *)                header);    break;
            case HEADER_TYPE_PTP2_ANNOUNCE:         log_ptp2_announce_header        ((const ptp2_announce_header_t *)       header);    break;
            case HEADER_TYPE_PTP2_SIGNALING:        log_ptp2_signaling_header       ((const ptp2_signaling_header_t *)      header);    break;
            case HEADER_TYPE_PTP2_SIGNALING_TLV:    log_ptp2_signaling_tlv_header   ((const ptp2_signaling_tlv_header_t *)  header);    break;
            case HEADER_TYPE_NTP:                   log_ntp_header                  ((const ntp_header_t *)                 header);    break;
            case HEADER_TYPE_ADVA_TLV:              log_adva_tlv_header             ((const adva_tlv_header_t *)            header);    break;
            default:                                                                                                                    break;
        }
        header = header->next;
    }
}

void
log_ethernet_header(const ethernet_header_t *ether_header)
{
    LOG_PRINTF(LOG_STREAM, "Ethernet\n");
    
    LOG_MAC(&(ether_header->dest), dest_str);
    LOG_MAC(&(ether_header->src),  src_str);
    
    LOG_PRINTF(LOG_STREAM, "   |-Destination MAC                    %s\n",                                    dest_str);
    LOG_PRINTF(LOG_STREAM, "   |-Source MAC                         %s\n",                                    src_str);
    
    if (ether_header->type == ETHERTYPE_VLAN) {
        LOG_PRINTF(LOG_STREAM, "   |-Tag Protocol Identifier (TPID)     %-15s (0x%04" PRIx16 ")\n",           log_ether_type(ether_header->type), ether_header->type);
        LOG_PRINTF(LOG_STREAM, "   |-VLAN                               0x%04" PRIx16 "\n",                   ether_header->vlan.tci);
        LOG_PRINTF(LOG_STREAM, "     |-Priority       (PCP)             0x%02" PRIx8 "            (%u)\n",    ether_header->vlan.pcp, ether_header->vlan.pcp);
        LOG_PRINTF(LOG_STREAM, "     |-Drop Indicator (DEI)             %-15s (0x%02x)\n",                    ether_header->vlan.dei ? "set" : "no set", ether_header->vlan.dei);
        LOG_PRINTF(LOG_STREAM, "     |-Identifier     (VID)             0x%04" PRIx16 "          (%u)\n",     ether_header->vlan.vid, ether_header->vlan.vid);
        LOG_PRINTF(LOG_STREAM, "     |-Type                             %-15s (0x%04" PRIx16 ")\n",           log_ether_type(ether_header->vlan.type), ether_header->vlan.type);
    } else {
        LOG_PRINTF(LOG_STREAM, "   |-Type                               %-15s (0x%04" PRIx16 ")\n",           log_ether_type(ether_header->type), ether_header->type);
    }
}

void
log_arp_header(const arp_header_t *arp_header)
{
    LOG_PRINTF(LOG_STREAM, "ARP Header\n");
    
    LOG_MAC(&(arp_header->sha),  sha_str);
    LOG_MAC(&(arp_header->tha),  tha_str);
    
    LOG_IPV4(&(arp_header->spa), spa_str);
    LOG_IPV4(&(arp_header->tpa), tpa_str);
    
    LOG_PRINTF(LOG_STREAM, "   |-Hardware type (HTYPE)              %-15s (0x%04" PRIx16 ")\n", arp_header->htype == ARP_HTYPE_ETHERNET ? "Ethernet" : "unknow", arp_header->htype);
    LOG_PRINTF(LOG_STREAM, "   |-Protocol type (PTYPE)              %-15s (0x%04" PRIx16 ")\n", arp_header->ptype == ARP_PTYPE_IPV4     ? "IPv4"     : "unknow", arp_header->ptype);
    LOG_PRINTF(LOG_STREAM, "   |-Hardware address length (HLEN)     %-15u (0x%02" PRIx8  ")\n", arp_header->hlen, arp_header->hlen);
    LOG_PRINTF(LOG_STREAM, "   |-Protocol address length (PLEN)     %-15u (0x%02" PRIx8  ")\n", arp_header->plen, arp_header->plen);
    LOG_PRINTF(LOG_STREAM, "   |-Operation (OPER)                   %-15s (0x%04" PRIx16 ")\n", log_arp_oper(arp_header->oper), arp_header->oper);
    LOG_PRINTF(LOG_STREAM, "   |-Sender hardware address (SHA)      %-15s\n",                   sha_str);
    LOG_PRINTF(LOG_STREAM, "   |-Sender protocol address (SPA)      %-15s (0x%08" PRIx32 ")\n", spa_str, arp_header->spa.addr32);
    LOG_PRINTF(LOG_STREAM, "   |-Target hardware address (THA)      %-15s\n",                   tha_str);
    LOG_PRINTF(LOG_STREAM, "   |-Target protocol address (TPA)      %-15s (0x%08" PRIx32 ")\n", tpa_str, arp_header->tpa.addr32);
}

void
log_icmpv4_header(const icmpv4_header_t *icmpv4_header)
{
    LOG_PRINTF(LOG_STREAM, "ICMPv4 Header\n");
    
    LOG_PRINTF(LOG_STREAM, "   |-Type                               %-2"   PRId8,  icmpv4_header->type);
    LOG_PRINTF(LOG_STREAM, "   |-Code                               %-2"   PRIu8,  icmpv4_header->code);
    LOG_PRINTF(LOG_STREAM, "   |-Checksum                           0x%04" PRIx16, icmpv4_header->checksum);
    if (icmpv4_header->type == ICMPV4_TYPE_ECHO_REQUEST || icmpv4_header->type == ICMPV4_TYPE_ECHO_REPLY) {
        LOG_PRINTF(LOG_STREAM, "   |-%s",                                                                        log_icmpv4_type_code(icmpv4_header->type, icmpv4_header->code));
        LOG_PRINTF(LOG_STREAM, "      |-Identifier                      0x%04" PRIx16 "          (%" PRIu16 ")", icmpv4_header->echo.id, icmpv4_header->echo.id);
        LOG_PRINTF(LOG_STREAM, "      |-Sequence Number                 0x%04" PRIx16 "          (%" PRIu16 ")", icmpv4_header->echo.seqno, icmpv4_header->echo.seqno);
        LOG_PRINTF(LOG_STREAM, "      |-Data                            length: %-3u",                           icmpv4_header->echo.len);
    }
}

void
log_ipv4_header(const ipv4_header_t *ipv4_header)
{
    LOG_PRINTF(LOG_STREAM, "IPv4 Header\n");
    
    LOG_IPV4(&(ipv4_header->src),  src_str);
    LOG_IPV4(&(ipv4_header->dest), dest_str);
    
    LOG_PRINTF(LOG_STREAM, "   |-IP Version                         %"     PRIu8 "\n",                            ipv4_header->version);
    LOG_PRINTF(LOG_STREAM, "   |-IP Header Length                   %"     PRIu8 " dwords or %" PRIu8 " bytes\n", ipv4_header->ihl, ipv4_header->ihl * 4);
    LOG_PRINTF(LOG_STREAM, "   |-Differentiated Service             0x%02" PRIx8 "\n",                            ipv4_header->dscp);
    LOG_PRINTF(LOG_STREAM, "   |-IP Total Length                    %"     PRIu16 " bytes\n",                     ipv4_header->len);
    LOG_PRINTF(LOG_STREAM, "   |-Identification                     0x%04" PRIx16 "          (%" PRIu16 ")\n",    ipv4_header->id, ipv4_header->id);
    LOG_PRINTF(LOG_STREAM, "   |-Flags                              0x%04" PRIx16 "          (%" PRIu16 ")\n",    ipv4_header->flags_offset & IPV4_HEADER_MASK_FLAGS,
                                                                                                                  ipv4_header->flags_offset & IPV4_HEADER_MASK_FLAGS);
    LOG_PRINTF(LOG_STREAM, "      |-Don't Fragment Field            %-15s\n",                                     ipv4_header->dont_fragment ? "set" : "no set");
    LOG_PRINTF(LOG_STREAM, "      |-More Fragment Field             %-15s\n",                                     ipv4_header->more_fragments ? "set" : "no set");
    LOG_PRINTF(LOG_STREAM, "   |-Fragment Offset                    0x%04" PRIx16 "          (%" PRIu16 ")\n",    ipv4_header->fragment_offset, ipv4_header->fragment_offset);
    LOG_PRINTF(LOG_STREAM, "   |-TTL                                %"     PRIu8 "\n",                            ipv4_header->ttl);
    LOG_PRINTF(LOG_STREAM, "   |-Protocol                           %-15s (%"     PRIu8 ")\n",                    log_ipv4_protocol(ipv4_header->protocol), ipv4_header->protocol);
    LOG_PRINTF(LOG_STREAM, "   |-Checksum                           0x%04" PRIx16 "          (%" PRIu16 ")\n",    ipv4_header->checksum, ipv4_header->checksum);
    LOG_PRINTF(LOG_STREAM, "   |-Source IP                          %-15s (0x%08" PRIx32 ")\n",                   src_str, ipv4_header->src.addr32);
    LOG_PRINTF(LOG_STREAM, "   |-Destination IP                     %-15s (0x%08" PRIx32 ")\n",                   dest_str, ipv4_header->dest.addr32);
}

void
log_udpv4_header(const udpv4_header_t *udpv4_header)
{
    LOG_PRINTF(LOG_STREAM, "UDPv4 Header\n");
    
    LOG_PRINTF(LOG_STREAM, "   |-Source Port                        %-15s (%" PRIu16 ")\n",               log_ip_port(udpv4_header->src_port), udpv4_header->src_port);
    LOG_PRINTF(LOG_STREAM, "   |-Destination Port                   %-15s (%" PRIu16 ")\n",               log_ip_port(udpv4_header->dest_port), udpv4_header->dest_port);
    LOG_PRINTF(LOG_STREAM, "   |-UDP Length                         %"        PRIu16 " Bytes\n",          udpv4_header->len);
    LOG_PRINTF(LOG_STREAM, "   |-UDP Checksum                       0x%04"    PRIx16 "          (%" PRIu16 ")\n",  udpv4_header->checksum, udpv4_header->checksum);
}

/*** TO STRING ***************************************************************/

void
log_mac(const mac_address_t *mac, uint8_t *str)
{
    snprintf((char *) str, LOG_MAC_LEN, "%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8,
                                             mac->addr[0], mac->addr[1], mac->addr[2],
                                             mac->addr[3], mac->addr[4], mac->addr[5]);
}

void
log_ipv4(const ipv4_address_t *ipv4, uint8_t *str)
{
    snprintf((char *) str, LOG_IPV4_LEN, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "", ipv4->addr[0],
                                                             ipv4->addr[1],
                                                             ipv4->addr[2],
                                                             ipv4->addr[3]);
}

void
log_ipv6(const ipv6_address_t *ipv6, uint8_t *str)
{
    static const uint8_t    WIDTH = 4;      /* 16-bit, WIDTH=1: 4-bit */
    uint16_t                i;
    uint16_t                j;
    uint8_t                 chr[WIDTH];
    uint16_t                len = 0;
    bool                    padding;
    
    /* iterate over 8 blocks */
    for (i = 0; i < IPV6_ADDRESS_HW_LEN; i++) {
        /* IPv6 block is zero */
        if (ipv6->addr16[i] == 0) {
            str[len++] = '0';
            
        /* IPv6 block is _NOT_ zero */
        } else {
            num2hexstr(ntohs(ipv6->addr16[i]), chr, WIDTH);
            padding = true;
            for (j = 0; j < WIDTH; j++) {
                /* don't use leading zeros */ 
                if (padding) {
                    if (chr[j] != '0') {
                        padding = false;
                    } else {
                        continue;
                    }
                }
                str[len++] = chr[j];
            }
        }
        str[len++] = ':';
    }
    str[--len] = '\0';
}

const char *
log_header_type(const header_type_t header_type)
{
    switch (header_type) {
        case HEADER_TYPE_ETHERNET:              return "Ethernet";
        case HEADER_TYPE_VLAN:                  return "VLAN";
        case HEADER_TYPE_ARP:                   return "ARP";
        case HEADER_TYPE_IPV4:                  return "IP4v";
        case HEADER_TYPE_IPV6:                  return "IPv6";
        case HEADER_TYPE_ICMPV4:                return "ICMPv4";
        case HEADER_TYPE_UDPV4:                 return "UDPv4";
        case HEADER_TYPE_TCPV4:                 return "TCPv4";
        case HEADER_TYPE_ICMPV6:                return "ICMPv6";
        case HEADER_TYPE_UDPV6:                 return "UDPv6";
        case HEADER_TYPE_TCPV6:                 return "TCPv6";
        case HEADER_TYPE_DNS:                   return "DNS";
        case HEADER_TYPE_PTP2:                  return "PTPv2";
        case HEADER_TYPE_PTP2_SYNC:             return "PTPv2 Sync";
        case HEADER_TYPE_PTP2_ANNOUNCE:         return "PTPv2 Announce";
        case HEADER_TYPE_PTP2_DELAY_REQ:        return "PTPv2 Delay Request";
        case HEADER_TYPE_PTP2_DELAY_RESP:       return "PTPv2 Delay Response";
        case HEADER_TYPE_PTP2_SIGNALING:        return "PTPv2 Signaling";
        case HEADER_TYPE_PTP2_SIGNALING_TLV:    return "PTPv2 Signaling TLV";
        case HEADER_TYPE_NTP:                   return "NTP";
        case HEADER_TYPE_IGNORE:                return "Ignore";
        case HEADER_TYPE_ALL:                   return "All";
        default:                                return "unknow";
    }
}

const char *
log_ether_type(const uint16_t ether_type)
{
    switch (ether_type) {
        case ETHERTYPE_IPV4:        return "IPv4";
        case ETHERTYPE_IPV6:        return "IPv6";
        case ETHERTYPE_ARP:         return "ARP";
        case ETHERTYPE_VLAN:        return "VLAN";
        default:                    return "unknow";
    }
}

const char *
log_arp_oper(const uint16_t oper)
{
    switch (oper) {
        case ARP_OPER_REQUEST:          return "ARP Request";
        case ARP_OPER_RESPONSE:         return "ARP Response";
        default:                        return "Unknow";
    }
}

const char *
log_icmpv4_type_code(const uint16_t type, const uint16_t code)
{
    switch (type) {
        case ICMPV4_TYPE_ECHO_REQUEST:  return "ICMPv4 Echo Request";
        case ICMPV4_TYPE_ECHO_REPLY:    return "ICMPv4 Echo Reply";
        default:                        return "unknow";
    }
}

const char *
log_ipv4_protocol(const uint8_t ipv4_protocol)
{
    switch (ipv4_protocol) {
        case IPV4_PROTOCOL_TCP:     return "TCP";
        case IPV4_PROTOCOL_UDP:     return "UDP";
        case IPV4_PROTOCOL_ICMP:    return "ICMP";
        default:                    return "unknow";
    }
}

const char *
log_ip_port(const uint16_t port)
{
    switch (port) {
        case PORT_DNS:              return "DNS";
        case PORT_PTP2_EVENT:       return "PTPv2 Event";
        case PORT_PTP2_GENERAL:     return "PTPv2 General";
        case PORT_NTP:              return "NTP";
        default:                    return "unknow";
    }
}

