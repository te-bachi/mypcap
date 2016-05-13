#include "log_dns.h"
#include "log_network.h"

#include "packet/packet.h"

#include <stddef.h>
#include <inttypes.h>

/*** PACKETS + HEADERS  ******************************************************/

void
log_dns_header(const dns_header_t *dns_header)
{
    LOG_PRINTF(LOG_STREAM, "DNS Header\n");
    
    LOG_PRINTF(LOG_STREAM, "   |-Identifier                         0x%04" PRIx16   "          (%" PRIu16 ")\n",     dns_header->id,           dns_header->id);
    LOG_PRINTF(LOG_STREAM, "   |-Flags                              0x%04" PRIx16   "          (%" PRIu16 ")\n",     dns_header->flags.raw,    dns_header->flags.raw);
    LOG_PRINTF(LOG_STREAM, "      |-Query / Response     (qr)       %s\n",                                           dns_header->flags.qr ? "Response" : "Query");
    LOG_PRINTF(LOG_STREAM, "      |-Operation Code       (opcode)   %-15s (0x%04" PRIx16 ")\n",       log_dns_opcode(dns_header->flags.opcode), dns_header->flags.opcode);
    LOG_PRINTF(LOG_STREAM, "      |-Authoritative Answer (aa)       %s\n",                                           dns_header->flags.aa ? "set" : "not set");
    LOG_PRINTF(LOG_STREAM, "      |-Truncation           (tc)       %s\n",                                           dns_header->flags.tc ? "set" : "not set");
    LOG_PRINTF(LOG_STREAM, "      |-Recursion Desired    (rd)       %s\n",                                           dns_header->flags.rd ? "set" : "not set");
    LOG_PRINTF(LOG_STREAM, "      |-Recursion Available  (ra)       %s\n",                                           dns_header->flags.ra ? "set" : "not set");
    LOG_PRINTF(LOG_STREAM, "      |-Authentic Data       (ad)       %s\n",                                           dns_header->flags.ad ? "set" : "not set");
    LOG_PRINTF(LOG_STREAM, "      |-Checking Disabled    (cd)       %s\n",                                           dns_header->flags.cd ? "set" : "not set");
    LOG_PRINTF(LOG_STREAM, "      |-Response Code        (rcode)    %s (%" PRIu16 ")\n",               log_dns_rcode(dns_header->flags.rcode), dns_header->flags.rcode);
    LOG_PRINTF(LOG_STREAM, "   |-Questions                          %-4" PRIu16   "            (0x%04" PRIx16 ")\n", dns_header->qd_count,  dns_header->qd_count);
    LOG_PRINTF(LOG_STREAM, "   |-Answer RRs                         %-4" PRIu16   "            (0x%04" PRIx16 ")\n", dns_header->an_count,  dns_header->an_count);
    LOG_PRINTF(LOG_STREAM, "   |-Authority RRs                      %-4" PRIu16   "            (0x%04" PRIx16 ")\n", dns_header->ns_count,  dns_header->ns_count);
    LOG_PRINTF(LOG_STREAM, "   |-Additional RRs                     %-4" PRIu16   "            (0x%04" PRIx16 ")\n", dns_header->ar_count,  dns_header->ar_count);
    LOG_PRINTF(LOG_STREAM, "   |-Questions\n");
    log_dns_queries(dns_header->qd_count, dns_header->qd);
    LOG_PRINTF(LOG_STREAM, "   |-Answer RRs\n");
    log_dns_resource_records(dns_header->an_count, dns_header->an);
    LOG_PRINTF(LOG_STREAM, "   |-Authority RRs\n");
    log_dns_resource_records(dns_header->ns_count, dns_header->ns);
    LOG_PRINTF(LOG_STREAM, "   |-Additional RRs\n");
    log_dns_resource_records(dns_header->ar_count, dns_header->ar);
}

void
log_dns_queries(const uint16_t count, const dns_query_t *query)
{
    uint16_t        idx;
    char            domain[DNS_DOMAIN_MAX_LEN];
    
    for (idx = 0; idx < count; idx++, query = query->next) {
        dns_convert_to_domain(domain, query->qname);
        
        LOG_PRINTF(LOG_STREAM, "      |-Query %" PRIu16 "\n",                   idx + 1);        
        LOG_PRINTF(LOG_STREAM, "         |-Name                         %s\n",  domain);
        LOG_PRINTF(LOG_STREAM, "         |-Type                         %s\n",  log_dns_type(query->qtype));
        LOG_PRINTF(LOG_STREAM, "         |-Class                        %s\n",  log_dns_class(query->qclass));
    }
}

void
log_dns_resource_records(const uint16_t count, const dns_rr_t *rr)
{
    uint16_t        idx;
    char            domain[DNS_DOMAIN_MAX_LEN];
    
    for (idx = 0; idx < count; idx++, rr = rr->next) {
        dns_convert_to_domain(domain, rr->name);
        
        LOG_PRINTF(LOG_STREAM, "      |-Resource Record %" PRIu16 "\n",         idx + 1);        
        LOG_PRINTF(LOG_STREAM, "         |-Name                         %s\n",  domain);
        LOG_PRINTF(LOG_STREAM, "         |-Type                         %s\n",  log_dns_type(rr->type));
        
        if (rr->type != DNS_TYPE_OPT) {
            LOG_PRINTF(LOG_STREAM, "         |-Class                        %s\n",  log_dns_class(rr->klass));
        }

        switch (rr->type) {
            case DNS_TYPE_A:            {
                                        LOG_IPV4(&(rr->a.ipv4_address), ipv4_address_str);
                                        LOG_PRINTF(LOG_STREAM, "         |-Address                      %s\n", ipv4_address_str);
                                        }
                                        break;
                                        
            case DNS_TYPE_NS:           dns_convert_to_domain(domain, rr->ns.nsdname);
                                        LOG_PRINTF(LOG_STREAM, "         |-Name Server                  %s\n", domain);
                                        break;

            case DNS_TYPE_CNAME:        dns_convert_to_domain(domain, rr->ns.nsdname);
                                        LOG_PRINTF(LOG_STREAM, "         |-Canonical Name               %s\n", domain);
                                        break;

            case DNS_TYPE_SOA:          dns_convert_to_domain(domain, rr->soa.mname);
                                        LOG_PRINTF(LOG_STREAM, "         |-Primary Name Server          %s\n", domain);
                                        dns_convert_to_domain(domain, rr->soa.rname);
                                        LOG_PRINTF(LOG_STREAM, "         |-Responsible Mailbox          %s\n", domain);
                                        LOG_PRINTF(LOG_STREAM, "         |-Serial Number                %u\n", rr->soa.serial);
                                        LOG_PRINTF(LOG_STREAM, "         |-Refresh Interval             %u\n", rr->soa.refresh);
                                        LOG_PRINTF(LOG_STREAM, "         |-Retry Interval               %u\n", rr->soa.retry);
                                        LOG_PRINTF(LOG_STREAM, "         |-Expire Limit                 %u\n", rr->soa.expire);
                                        LOG_PRINTF(LOG_STREAM, "         |-Minimum TTL                  %u\n", rr->soa.minimum);
                                        break;

            case DNS_TYPE_PTR:          dns_convert_to_domain(domain, rr->ptr.ptrdname);
                                        LOG_PRINTF(LOG_STREAM, "         |-Domain Name                  %s\n", domain);
                                        break;

            case DNS_TYPE_MX:           dns_convert_to_domain(domain, rr->mx.exchange);
                                        LOG_PRINTF(LOG_STREAM, "         |-Preference                   %u\n", rr->mx.preference);
                                        LOG_PRINTF(LOG_STREAM, "         |-Exchange                     %s\n", domain);
                                        break;
            case DNS_TYPE_OPT:
            default:                    break;
        }
    }
}

/*** TO STRING ***************************************************************/

const char *
log_dns_opcode(const uint16_t opcode)
{
    switch (opcode) {
        case DNS_HEADER_OPCODE_QUERY:    return "Query";
        case DNS_HEADER_OPCODE_IQUERY:   return "IQuery";
        case DNS_HEADER_OPCODE_STATUS:   return "Status";
        case DNS_HEADER_OPCODE_NOTIFY:   return "Notify";
        case DNS_HEADER_OPCODE_UPDATE:   return "Update";
        default:                         return "Unknow";
    }
}

const char *
log_dns_rcode(const uint16_t rcode)
{
    switch (rcode) {
        case DNS_HEADER_RCODE_NO_ERROR:  return "No Error";
        case DNS_HEADER_RCODE_FORM_ERR:  return "Format Error";
        case DNS_HEADER_RCODE_SERV_FAIL: return "Server Failure";
        case DNS_HEADER_RCODE_NX_DOMAIN: return "Non-Existent Domain";
        case DNS_HEADER_RCODE_NOT_IMPL:  return "Not Implemented";
        case DNS_HEADER_RCODE_REFUSED:   return "Query Refused";
        case DNS_HEADER_RCODE_YX_DOMAIN: return "Name Exists when it should not";
        case DNS_HEADER_RCODE_YX_RR_SET: return "RR Set Exists when it should not";
        case DNS_HEADER_RCODE_NX_RR_SET: return "RR Set that should exist does not";
        case DNS_HEADER_RCODE_NOT_AUTH:  return "Server Not Authoritative for zone";
        case DNS_HEADER_RCODE_NOT_ZONE:  return "Name not contained in zone";
        default:                         return "Unknow";
    }
}

const char *
log_dns_type(const uint16_t type) {
    switch (type) {
        case DNS_TYPE_A:                return "A (Address)";
        case DNS_TYPE_NS:               return "NS (Name Server)";
        case DNS_TYPE_MD:               return "MD (Mail Destination)";
        case DNS_TYPE_MF:               return "MF (Mail Forward)";
        case DNS_TYPE_CNAME:            return "CNAME (Canonical Name)";
        case DNS_TYPE_SOA:              return "SOA (Start of Authority)";
        case DNS_TYPE_MB:               return "MB (Mailbox)";
        case DNS_TYPE_MG:               return "MG (Mail Group)";
        case DNS_TYPE_MR:               return "MR (Mail Rename)";
        case DNS_TYPE_NULL:             return "NULL (null RR)";
        case DNS_TYPE_WKS:              return "WKS (Well Known Service)";
        case DNS_TYPE_PTR:              return "PTR (Domain Name Pointer)";
        case DNS_TYPE_HINFO:            return "HINFO (Host Information)";
        case DNS_TYPE_MINFO:            return "MINFO (Mailbox Information)";
        case DNS_TYPE_MX:               return "MX (Mail Exchange)";
        case DNS_TYPE_TXT:              return "TXT (Text String)";
        case DNS_TYPE_SIG:              return "SIG";
        case DNS_TYPE_KEY:              return "KEY";
        case DNS_TYPE_NXT:              return "NXT";
        case DNS_TYPE_OPT:              return "OPT";
        case DNS_TYPE_DS:               return "DS (Delegation Signer)";
        case DNS_TYPE_RRSIG:            return "RRSIG";
        case DNS_TYPE_NSEC:             return "NSEC";
        case DNS_TYPE_DNSKEY:           return "DNSKEY";
        case DNS_TYPE_NSEC3:            return "NSEC3";
        case DNS_TYPE_ANY:              return "ANY (All Records)";
        default:                        return "Unknow";
    }
}

const char *
log_dns_class(const uint16_t klass) {
    switch (klass) {
        case DNS_CLASS_IN:              return "IN (Internet)";
        default:                        return "Unknow";
    }
}
