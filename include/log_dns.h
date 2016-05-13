#ifndef __LOG_DNS_H__
#define __LOG_DNS_H__

#include "log.h"
#include "packet/packet.h"

/*** DEFINES ****************************************************************/

/*** MACROS *****************************************************************/
#define LOG_DNS_HEADER(category, level, packet, msg)        LOG_NETWORK_FUNCTION(log_dns_header,         category, level, packet, msg)

/*** DEFINITION *************************************************************/
void        log_dns_header                  (const dns_header_t                 *dns_header);

void        log_dns_queries                 (const uint16_t count, const dns_query_t *query);
void        log_dns_resource_records        (const uint16_t count, const dns_rr_t    *rr);

const char *log_dns_opcode                  (const uint16_t opcode);
const char *log_dns_rcode                   (const uint16_t rcode);
const char *log_dns_type                    (const uint16_t type);
const char *log_dns_class                   (const uint16_t klass);

#endif