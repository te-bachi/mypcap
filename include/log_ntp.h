#ifndef __LOG_NTP_H__
#define __LOG_NTP_H__

#include "log.h"
#include "ntp_types.h"
#include "packet/packet.h"

/*** DEFINES ****************************************************************/
                                        /* month + space + day + space + year + space + time + point + nanosec +  NUL-character */
#define LOG_NTP_TIMESTAMP_LEN           (  3     + 1     + 2   + 1     + 4    + 1     + 8    + 1     + 9       + 1)

/*** MACROS *****************************************************************/
#define LOG_NTP_TIMESTAMP(var, var_str)         uint8_t var_str[LOG_NTP_TIMESTAMP_LEN]; log_ntp_timestamp(var, var_str)

/*** DEFINITION *************************************************************/
void        log_ntp_header                  (const ntp_header_t *ntp);

const char *log_ntp_version                 (uint8_t version);
const char *log_ntp_leap_indicator          (uint8_t leap_indicator);
const char *log_ntp_mode                    (uint8_t mode);
const char *log_ntp_stratum                 (uint8_t stratum);

void        log_ntp_timestamp               (const ntp_timestamp_t *ntp_timestamp, uint8_t *str);

#endif
