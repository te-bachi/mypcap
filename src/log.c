#include "log.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

bool log_enabled = true;

log_level_t LOG_CATEGORY_LEVEL[] = {
    [LOG_OBJECT]                        = LOG_INFO,
    [LOG_PCAP]                          = LOG_ERROR,
    [LOG_NETWORK_INTERFACE]             = LOG_INFO,
    [LOG_SOCKET_BPF]                    = LOG_INFO,
    [LOG_HEADER_STORAGE]                = LOG_INFO,
    [LOG_HEADER_ETHERNET]               = LOG_DEBUG,
    [LOG_HEADER_ARP]                    = LOG_DEBUG,
    [LOG_HEADER_IPV4]                   = LOG_DEBUG,
    [LOG_HEADER_UDPV4]                  = LOG_DEBUG,
    [LOG_HEADER_ICMPV4]                 = LOG_DEBUG,
    [LOG_HEADER_DNS]                    = LOG_DEBUG,
    [LOG_HEADER_PTP2]                   = LOG_DEBUG,
    [LOG_HEADER_PTP2_SYNC]              = LOG_DEBUG,
    [LOG_HEADER_PTP2_ANNOUNCE]          = LOG_DEBUG,
    [LOG_HEADER_PTP2_DELAY_REQ]         = LOG_DEBUG,
    [LOG_HEADER_PTP2_DELAY_RESP]        = LOG_DEBUG,
    [LOG_HEADER_PTP2_SIGNALING]         = LOG_DEBUG,
    [LOG_HEADER_PTP2_SIGNALING_TLV]     = LOG_DEBUG,
};

const char *LOG_CATEGORY_STRING[] = {
    [LOG_OBJECT]                        = "[OBJECT                    ]",
    [LOG_PCAP]                          = "[PCAP                      ]",
    [LOG_NETWORK_INTERFACE]             = "[NETWORK INTERFACE         ]",
    [LOG_SOCKET_BPF]                    = "[SOCKET BPF                ]",
    [LOG_HEADER_STORAGE]                = "[HEADER STORAGE            ]",
    [LOG_HEADER_ETHERNET]               = "[HEADER ETHERNET           ]",
    [LOG_HEADER_ARP]                    = "[HEADER ARP                ]",
    [LOG_HEADER_IPV4]                   = "[HEADER IPv4               ]",
    [LOG_HEADER_UDPV4]                  = "[HEADER UDPv4              ]",
    [LOG_HEADER_ICMPV4]                 = "[HEADER ICMPv4             ]",
    [LOG_HEADER_DNS]                    = "[HEADER DNS                ]",
    [LOG_HEADER_PTP2]                   = "[HEADER PTPv2              ]",
    [LOG_HEADER_PTP2_SYNC]              = "[HEADER PTPv2 SYNC         ]",
    [LOG_HEADER_PTP2_ANNOUNCE]          = "[HEADER PTPv2 ANNOUNCE     ]",
    [LOG_HEADER_PTP2_DELAY_REQ]         = "[HEADER PTPv2 DELAY REQ    ]",
    [LOG_HEADER_PTP2_DELAY_RESP]        = "[HEADER PTPv2 DELAY RESP   ]",
    [LOG_HEADER_PTP2_SIGNALING]         = "[HEADER PTPv2 SIGNALING    ]",
    [LOG_HEADER_PTP2_SIGNALING_TLV]     = "[HEADER PTPv2 SIGNALING TLV]",
};

const char *LOG_LEVEL_STRING[] = {
    [LOG_ERROR]                         = "[ERROR  ] ",
    [LOG_WARNING]                       = "[WARN   ] ",
    [LOG_INFO]                          = "[INFO   ] ",
    [LOG_DEBUG]                         = "[DEBUG  ] ",
    [LOG_VERBOSE]                       = "[VERBOSE] "
};

void
log_init(void)
{
    //
}

void 
log_enable(void)
{
    log_enabled = true;
}

void
log_disable(void)
{
    log_enabled = false;
}

/*** MESSAGES ****************************************************************/

/**
 * Print header information like time and category
 *
 * @param category      list of categories, see log.h
 * @param level         list of levels, see log.h
 */
void
log_print_header(log_category_t category, log_level_t level)
{
    time_t      now;
    struct tm   local;
    
    now = time(NULL);
    localtime_r(&now, &local);
    
    LOG_PRINTF(LOG_STREAM, "[%02" PRId8 ".%02" PRId8 ".%04" PRId8 " %02" PRId8 ":%02" PRId8 ":%02" PRId8 "]",
                           local.tm_mday, local.tm_mon + 1, local.tm_year + 1900,
                           local.tm_hour, local.tm_min, local.tm_sec);

    LOG_HEADER_CATEGORY(category);
    LOG_HEADER_LEVEL(level);
}


void
log_print(const char *format, ...)
{   
    va_list             args;
    
    va_start(args, format);
    LOG_VPRINTF(LOG_STREAM, format, args);
    LOG_FLUSH(LOG_STREAM);
    va_end(args);
}

void
log_println(const char *format, ...)
{
    va_list             args;
    
    va_start(args, format);
    LOG_VPRINTF(LOG_STREAM, format, args);
    LOG_PRINTF(LOG_STREAM, "\n");
    LOG_FLUSH(LOG_STREAM);
    va_end(args);
}

void
log_append(const char *format, ...)
{
    va_list             args;
    
    va_start(args, format);
    LOG_VPRINTF(LOG_STREAM, format, args);
    LOG_FLUSH(LOG_STREAM);
    va_end(args);
}

void
log_appendln(const char *format, ...)
{
    va_list             args;
    
    va_start(args, format);
    LOG_VPRINTF(LOG_STREAM, format, args);
    LOG_PRINTF(LOG_STREAM, "\n");
    LOG_FLUSH(LOG_STREAM);
    va_end(args);
}

void
log_errno(int errnum)
{
    char error_str[STRERROR_R_BUFFER_MAX];
    
    if (!strerror_r(errnum, error_str, sizeof(error_str))) {
        LOG_PRINTF(LOG_STREAM, ": %s\n", error_str);
    } else {
        LOG_PRINTF(LOG_STREAM, ": <lookup error number failed>\n");
    }
}

/*** TO BIT FIELD ************************************************************/

void
log_bit8(const uint8_t value, const uint8_t mask, uint8_t *str)
{
    uint8_t idx;
    uint8_t num;
    uint8_t bit;

    for (bit = (1 << 7), num = 0, idx = 0; bit > 0; bit >>= 1, num++, idx++) {

        if (num != 0 && num % 4 == 0) {
            str[idx++] = ' ';
        }

        if (mask & bit) {
            str[idx] = (value & bit) ? '1' : '0';
        } else {
            str[idx] = '.';
        }
    }
    str[idx] = '\0';
}

void
log_bit16(const uint16_t value, const uint16_t mask, uint8_t *str)
{
    uint8_t idx;
    uint8_t num;
    uint16_t bit;

    for (bit = (1 << 15), num = 0, idx = 0; bit > 0; bit >>= 1, num++, idx++) {

        if (num != 0 && num % 4 == 0) {
            str[idx++] = ' ';
        }

        if (mask & bit) {
            str[idx] = (value & bit) ? '1' : '0';
        } else {
            str[idx] = '.';
        }
    }
    str[idx] = '\0';
}

void
log_bit32(const uint32_t value, const uint32_t mask, uint8_t *str)
{
    uint8_t idx;
    uint8_t num;
    uint32_t bit;

    for (bit = (1 << 31), num = 0, idx = 0; bit > 0; bit >>= 1, num++, idx++) {

        if (num != 0 && num % 4 == 0) {
            str[idx++] = ' ';
        }

        if (mask & bit) {
            str[idx] = (value & bit) ? '1' : '0';
        } else {
            str[idx] = '.';
        }
    }
    str[idx] = '\0';
}

void
log_time(uint32_t seconds, uint8_t *str)
{
    uint32_t days;
    uint32_t hours;
    uint32_t minutes;

    days      = seconds   / (60 * 60 * 24);
    seconds  -= days      * (60 * 60 * 24);
    hours     = seconds   / (60 * 60);
    seconds  -= hours     * (60 * 60);
    minutes   = seconds   / (60);
    seconds  -= minutes   * (60);

                                             /*    days          hours   :     minutes :     seconds */
    snprintf((char *) str, LOG_TIME_LEN, "%05" PRIu32 " %02" PRIu32 ":%02" PRIu32 ":%02" PRIu32, days, hours, minutes, seconds);
}
