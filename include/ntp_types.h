#ifndef __NTP_TYPES_H__
#define __NTP_TYPES_H__

#include <stdint.h>
#include <stdbool.h>

#define JAN_1970                        2208988800UL                            /* Unix base epoch */
#define NANOSECONDS                     1000000000
#define FRAC                            4294967296.0                            /* 2^32 as a double */
#define NSECFRAC                        (FRAC / NANOSECONDS)
#define FTOTVN(tsf)                     ((uint32_t) ((tsf)  / NSECFRAC + 0.5))
#define TVNTOF(tvu)                     ((uint32_t) ((tvu) * NSECFRAC + 0.5))

#define NTP_LEAP_INDICATOR_NO_WARNING   0
#define NTP_LEAP_INDICATOR_61           1
#define NTP_LEAP_INDICATOR_59           2
#define NTP_LEAP_INDICATOR_NOT_SYNCED   3

#define NTP_VERSION_1                   1
#define NTP_VERSION_2                   2
#define NTP_VERSION_3                   3
#define NTP_VERSION_4                   4

#define NTP_MODE_RESERVED               0
#define NTP_MODE_SYMMETRIC_ACTIVE       1
#define NTP_MODE_SYMMETRIC_PASSIVE      2
#define NTP_MODE_CLIENT                 3
#define NTP_MODE_SERVER                 4
#define NTP_MODE_BROADCAST              5
#define NTP_MODE_CONTROL                6
#define NTP_MODE_PRIVATE                7

#define NTP_REFERENCE_ID_LEN            4

typedef struct _ntp_timestamp_t {
    uint32_t    seconds;
    uint32_t    nanoseconds;
} ntp_timestamp_t;

#endif
