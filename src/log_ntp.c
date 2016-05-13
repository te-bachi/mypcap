#include "log_ntp.h"
#include "log_network.h"

#include "packet/packet.h"

#include <inttypes.h>
#include <time.h>
#include <math.h>

void
log_ntp_header(const ntp_header_t *ntp)
{
	double		 root_delay;
	double		 root_dispersion;
	double       polling_interval;
	double       clock_precision;
	
    LOG_PRINTF(LOG_STREAM, "NTP Header\n");

    LOG_BIT8(ntp->flags_raw, 0xc0, leap_str);
    LOG_BIT8(ntp->flags_raw, 0x38, version_str);
    LOG_BIT8(ntp->flags_raw, 0x07, mode_str);
    
    polling_interval    = pow(2, ntp->polling_interval);
    clock_precision     = pow(2, ntp->clock_precision);
    root_delay          = ((int16_t) ntp->root_delay      >> 16) + ((ntp->root_delay       & 0xffff) / 65536.0);
    root_dispersion     = ((int16_t) ntp->root_dispersion >> 16) + ((ntp->root_dispersion  & 0xffff) / 65536.0);
    
    LOG_PRINTF(LOG_STREAM, "   |-Flags                              0x%02" PRIx8 "             (%" PRIu8 ")\n", ntp->flags_raw,         ntp->flags_raw);
    LOG_PRINTF(LOG_STREAM, "      |-Leap Indicator       %s  0x%02" PRIx8 "             %s\n",                  leap_str,               ntp->leap_indicator,  log_ntp_leap_indicator(ntp->leap_indicator));
    LOG_PRINTF(LOG_STREAM, "      |-Version number       %s  0x%02" PRIx8 "             %s\n",                  version_str,            ntp->version,         log_ntp_version(ntp->version));
    LOG_PRINTF(LOG_STREAM, "      |-Mode                 %s  0x%02" PRIx8 "             %s\n",                  mode_str,               ntp->mode,            log_ntp_mode(ntp->mode));
    LOG_PRINTF(LOG_STREAM, "   |-Clock Stratum                      %-3" PRIu8 "              %s\n",            ntp->stratum,           log_ntp_stratum(ntp->stratum));
    LOG_PRINTF(LOG_STREAM, "   |-Polling Interval                   %-4" PRId8 "             %8.9f sec\n",      ntp->polling_interval,  polling_interval);
    LOG_PRINTF(LOG_STREAM, "   |-Clock Precision                    %-4" PRId8 "             %8.9f sec\n",      ntp->clock_precision,   clock_precision);
    LOG_PRINTF(LOG_STREAM, "   |-Root Delay                         0x%08" PRIx32 "       %8.9f sec\n",         ntp->root_delay,        root_delay);
    LOG_PRINTF(LOG_STREAM, "   |-Root Dispersione                   0x%08" PRIx32 "       %8.9f sec\n",         ntp->root_dispersion,   root_dispersion);
    
    if (ntp->stratum <= 1) {
        LOG_PRINTF(LOG_STREAM, "   |-Reference Id                       %.*s\n",                                NTP_REFERENCE_ID_LEN, ntp->reference_id);
    } else {
        LOG_IPV4(&(ntp->reference_ipv4), refid_str);
        LOG_PRINTF(LOG_STREAM, "   |-Reference Id                       %s\n",                                  refid_str);
    }
    
    LOG_NTP_TIMESTAMP(&(ntp->reference_timestamp), reference_str);
    LOG_NTP_TIMESTAMP(&(ntp->origin_timestamp),    origin_str);
    LOG_NTP_TIMESTAMP(&(ntp->receive_timestamp),   receive_str);
    LOG_NTP_TIMESTAMP(&(ntp->transmit_timestamp),  transmit_str);
    
    LOG_PRINTF(LOG_STREAM, "   |-Reference Timestamp                %s UTC\n",                                  reference_str);
    LOG_PRINTF(LOG_STREAM, "   |-Origin Timestamp                   %s UTC\n",                                  origin_str);
    LOG_PRINTF(LOG_STREAM, "   |-Receive Timestamp                  %s UTC\n",                                  receive_str);
    LOG_PRINTF(LOG_STREAM, "   |-Transmit Timestamp                 %s UTC\n",                                  transmit_str);
    
}

const char *
log_ntp_version(uint8_t version)
{
    switch (version) {
        case NTP_VERSION_1:                     return "NTP Version 1";
        case NTP_VERSION_2:                     return "NTP Version 2";
        case NTP_VERSION_3:                     return "NTP Version 3";
        case NTP_VERSION_4:                     return "NTP Version 4";
    }
    return "Reserved";
}

const char *
log_ntp_leap_indicator(uint8_t leap_indicator)
{
    switch (leap_indicator) {
        case NTP_LEAP_INDICATOR_NO_WARNING:     return "No warning";
        case NTP_LEAP_INDICATOR_61:             return "Leap 61";
        case NTP_LEAP_INDICATOR_59:             return "Leap 59";
        case NTP_LEAP_INDICATOR_NOT_SYNCED:     return "Not synced";
    }
    
    return "Unknow";
}

const char *
log_ntp_mode(uint8_t mode)
{
    switch (mode) {
        case NTP_MODE_RESERVED:                 return "Reserved";
        case NTP_MODE_SYMMETRIC_ACTIVE:         return "Symmetric Active";
        case NTP_MODE_SYMMETRIC_PASSIVE:        return "Symmetric Passive";
        case NTP_MODE_CLIENT:                   return "Client";
        case NTP_MODE_SERVER:                   return "Server";
        case NTP_MODE_BROADCAST:                return "Broadcast";
        case NTP_MODE_CONTROL:                  return "Control";
        case NTP_MODE_PRIVATE:                  return "Private";
    }

    return "Unknow";
}

const char *
log_ntp_stratum(uint8_t stratum)
{
    if (stratum == 0) {
        return "Unspecified or Invalid";
    } else if (stratum == 1) {
        return "Primary Reference";
    } else if (stratum >= 2 && stratum <= 15) {
        return "Secondary Reference";
    } else if (stratum == 16) {
        return "Unsynchronized";
    }
    
    return "Reserved";
}


/*
#define EPOCH_YEAR              1970
#define MONS_PER_YEAR           12
#define DAYS_PER_N_YEAR         365
#define DAYS_PER_L_YEAR         366
#define SECS_PER_MIN            (60)
#define SECS_PER_HOUR           (60 * 60)
#define SECS_PER_DAY            (24 * 60 * 60)
#define DAYS_PER_WEEK           7
#define LEAPS_THRU_END_OF(y)    ((y) / 4 - (y) / 100 + (y) / 400)
#define isleap(y)               (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

static const uint32_t mon_lengths[2][MONS_PER_YEAR] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

static const uint32_t year_lengths[2] = {
    DAYS_PER_N_YEAR, DAYS_PER_L_YEAR
};
*/

#define NTP_OFFSET 2208988800ULL

void
log_ntp_timestamp(const ntp_timestamp_t *ntp_timestamp, uint8_t *str)
{
    time_t      now = ntp_timestamp->seconds - 2208988800ULL;
    struct tm   time = {
        .tm_mday = 1,
        .tm_mon  = 0,
        .tm_year = 70,
        .tm_hour = 0,
        .tm_min  = 0,
        .tm_sec  = 0
    };
    
    if (ntp_timestamp->seconds > 0) {
        gmtime_r((const time_t *) &now, &time);
        //time.tm_year += 70;
    }
    
    /*
    uint32_t    remain;
    uint32_t    year_curr;
    uint32_t    year_new;
    uint32_t    year;
    uint32_t    month;
    const uint32_t   *month_ptr;
    uint32_t    days;
    uint32_t    hours;
    uint32_t    minutes;
    uint32_t    leap;
    
    if (seconds == 0) {
        days    = 1;
        month   = 1;
        year    = 1970;
        hours   = 0;
        minutes = 0;
        seconds = 0;
    } else {
        days    = seconds   / SECS_PER_DAY;
        remain  = seconds   % SECS_PER_DAY;
        
        hours   = remain    / SECS_PER_HOUR;
        remain  = remain    % SECS_PER_HOUR;
        
        minutes  = remain   / SECS_PER_MIN;
        seconds  = remain   % SECS_PER_MIN;
        
        year_curr = EPOCH_YEAR;
        while (days < 0 || days >= (long) year_lengths[leap = isleap(year_curr)]) {
            
            year_new = year_curr + days / DAYS_PER_N_YEAR;
            if (days < 0) {
                --year_new;
            }
            days -= (year_new - year_curr) * DAYS_PER_N_YEAR +
                    LEAPS_THRU_END_OF(year_new  - 1) -
                    LEAPS_THRU_END_OF(year_curr - 1);
            year_curr = year_new;
        }
        
        year = year_curr - 70;
        month_ptr = mon_lengths[leap];
        for (month = 0; days >= month_ptr[month]; ++month) {
            days = days - month_ptr[month];
        }
        month += 1;
        days += 1;
    }
    */
    /*
    year    = (((day * 4) + 2) / 1461) + 70;
    leap    = !(year & 3);
    day    -= (((year - 70) * 1461) + 1) / 4;
    day    += (day > 58 + leap) ? ((leap) ? 1 : 2) : 0;
    month   = ((day * 12) + 6) / 367;
    day     = day + 1 - ((month * 367) + 5) / 12;
    */
    
                                                /* day         . month     . year          hour    :     minute  :     second */
    //snprintf((char *) str, LOG_NTP_TIMESTAMP_LEN, "%02" PRIu32 ".%02" PRIu32".%04" PRIu32 " %02" PRIu32 ":%02" PRIu32 ":%02" PRIu32, days, month, year, hours, minutes, seconds);
    snprintf((char *) str, LOG_NTP_TIMESTAMP_LEN, "%02d.%02d.%04d %02d:%02d:%02d.%09" PRIu32,
                                                  time.tm_mday, time.tm_mon + 1, time.tm_year + 1900, time.tm_hour, time.tm_min, time.tm_sec, ntp_timestamp->nanoseconds);
}
