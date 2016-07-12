#include "config.h"
#include "config_file.h"
#include "log.h"
#include "log_network.h"
#include "log_ntp.h"

#include "packet/raw_packet.h"
#include "packet/packet.h"
#include "packet/port.h"

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <linux/limits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#define OPT_REQUIRED     (void *) 1
#define OPT_UNRECOGNISED (void *) 2

#define UTC_OFFSET                      36                                      /* Current UTC Offset */
#define NTP_OFFSET                      2208988800UL                            /* Unix base epoch */

void usage(int argc, char *argv[], const char *msg);

static inline void  get_ostime(struct timespec *tsp);

static inline void
get_ostime(struct timespec *tsp)
{
    int     rc;

    rc = clock_gettime(CLOCK_REALTIME, tsp);
    if (rc < 0) {

        LOG_ERRNO(LOG_SIM, LOG_INFO, errno, ("read system clock failed"));
        exit(1);
    }
}

/****************************************************************************

#290
rec seconds:  db 27 2f bb (06.07.2016 07:20:27)
rec fraction: 0f 45 e0 c6 (059660000)

#294
rec seconds:  db 27 2f ac (06.07.2016 07:20:12)
rec fraction: 20 5a d0 ca (126385000)

#296
rec seconds:  db 27 2f bd (06.07.2016 07:20:29)
rec fraction: 1a 9e 62 5e (103979000)

 ***************************************************************************/

int
main(int argc, char *argv[])
{
    ntp_timestamp_t     ts1 = {
        .seconds        = 0xdb272fbb,
        .nanoseconds    = 0x0f45e0c6
    };
    uint32_t            tai1 = ts1.seconds + UTC_OFFSET - NTP_OFFSET;

    ntp_timestamp_t     ts2 = {
        .seconds        = 0xdb272fac,
        .nanoseconds    = 0x205ad0ca
    };
    uint32_t            tai2 = ts2.seconds + UTC_OFFSET - NTP_OFFSET;

    ntp_timestamp_t     ts3 = {
        .seconds        = 0xdb272fbd,
        .nanoseconds    = 0x1a9e625e
    };
    uint32_t            tai3 = ts3.seconds + UTC_OFFSET - NTP_OFFSET;

    uint32_t            tai4 = 1467917679;
    ntp_timestamp_t     ts4  = {
        .seconds        = tai4 - UTC_OFFSET + NTP_OFFSET,
        .nanoseconds    = 0
    };


    int                 opt;            /* argument for getopt() as a single integer */

    /* first character ':' of getopt()'s optstring sets opterr=0 and
       returns ':' to indicate a missing option argument
       or '?' to indicate a unrecognised option */
    while ((opt = getopt(argc, argv, ":h")) != -1) {
        switch (opt) {
            /* help */
            case 'h':
                usage(argc, argv, NULL);
                return 0;

            /* missing option argument */
            case ':':
                usage(argc, argv, OPT_REQUIRED);
                break;

            /* unrecognised option */
            case '?':
                usage(argc, argv, OPT_UNRECOGNISED);
                break;

            default:
                usage(argc, argv, NULL);
        }
    }

    log_init();

    LOG_NTP_TIMESTAMP(&ts1, ts1_str);
    LOG_NTP_TIMESTAMP(&ts2, ts2_str);
    LOG_NTP_TIMESTAMP(&ts3, ts3_str);
    LOG_NTP_TIMESTAMP(&ts4, ts4_str);

    LOG_BIT32(tai1, 0xffffffff, tai1_str);
    LOG_BIT32(tai2, 0xffffffff, tai2_str);
    LOG_BIT32(tai3, 0xffffffff, tai3_str);
    LOG_BIT32(tai4, 0xffffffff, tai4_str);
    printf("ts1=%s tai1=%d (%s)\n", ts1_str, tai1, tai1_str);
    printf("ts2=%s tai2=%d (%s)\n", ts2_str, tai2, tai2_str);
    printf("ts3=%s tai3=%d (%s)\n", ts3_str, tai3, tai3_str);
    printf("ts4=%s tai4=%d (%s)\n", ts4_str, tai4, tai4_str);

    fprintf(stderr, "Exit!\n");

    return 0;
}

void
usage(int argc, char *argv[], const char *msg)
{
   fprintf(stderr, "NTP Timestamp Analysis\n");
   fprintf(stderr, "Usage: %s\n", argv[0]);

   if (msg == OPT_REQUIRED) {
       fprintf(stderr, "\nOption -%c requires an operand\n", optopt);
   } else if (msg == OPT_UNRECOGNISED) {
       fprintf(stderr, "\nUnrecognised option: -%c\n", optopt);
   } else if (msg != NULL) {
       fprintf(stderr, "\n%s\n", msg);
   }

   exit(EXIT_FAILURE);
}
