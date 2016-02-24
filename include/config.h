#ifndef __CONFIG_H__
#define __CONFIG_H__

#define CONFIG_PROGRAM_NAME                 "sim"
#define CONFIG_PROGRAM_DESC                 "PTP/NTP Simulator"
#define CONFIG_PROGRAM_VERSION              "0.1"

#define CONFIG_FILE_NAME                    "/etc/sim.conf"
#define CONFIG_DAEMON_LOG_FILE_NAME         "/var/log/sim.log"

#define CONFIG_LISTEN_BACKLOG               5       /* see listen(2), backlog */
#define CONFIG_SELECT_WAIT_SECS             0       /* see select(2), struct timeval */
#define CONFIG_SELECT_WAIT_USECS            500000  /* see select(2), struct timeval */


#endif