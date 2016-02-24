#include "config.h"
#include "config_file.h"
#include "log.h"
#include "log_network.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <linux/limits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define OPT_REQUIRED     (void *) 1
#define OPT_UNRECOGNISED (void *) 2

void usage(int argc, char *argv[], const char *msg);

/****************************************************************************
 * main
 *
 * @param argc argument count
 * @param argv argument list
 * @return int return code
 ***************************************************************************/
int
main(int argc, char *argv[])
{
    config_t    config;
    char        config_file[NAME_MAX+1];
//    bool        dflag = false;  /* option: daemonize */
//    bool        lflag = false;  /* option: log level */
    bool        fflag = false;  /* option: config-file */
    //log_level_t level  = 0;
    
    int         opt;            /* argument for getopt() as a single integer */
    
    /* program without arguments */
    if (argc == 1) {
        usage(argc, argv, NULL);
    }
    
    /* first character ':' of getopt()'s optstring sets opterr=0 and
       returns ':' to indicate a missing option argument
       or '?' to indicate a unrecognised option */
    while ((opt = getopt(argc, argv, ":l:df:")) != -1) {
        switch (opt) {
                
//            /* option: log level */
//            case 'l':
//                if (strlen(optarg) != 1 || !isdigit(optarg[0])) {
//                    usage(argc, argv, "Log-Level should be a number");
//                }
//
//                level = atoi(optarg);
//
//                if (level < LOG_NONE_PRIVATE || level > LOG_DEBUG_PRIVATE) {
//                    usage(argc, argv, "Log-Level should be between 0 (None) and 5 (Debug)");
//                }
//
//                lflag = true;
//
//                break;
                
//            /* option: daemonize */
//            case 'd':
//                dflag = true;
//                break;
                
            /* option: config-file */
            case 'f':
                strcpy(config_file, optarg);
                fflag = true;
                break;
                
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
    
//    /* option: log level */
//    if (!lflag) {
//        level = LOG_WARN_PRIVATE;
//    }
    
    log_init();
    
//    /* option: interface */
//    if (!iflag) {
//        usage(argc, argv, "No interface specified");
//    }
    
    /* option: config-file */
    if (!fflag) {
        strcpy(config_file, CONFIG_FILE_NAME);
    }
    
//    /* option: daemonize */
//    if (dflag) {
//        if (!Daemon_daemonize()) {
//            Daemon_removePid();
//            exit(EXIT_FAILURE);
//        }
//    }
    
    
    LOG_PRINTLN(LOG_SIM, LOG_INFO, ("Using config-file \"%s\"", config_file));
    if (!config_file_parse(config_file, &config)) {
        printf("Error in parsing the file!\n");
        exit(EXIT_FAILURE);
    }
    
    for (int i = 0; i < config.netif_size; i++) {
        printf("netif '%s'\n", config.netif[i].name);
        for (int j = 0; j < config.netif[i].vlan_size; j++) {
            printf("    vlan '%d'\n", config.netif[i].vlan[j].vid);
            if (config.netif[i].vlan[j].gateway_configured) {
                LOG_MAC(&(config.netif[i].vlan[j].gateway.mac_address), mac_str);
                LOG_IPV4(&(config.netif[i].vlan[j].gateway.ipv4_address), ipv4_str);
                printf("        gateway %s %s\n", mac_str, ipv4_str);
            }

            if (config.netif[i].vlan[j].ptp_configured) {
                for (int k = 0; k < config.netif[i].vlan[j].ptp.slave_size; k++) {

                }
            }

            if (config.netif[i].vlan[j].ntp_configured) {
                for (int k = 0; k < config.netif[i].vlan[j].ntp.client_size; k++) {
                    LOG_MAC(&(config.netif[i].vlan[j].ntp.client[k].mac_address), mac_str);
                    LOG_IPV4(&(config.netif[i].vlan[j].ntp.client[k].ipv4_address), ipv4_str);
                    printf("        client %s %s\n", mac_str, ipv4_str);
                }
            }
        }
    }
    
    fprintf(stderr, "Exit!\n");
    
    return 0;
}

void
usage(int argc, char *argv[], const char *msg)
{
   fprintf(stderr, CONFIG_PROGRAM_DESC " " CONFIG_PROGRAM_VERSION "\n");
   fprintf(stderr, "Usage: %s [-d] [-f <config-file>] [-l <number>] -i ifname\n", argv[0]);
   
   if (msg == OPT_REQUIRED) {
       fprintf(stderr, "\nOption -%c requires an operand\n", optopt);
   } else if (msg == OPT_UNRECOGNISED) {
       fprintf(stderr, "\nUnrecognised option: -%c\n", optopt);
   } else if (msg != NULL) {
       fprintf(stderr, "\n%s\n", msg);
   }
   
   exit(EXIT_FAILURE);
}
