
PROGRAMS                    = signaling delay_req pcap

CC                          = gcc
#GLOBAL_CFLAGS               = -O3 -flto -pthread -pipe -Wall -ggdb -std=gnu99 -fms-extensions -Iinclude -Wmissing-prototypes -Wno-uninitialized -Wstrict-prototypes
GLOBAL_CFLAGS               = -O0 -pthread -pipe -Wall -ggdb -std=gnu99 -fms-extensions -Iinclude -Wmissing-prototypes -Wno-uninitialized -Wstrict-prototypes
GLOBAL_LDFLAGS              = -lm
GLOBAL_SOURCE               = object.c \
                              log.c \
                              log_network.c \
                              log_ptp2.c \
                              ptp2_types.c \
                              network_interface.c \
                              bpf.c \
                              packet/net_address.c \
                              packet/raw_packet.c \
                              packet/packet.c \
                              packet/header_storage.c \
                              packet/ethernet_header.c \
                              packet/arp_header.c \
                              packet/ipv4_header.c \
                              packet/udpv4_header.c \
                              packet/dns_header.c \
                              packet/ptp2_header.c \
                              packet/ptp2_sync_header.c \
                              packet/ptp2_announce_header.c \
                              packet/ptp2_delay_req_header.c \
                              packet/ptp2_delay_resp_header.c \
                              packet/ptp2_signaling_header.c \
                              packet/ptp2_signaling_tlv_header.c

### SIGNALING #################################################################

signaling_CFLAGS            = 
signaling_LDFLAGS           = 
signaling_SOURCE            = main_signaling.c


### DELAY REQ #################################################################

delay_req_CFLAGS            = 
delay_req_LDFLAGS           = 
delay_req_SOURCE            = main_delay_req.c


### PCAP ######################################################################

pcap_CFLAGS                 = 
pcap_LDFLAGS                = -lpcap
pcap_SOURCE                 = main_pcap.c

include Makefile.inc

