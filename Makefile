
LIBRARIES_STATIC            = libmypcap.a
PROGRAMS                    = sim signaling delay_req pcap arp_reply arp_request crc_check icmp_echo

#GLOBAL_CFLAGS               = -O3 -flto -pthread -pipe -Wall -ggdb -std=gnu99 -fms-extensions -Iinclude -Wmissing-prototypes -Wno-uninitialized -Wstrict-prototypes
GLOBAL_CFLAGS               = -O0 -pthread -pipe -Wall -ggdb -std=gnu99 -fms-extensions -Iinclude -Wmissing-prototypes -Wno-uninitialized -Wstrict-prototypes
GLOBAL_LDFLAGS              = -lm


### LIBRARIES #################################################################

#-- libmypcap.a ---------------------------------------------------------------
libmypcap.a_SOURCE          = object.c \
                              log.c \
                              log_network.c \
                              log_dns.c \
                              log_ptp2.c \
                              log_ntp.c \
                              log_adva_tlv.c \
                              ptp2_types.c \
                              network_interface.c \
                              bpf.c \
                              arp_table.c \
                              config_file.c \
                              packet/net_address.c \
                              packet/raw_packet.c \
                              packet/packet.c \
                              packet/header_storage.c \
                              packet/ethernet_header.c \
                              packet/arp_header.c \
                              packet/ipv4_header.c \
                              packet/icmpv4_header.c \
                              packet/udpv4_header.c \
                              packet/dns_header.c \
                              packet/ptp2_header.c \
                              packet/ptp2_sync_header.c \
                              packet/ptp2_announce_header.c \
                              packet/ptp2_delay_req_header.c \
                              packet/ptp2_delay_resp_header.c \
                              packet/ptp2_signaling_header.c \
                              packet/ptp2_signaling_tlv_header.c \
                              packet/ntp_header.c \
                              packet/adva_tlv_header.c

                              
### SIGNALING #################################################################

signaling_CFLAGS            = 
signaling_LDFLAGS           = 
signaling_LIBRARIES         = $(LIBRARIES_STATIC)
signaling_SOURCE            = main_signaling.c


### DELAY REQ #################################################################

delay_req_CFLAGS            = 
delay_req_LDFLAGS           = 
delay_req_LIBRARIES         = $(LIBRARIES_STATIC)
delay_req_SOURCE            = main_delay_req.c


### ARP REPLY #################################################################

arp_reply_CFLAGS            = 
arp_reply_LDFLAGS           = 
arp_reply_LIBRARIES         = $(LIBRARIES_STATIC)
arp_reply_SOURCE            = main_arp_reply.c


### SIMULATOR #################################################################

sim_CFLAGS                  = 
sim_LDFLAGS                 = 
sim_LIBRARIES               = $(LIBRARIES_STATIC)
sim_SOURCE                  = main_sim.c


### PCAP ######################################################################

pcap_CFLAGS                 = 
pcap_LDFLAGS                = -lpcap
pcap_LIBRARIES              = $(LIBRARIES_STATIC)
pcap_SOURCE                 = main_pcap.c

arp_request_CFLAGS          = 
arp_request_LDFLAGS         = 
arp_request_LIBRARIES       = $(LIBRARIES_STATIC)
arp_request_SOURCE          = main_arp_request.c

crc_check_CFLAGS            = 
crc_check_LDFLAGS           = 
crc_check_LIBRARIES	        = $(LIBRARIES_STATIC)
crc_check_SOURCE            = crc_check.c

icmp_echo_CFLAGS            = 
icmp_echo_LDFLAGS           = 
icmp_echo_LIBRARIES         = $(LIBRARIES_STATIC)
icmp_echo_SOURCE            = main_icmp_echo.c


include autogen.mk

