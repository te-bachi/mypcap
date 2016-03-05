#ifndef __ADVA_TLV_HEADER_H__
#define __ADVA_TLV_HEADER_H__

typedef struct _adva_tlv_header_t                           adva_tlv_header_t;

/* length on the wire! */
#define ADVA_TLV_HEADER_LEN                                 12

#define ADVA_TLV_HEADER_OFFSET_TYPE                         0
#define ADVA_TLV_HEADER_OFFSET_LEN                          1
#define ADVA_TLV_HEADER_OFFSET_OPCODE_DOMAIN                2
#define ADVA_TLV_HEADER_OFFSET_FLOW_ID                      3
#define ADVA_TLV_HEADER_OFFSET_TSG_II                       4
#define ADVA_TLV_HEADER_OFFSET_TSG_I                        8

#define ADVA_TLV_TYPE_PTP                                   0x0a
#define ADVA_TLV_TYPE_NTP                                   0x0b

#define ADVA_TLV_OPCODE_FORWARD_TO_NP                       0b10000
#define ADVA_TLV_OPCODE_INSERT_ORIGIN_TIMESTAMP             0b01000
#define ADVA_TLV_OPCODE_DELAY_ASYMMETRY                     0b00100
#define ADVA_TLV_OPCODE_UPDATE_CORRECTION_FIELD             0b00010
#define ADVA_TLV_OPCODE_ENABLE_EGRESS_CAPTURE               0b00001

typedef union _adva_tlv_tsg_t {
    uint32_t            raw;
    struct {
        uint32_t        nanosec : 28;
        uint32_t        sec     : 4;
    };
} adva_tlv_tsg_t;

struct _adva_tlv_header_t {
    header_t                header;

    uint8_t                 type;
    uint8_t                 len;
    union {
        uint8_t             opcode_domain;
        struct {
            uint8_t         domain : 3;
            uint8_t         opcode : 5;
        };
    };
    uint8_t                 flow_id;
    adva_tlv_tsg_t          tsg_ii;
    adva_tlv_tsg_t          tsg_i;
};

adva_tlv_header_t  *adva_tlv_header_new     (void);
void                adva_tlv_header_free    (header_t *header);
packet_len_t        adva_tlv_header_encode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t           *adva_tlv_header_decode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

