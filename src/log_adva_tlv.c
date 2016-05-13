#include "log_adva_tlv.h"
#include "log_network.h"

#include "packet/packet.h"

#include <inttypes.h>
#include <time.h>
#include <math.h>

void
log_adva_tlv_header(const adva_tlv_header_t *adva_tlv)
{
    LOG_BIT8(adva_tlv->opcode_domain, ADVA_TLV_OPCODE_FORWARD_TO_NP << 3,           opcode_forward_str);
    LOG_BIT8(adva_tlv->opcode_domain, ADVA_TLV_OPCODE_INSERT_ORIGIN_TIMESTAMP << 3, opcode_insert_ts_str);
    LOG_BIT8(adva_tlv->opcode_domain, ADVA_TLV_OPCODE_DELAY_ASYMMETRY << 3,         opcode_delay_asym_str);
    LOG_BIT8(adva_tlv->opcode_domain, ADVA_TLV_OPCODE_UPDATE_CORRECTION_FIELD << 3, opcode_update_corr_field_str);
    LOG_BIT8(adva_tlv->opcode_domain, ADVA_TLV_OPCODE_ENABLE_EGRESS_CAPTURE << 3,   opcode_enable_egress_cap_str);
    
    LOG_PRINTF(LOG_STREAM, "ADVA TLV Header\n");
    LOG_PRINTF(LOG_STREAM, "   |-Type                               0x%02" PRIx8 "             (%" PRIu8 ")\n",             adva_tlv->type,                 adva_tlv->type);
    LOG_PRINTF(LOG_STREAM, "   |-Length                             0x%02" PRIx8 "             (%" PRIu8 ")\n",             adva_tlv->len,                  adva_tlv->len);
    LOG_PRINTF(LOG_STREAM, "   |-OpCode / Domain                    0x%02" PRIx8 "             (%" PRIu8 ")\n",             adva_tlv->opcode_domain,        adva_tlv->opcode_domain);
    LOG_PRINTF(LOG_STREAM, "      |-Forward to NP        %s  %-15s\n",                                                      opcode_forward_str,             adva_tlv->opcode & ADVA_TLV_OPCODE_FORWARD_TO_NP            ? "set" : "no set");
    LOG_PRINTF(LOG_STREAM, "      |-Insert Origin TS     %s  %-15s\n",                                                      opcode_insert_ts_str,           adva_tlv->opcode & ADVA_TLV_OPCODE_INSERT_ORIGIN_TIMESTAMP  ? "set" : "no set");
    LOG_PRINTF(LOG_STREAM, "      |-Delay Asymmetry      %s  %-15s\n",                                                      opcode_delay_asym_str,          adva_tlv->opcode & ADVA_TLV_OPCODE_DELAY_ASYMMETRY          ? "set" : "no set");
    LOG_PRINTF(LOG_STREAM, "      |-Update Correction F  %s  %-15s\n",                                                      opcode_update_corr_field_str,   adva_tlv->opcode & ADVA_TLV_OPCODE_UPDATE_CORRECTION_FIELD  ? "set" : "no set");
    LOG_PRINTF(LOG_STREAM, "      |-Enable Egress Cap    %s  %-15s\n",                                                      opcode_enable_egress_cap_str,   adva_tlv->opcode & ADVA_TLV_OPCODE_ENABLE_EGRESS_CAPTURE    ? "set" : "no set");
    LOG_PRINTF(LOG_STREAM, "      |-Domain                          0x%02" PRIx8 "             (%" PRIu8 ")\n",             adva_tlv->domain,               adva_tlv->domain);
    LOG_PRINTF(LOG_STREAM, "   |-Flow Id                            0x%02" PRIx8 "             (%" PRIu8 ")\n",             adva_tlv->flow_id,              adva_tlv->flow_id);
    LOG_PRINTF(LOG_STREAM, "   |-TSG II                             0x%08" PRIx32 "       %" PRIu32 ".%09" PRIu32 " sec\n", adva_tlv->tsg_ii.raw,           adva_tlv->tsg_ii.sec,   adva_tlv->tsg_ii.nanosec);
    LOG_PRINTF(LOG_STREAM, "   |-TSG I                              0x%08" PRIx32 "       %" PRIu32 ".%09" PRIu32 " sec\n", adva_tlv->tsg_i.raw,            adva_tlv->tsg_i.sec,    adva_tlv->tsg_i.nanosec);
    
}