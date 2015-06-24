#include "log_ptp2.h"

#include "packet/packet.h"

#include <inttypes.h>
#include <math.h>

void
log_ptp2_clock_identity(const ptp2_clock_identity_t *clock_identity, uint8_t *str)
{
    snprintf((char *) str, LOG_PTP2_CLOCK_IDENTITY_LEN, "%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8,
                                                        clock_identity->raw[0], clock_identity->raw[1], clock_identity->raw[2],
                                                        clock_identity->raw[3], clock_identity->raw[4], clock_identity->raw[5],
                                                        clock_identity->raw[6], clock_identity->raw[7]);
}

void
log_ptp2_header(const ptp2_header_t *ptp2)
{
    LOG_PRINTF(LOG_STREAM, "PTP2 Header\n");

    LOG_BIT8(ptp2->msg_raw, 0xf0, transport_str);
    LOG_BIT8(ptp2->msg_raw, 0x0f, msg_type_str);
    LOG_BIT8(ptp2->version, 0x0f, version_str);

    LOG_BIT16(ptp2->flags, 0x0100, alternate_master_str);
    LOG_BIT16(ptp2->flags, 0x0200, two_step_str);
    LOG_BIT16(ptp2->flags, 0x0400, unicast_str);
    LOG_BIT16(ptp2->flags, 0x2000, ptp_profile_spec1_str);
    LOG_BIT16(ptp2->flags, 0x4000, ptp_profile_spec2_str);

    LOG_BIT16(ptp2->flags, 0x0001, leap61_str);
    LOG_BIT16(ptp2->flags, 0x0002, leap59_str);
    LOG_BIT16(ptp2->flags, 0x0004, utc_offset_valid_str);
    LOG_BIT16(ptp2->flags, 0x0008, ptp_timescale_str);
    LOG_BIT16(ptp2->flags, 0x0010, time_traceable_str);
    LOG_BIT16(ptp2->flags, 0x0020, frequency_traceable_str);

    LOG_PTP2_CLOCK_IDENTITY(&(ptp2->src_port_identity.clock_identity), clock_identity_str);

    LOG_PRINTF(LOG_STREAM, "   |-Transport Specific      %s  0x%02" PRIx8 "\n",                                   transport_str, ptp2->transport);
    LOG_PRINTF(LOG_STREAM, "   |-Message Type            %s  0x%02" PRIx8 "            %s\n",                               msg_type_str,  ptp2->msg_type, log_ptp2_message_type(ptp2->msg_type));
    LOG_PRINTF(LOG_STREAM, "   |-PTP Version             %s  %-2"   PRIu8 "              (0x%02" PRIx8 ")\n",     version_str,   ptp2->version,  ptp2->version);
    LOG_PRINTF(LOG_STREAM, "   |-Message Length                     %-5" PRIu16 "           (0x%04" PRIx16 ")\n", ptp2->msg_len, ptp2->msg_len);
    LOG_PRINTF(LOG_STREAM, "   |-Domain Number                      %-3" PRIu8 "             (0x%02" PRIx8 ")\n", ptp2->domain_number, ptp2->domain_number);
    LOG_PRINTF(LOG_STREAM, "   |-Flag Field                         %-5" PRIu16 "           (0x%04" PRIx16 ")\n", ptp2->flags, ptp2->flags);

    if (ptp2->msg_type == PTP2_MESSAGE_TYPE_ANNOUNCE  || ptp2->msg_type == PTP2_MESSAGE_TYPE_SYNC || ptp2->msg_type == PTP2_MESSAGE_TYPE_FOLLOW_UP || ptp2->msg_type == PTP2_MESSAGE_TYPE_DELAY_RESP) {
        LOG_PRINTF(LOG_STREAM, "      |-Alternate Master                %-7s         (%s)\n", ptp2->flags & 0x0100 ? "set" : "not set", alternate_master_str);
    }

    if (ptp2->msg_type == PTP2_MESSAGE_TYPE_SYNC || ptp2->msg_type == PTP2_MESSAGE_TYPE_DELAY_RESP) {
        LOG_PRINTF(LOG_STREAM, "      |-Two Step                        %-7s         (%s)\n", ptp2->flags & 0x0200 ? "set" : "not set", two_step_str);
    }

    LOG_PRINTF(LOG_STREAM, "      |-Unicast                         %-7s         (%s)\n", ptp2->flags & 0x0400 ? "set" : "not set", unicast_str);
    LOG_PRINTF(LOG_STREAM, "      |-PTP Profile Specific 1          %-7s         (%s)\n", ptp2->flags & 0x2000 ? "set" : "not set", ptp_profile_spec1_str);
    LOG_PRINTF(LOG_STREAM, "      |-PTP Profile Specific 2          %-7s         (%s)\n", ptp2->flags & 0x4000 ? "set" : "not set", ptp_profile_spec2_str);

    if (ptp2->msg_type == PTP2_MESSAGE_TYPE_ANNOUNCE) {
        LOG_PRINTF(LOG_STREAM, "      |-Leap 61                         %-7s         (%s)\n", ptp2->flags & 0x0001 ? "set" : "not set", leap61_str);
        LOG_PRINTF(LOG_STREAM, "      |-Leap 59                         %-7s         (%s)\n", ptp2->flags & 0x0002 ? "set" : "not set", leap59_str);
        LOG_PRINTF(LOG_STREAM, "      |-UTC Offset Valid                %-7s         (%s)\n", ptp2->flags & 0x0004 ? "set" : "not set", utc_offset_valid_str);
        LOG_PRINTF(LOG_STREAM, "      |-PTP Timescale                   %-7s         (%s)\n", ptp2->flags & 0x0008 ? "set" : "not set", ptp_timescale_str);
        LOG_PRINTF(LOG_STREAM, "      |-Time Traceable                  %-7s         (%s)\n", ptp2->flags & 0x0010 ? "set" : "not set", time_traceable_str);
        LOG_PRINTF(LOG_STREAM, "      |-Frequency Traceable             %-7s         (%s)\n", ptp2->flags & 0x0020 ? "set" : "not set", frequency_traceable_str);
    }

    LOG_PRINTF(LOG_STREAM, "   |-Source Clock Identity              %s\n",                                        clock_identity_str);
    LOG_PRINTF(LOG_STREAM, "   |-Source Port Number                 %-5" PRIu16 "           (0x%04" PRIx16 ")\n", ptp2->src_port_identity.port_number, ptp2->src_port_identity.port_number);
    LOG_PRINTF(LOG_STREAM, "   |-Sequence Id                        %-5" PRIu16 "           (0x%04" PRIx16 ")\n", ptp2->seq_id,            ptp2->seq_id);
    LOG_PRINTF(LOG_STREAM, "   |-Control Field                      %-3" PRIu8 "             (0x%02" PRIx8 ")\n", ptp2->control,           ptp2->control);
    LOG_PRINTF(LOG_STREAM, "   |-Log Message Interval               %-3" PRIu8 "             (0x%02" PRIx8 ")\n", ptp2->log_msg_interval,  ptp2->log_msg_interval);
}

void
log_ptp2_signaling_header(const ptp2_signaling_header_t *ptp2_signaling)
{
    LOG_PRINTF(LOG_STREAM, "PTP2 Signaling Header\n");
    LOG_PTP2_CLOCK_IDENTITY(&(ptp2_signaling->target_port_identity.clock_identity), clock_identity_str);

    LOG_PRINTF(LOG_STREAM, "   |-Target Clock Identity              %s\n",                                            clock_identity_str);
    LOG_PRINTF(LOG_STREAM, "   |-Target Port Number                 %-5" PRIu16 "           (0x%04" PRIx16 ")\n",     ptp2_signaling->target_port_identity.port_number, ptp2_signaling->target_port_identity.port_number);
}

void
log_ptp2_signaling_tlv_header(const ptp2_signaling_tlv_header_t *ptp2_signaling_tlv)
{
    double period;
    double rate;

    LOG_PRINTF(LOG_STREAM, "   |-TLV\n");
    LOG_PRINTF(LOG_STREAM, "      |-Type                            0x%04" PRIx16 "          %s\n",               ptp2_signaling_tlv->type, log_ptp2_signaling_tlv_type(ptp2_signaling_tlv->type));
    LOG_PRINTF(LOG_STREAM, "      |-Length                          0x%04" PRIx16 "          %" PRIu16 "\n",      ptp2_signaling_tlv->len,  ptp2_signaling_tlv->len);
    /* request unicast transmission */
    if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION) {
        period = pow(2, ptp2_signaling_tlv->request_unicast.log_period);
        rate   = 1 / period;

        LOG_BIT8(ptp2_signaling_tlv->request_unicast.msg.raw, 0xf0, msg_type_str);
        LOG_TIME(ptp2_signaling_tlv->request_unicast.duration, duration_str);

        LOG_PRINTF(LOG_STREAM, "      |-Message Type         %s  0x%02" PRIx8 "            %s\n",                 msg_type_str, ptp2_signaling_tlv->request_unicast.msg.type,    log_ptp2_message_type(ptp2_signaling_tlv->request_unicast.msg.type));
        LOG_PRINTF(LOG_STREAM, "      |-Log Inter Message Period        0x%02" PRIx8 "            %" PRId8 "\n",  (uint8_t) ptp2_signaling_tlv->request_unicast.log_period, ptp2_signaling_tlv->request_unicast.log_period);
        LOG_PRINTF(LOG_STREAM, "         |-Period                                       every %lg second\n",      period);
        LOG_PRINTF(LOG_STREAM, "         |-Rate                                         %lg %s/sec \n",           rate, rate == 1.0f ? "packet" : "packets");
        LOG_PRINTF(LOG_STREAM, "      |-Duration Field                  0x%08" PRIx32 "      %s\n",               ptp2_signaling_tlv->request_unicast.duration, duration_str);

    /* grant unicast transmission */
    } else if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_GRANT_UNICAST_TRANSMISSION) {
        period = pow(2, ptp2_signaling_tlv->grant_unicast.log_period);
        rate   = 1 / period;

        LOG_BIT8(ptp2_signaling_tlv->grant_unicast.msg.raw, 0xf0, msg_type_str);
        LOG_TIME(ptp2_signaling_tlv->grant_unicast.duration, duration_str);
        LOG_BIT8(ptp2_signaling_tlv->grant_unicast.renewal.raw, 0x01,renewal_str);

        LOG_PRINTF(LOG_STREAM, "      |-Message Type         %s  0x%02" PRIx8 "            %s\n",                 msg_type_str, ptp2_signaling_tlv->grant_unicast.msg.type,    log_ptp2_message_type(ptp2_signaling_tlv->grant_unicast.msg.type));
        LOG_PRINTF(LOG_STREAM, "      |-Log Inter Message Period        0x%02" PRIx8 "            %" PRId8 "\n",  (uint8_t) ptp2_signaling_tlv->grant_unicast.log_period, ptp2_signaling_tlv->grant_unicast.log_period);
        LOG_PRINTF(LOG_STREAM, "         |-Period                                       every %lg second\n",      period);
        LOG_PRINTF(LOG_STREAM, "         |-Rate                                         %lg %s/sec \n",           rate, rate == 1.0f ? "packet" : "packets");
        LOG_PRINTF(LOG_STREAM, "      |-Duration Field                  0x%08" PRIx32 "      %s\n",               ptp2_signaling_tlv->grant_unicast.duration, duration_str);
        LOG_PRINTF(LOG_STREAM, "      |-Renewal Invited                 %-7s         (%s)\n",                     ptp2_signaling_tlv->grant_unicast.renewal.flag ? "set" : "not set", renewal_str);

    /* cancel unicast transmission */
    } else if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION) {


    } else if (ptp2_signaling_tlv->type == PTP2_SIGNALING_TLV_TYPE_ACK_CANCEL_UNICAST_TRANSMISSION) {

    }
}

void
log_ptp2_announce_header(const ptp2_announce_header_t *ptp2_announce)
{
    LOG_PRINTF(LOG_STREAM, "PTP2 Announce Header\n");
}

const char *
log_ptp2_message_type(uint8_t msg_type)
{
    switch (msg_type) {
        case PTP2_MESSAGE_TYPE_SYNC:                        return "Sync";
        case PTP2_MESSAGE_TYPE_DELAY_REQ:                   return "Delay Request";
        case PTP2_MESSAGE_TYPE_PDELAY_REQ:                  return "Peer-Delay Request";
        case PTP2_MESSAGE_TYPE_PDELAY_RESP:                 return "Peer-Delay Response";
        case PTP2_MESSAGE_TYPE_FOLLOW_UP:                   return "Follow Up";
        case PTP2_MESSAGE_TYPE_DELAY_RESP:                  return "Delay Response";
        case PTP2_MESSAGE_TYPE_PDELAY_RESP_FOLLOW_UP:       return "Peer-Delay Response Follow Up";
        case PTP2_MESSAGE_TYPE_ANNOUNCE:                    return "Announce";
        case PTP2_MESSAGE_TYPE_SIGNALING:                   return "Signaling";
        case PTP2_MESSAGE_TYPE_MANAGEMENT:                  return "Management";
        default:                                            return "Unknow";
    }
}

const char *
log_ptp2_signaling_tlv_type(uint16_t tlv_type)
{
    switch (tlv_type) {
        case PTP2_SIGNALING_TLV_TYPE_MANAGEMENT:                      return "Management";
        case PTP2_SIGNALING_TLV_TYPE_MANAGEMENT_ERROR_STATUS:         return "Management Error Status";
        case PTP2_SIGNALING_TLV_TYPE_ORGANIZATION_EXTENSION:          return "Organization Extension";
        case PTP2_SIGNALING_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION:    return "Request Unicast Transmission";
        case PTP2_SIGNALING_TLV_TYPE_GRANT_UNICAST_TRANSMISSION:      return "Grant Unicast Transmission";
        case PTP2_SIGNALING_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION:     return "Cancel Unicast Transmission";
        case PTP2_SIGNALING_TLV_TYPE_ACK_CANCEL_UNICAST_TRANSMISSION: return "Acknowledge Cancel Unicast Transmission";
        case PTP2_SIGNALING_TLV_TYPE_PATH_TRACE:                      return "Path Trace";
        case PTP2_SIGNALING_TLV_TYPE_ALTERNATE_TIME_OFFSET_INDICATOR: return "Alternate Time Offset Indicator";
        case PTP2_SIGNALING_TLV_TYPE_AUTHENTICATION:                  return "Authentication";
        case PTP2_SIGNALING_TLV_TYPE_AUTHENTICATION_CHALLENGE:        return "Authentication Challenge";
        case PTP2_SIGNALING_TLV_TYPE_SECURITY_ASSOCIATION_UPDATE:     return "Security Association Update";
        case PTP2_SIGNALING_TLV_TYPE_CUM_FREQ_SCALE_FACTOR_OFFSET:    return "Cumulative Frequency Scale Factor Offset";
        default:                                            return "Unknow";
    }
}

const char *
log_ptp2_port_state(ptp2_port_state_t port_state)
{
    switch (port_state) {
        case PTP2_PORT_STATE_NOT_DEFINED:                   return "NOT DEFINED";
        case PTP2_PORT_STATE_INITIALIZING:                  return "INITIALIZING";
        case PTP2_PORT_STATE_FAULTY:                        return "FAULTY";
        case PTP2_PORT_STATE_DISABLED:                      return "DISABLED";
        case PTP2_PORT_STATE_LISTENING:                     return "LISTENING";
        case PTP2_PORT_STATE_PRE_MASTER:                    return "PRE-MASTER";
        case PTP2_PORT_STATE_MASTER:                        return "MASTER";
        case PTP2_PORT_STATE_PASSIVE:                       return "PASSIVE";
        case PTP2_PORT_STATE_UNCALIBRATED:                  return "UNCALIBRATED";
        case PTP2_PORT_STATE_SLAVE:                         return "SLAVE";
        default:                                            return "UNKNOWN";
    }
}

const char *
log_ptp2_time_source(ptp2_time_source_t time_source)
{
    switch (time_source) {
        case PTP2_TIME_SOURCE_ATOMIC_CLOCK:         return "ATOMIC_CLOCK";
        case PTP2_TIME_SOURCE_GPS:                  return "GPS";
        case PTP2_TIME_SOURCE_TERRESTRIAL_RADIO:    return "TERRESTRIAL_RADIO";
        case PTP2_TIME_SOURCE_PTP:                  return "PTP";
        case PTP2_TIME_SOURCE_NTP:                  return "NTP";
        case PTP2_TIME_SOURCE_HAND_SET:             return "HAND_SET";
        case PTP2_TIME_SOURCE_OTHER:                return "OTHER";
        case PTP2_TIME_SOURCE_INTERNAL_OSCILLATOR:  return "INTERNAL_OSCILLATOR";
        default:                                    return "UNKNOW";
    }
}
/**
 * 7.6.2.5 clockAccuracy
 */
const char *
log_ptp2_clock_accuracy(uint8_t clock_accuracy)
{
    if (clock_accuracy <= 0x1f || (clock_accuracy >= 0x32 && clock_accuracy <= 0x7f) || clock_accuracy == 0xff) {
        return "reserved";
    }

    if (clock_accuracy >= 0x80 && clock_accuracy <= 0xfd) {
        return "alternate profile";
    }

    switch (clock_accuracy) {
        case 0x20: return "25 ns";
        case 0x21: return "100 ns";
        case 0x22: return "250 ns";
        case 0x23: return "1 us";
        case 0x24: return "2.5 us";
        case 0x25: return "10 us";
        case 0x26: return "25 us";
        case 0x27: return "100 us";
        case 0x28: return "250 us";
        case 0x29: return "1 ms";
        case 0x2a: return "2.5 ms";
        case 0x2b: return "10 ms";
        case 0x2c: return "25 ms";
        case 0x2d: return "100 ms";
        case 0x2e: return "250 ms";
        case 0x2f: return "1 s";
        case 0x30: return "10 s";
        case 0x31: return "10 s";
    }

    return "unknow";
}

const char *
log_ptp2_delay_mechanism(ptp2_delay_mechanism_t delay_mechanism)
{
    switch (delay_mechanism) {
        case PTP2_DELAY_MECHANISM_E2E:      return "E2E";
        case PTP2_DELAY_MECHANISM_P2P:      return "P2P";
        case PTP2_DELAY_MECHANISM_DISABLED: return "disabled";
    }

    return "unknow";
}

