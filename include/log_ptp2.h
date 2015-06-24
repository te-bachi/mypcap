#ifndef __LOG_PTP2_H__
#define __LOG_PTP2_H__

#include "log.h"
#include "ptp2_types.h"
#include "packet/packet.h"

/*** DEFINES ****************************************************************/
#define LOG_PTP2_CLOCK_IDENTITY_LEN                 23 + 1    /* clock identity string length, with NUL-character */

/*** MACROS *****************************************************************/
#define LOG_PTP2_CLOCK_IDENTITY(var, var_str)       uint8_t var_str[LOG_PTP2_CLOCK_IDENTITY_LEN];   log_ptp2_clock_identity(var, var_str)

/*** DEFINITION *************************************************************/

void        log_ptp2_clock_identity         (const ptp2_clock_identity_t *clock_identity, uint8_t *str);

void        log_ptp2_header                 (const ptp2_header_t                *ptp2);
void        log_ptp2_signaling_header       (const ptp2_signaling_header_t      *ptp2_signaling);
void        log_ptp2_signaling_tlv_header   (const ptp2_signaling_tlv_header_t  *ptp2_signaling_tlv);
void        log_ptp2_announce_header        (const ptp2_announce_header_t       *ptp2_announce);

const char *log_ptp2_message_type           (uint8_t msg_type);
const char *log_ptp2_signaling_tlv_type     (uint16_t tlv_type);
const char *log_ptp2_port_state             (ptp2_port_state_t port_state);
const char *log_ptp2_time_source            (ptp2_time_source_t time_source);
const char *log_ptp2_clock_accuracy         (uint8_t clock_accuracy);
const char *log_ptp2_delay_mechanism        (ptp2_delay_mechanism_t delay_mechanism);

#endif
