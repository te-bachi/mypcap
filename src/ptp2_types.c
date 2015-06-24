#include "ptp2_types.h"

const ptp2_port_identity_t  PTP2_PORT_IDENTITY_ALL  = { .raw = { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff } };
const ptp2_clock_identity_t PTP2_CLOCK_IDENTITY_ALL = { .raw = { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff } };
const uint16_t              PTP2_PORT_NUMBER_ALL    = 0xffff;
const ptp2_correction_t     PTP2_CORRECTION_NULL    = { .raw = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 } };
const ptp2_time_interval_t  PTP2_TIME_INTERVAL_NULL = { .nanoseconds = 0 };

/**
 * Compare clock identities
 *
 * @param   clock_identity_a    clock identity A
 * @param   clock_identity_b    clock identity B
 * @return                      A_BIGGER_B, A_SAME_B, A_SMALLER_B
 */
ptp2_compare_result_t
ptp2_clock_identity_compare(const ptp2_clock_identity_t *a, const ptp2_clock_identity_t *b)
{
    int16_t i;

    for (i = 0; i < PTP2_CLOCK_IDENTITY_LEN; i++) {
        if (a->raw[i] > b->raw[i]) {
            return A_BIGGER_B;
        }

        if (a->raw[i] < b->raw[i]) {
            return A_SMALLER_B;
        }
    }

    return A_SAME_B;
}

/**
 * Compare port identities
 *
 * @param   port_identity_a     port identity A
 * @param   port_identity_b     port identity B
 * @return                      A_BIGGER_B, A_SAME_B, A_SMALLER_B
 */
ptp2_compare_result_t
ptp2_port_identity_compare(const ptp2_port_identity_t *a, const ptp2_port_identity_t *b)
{
    int16_t ret;

    if (A_SAME_B != (ret = ptp2_clock_identity_compare((ptp2_clock_identity_t *) a, (ptp2_clock_identity_t *) b))) {
        return ret;
    }

    if (a->port_number > b->port_number) {
        return A_BIGGER_B;
    }

    if (a->port_number < b->port_number) {
        return A_SMALLER_B;
    }

    return A_SAME_B;
}

/**
 * Converts a logarithm value to base 2 in seconds into a calculated result of milliseconds
 *
 * @param   log_interval        logarithm to base 2 measured in seconds (range: 22 .. -9)
 * @return                      milliseconds
 */
uint32_t
ptp2_milliseconds_log_interval(int8_t log_interval)
{
    /* check range */
    if (log_interval > 22)  return 0xffffffff;
    if (log_interval < -9)  return 0x00000001;

    if (log_interval > 0)   return 1000 * (1 << log_interval);
    else                    return (1000 >> (-log_interval));
}

