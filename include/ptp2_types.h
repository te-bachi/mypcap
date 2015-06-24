#ifndef __PTP2_TYPES_H__
#define __PTP2_TYPES_H__

#include <stdint.h>
#include <stdbool.h>

#define PTP2_PORT_IDENTITY_LEN          10
#define PTP2_CLOCK_IDENTITY_LEN         8
#define PTP2_PORT_NUMBER_LEN            2
#define PTP2_CORRECTION_LEN             8
#define PTP2_EUI48_LEN                  6

#define PTP2_FLAG_LEAP61                                0x0001
#define PTP2_FLAG_LEAP59                                0x0002
#define PTP2_FLAG_CURRENT_UTC_OFFSET_VALID              0x0004
#define PTP2_FLAG_PTP_TIMESCALE                         0x0008
#define PTP2_FLAG_TIME_TRACEABLE                        0x0010
#define PTP2_FLAG_FREQUENCY_TRACEABLE                   0x0020
#define PTP2_FLAG_ALTERNATE_MASTER                      0x0100
#define PTP2_FLAG_TWO_STEP                              0x0200
#define PTP2_FLAG_UNICAST                               0x0400

#define PTP2_TIMESTAMP_LEN              10
#define PTP2_TIMESTAMP_SECONDS_LEN      6
#define PTP2_TIMESTAMP_NANOSECONDS_LEN  4

#define PTP2_TIMESTAMP_SECONDS_NTOH(x)      (((uint64_t) x.seconds[0]) << 40 | ((uint64_t) x.seconds[1]) << 32 | ((uint64_t) x.seconds[2]) << 24 | ((uint64_t) x.seconds[3]) << 16 | ((uint64_t) x.seconds[4]) << 8 | ((uint64_t) x.seconds[5]))
#define PTP2_TIMESTAMP_NANOSECONDS_NTOH(x)  (x.nanoseconds[0] << 24 | x.nanoseconds[1] << 16 | x.nanoseconds[2] << 8 | x.nanoseconds[3])

/** 8.2.5.3.1 portDS.portState */
typedef enum {
    PTP2_PORT_STATE_NOT_DEFINED,
    PTP2_PORT_STATE_INITIALIZING,
    PTP2_PORT_STATE_FAULTY,
    PTP2_PORT_STATE_DISABLED,
    PTP2_PORT_STATE_LISTENING,
    PTP2_PORT_STATE_PRE_MASTER,
    PTP2_PORT_STATE_MASTER,
    PTP2_PORT_STATE_PASSIVE,
    PTP2_PORT_STATE_UNCALIBRATED,
    PTP2_PORT_STATE_SLAVE,
    PTP2_PORT_STATE_NUM,
} ptp2_port_state_t;

/** 8.2.5.4.4 portDS.delayMechanism */
typedef enum {
    PTP2_DELAY_MECHANISM_E2E = 0x01,
    PTP2_DELAY_MECHANISM_P2P = 0x02,
    PTP2_DELAY_MECHANISM_DISABLED = 0xFE
} ptp2_delay_mechanism_t;

typedef enum {
    PTP2_BMC_A_BETTER_B                     = 1,
    PTP2_BMC_B_BETTER_A                     = 2,
    PTP2_BMC_A_BETTER_B_TOPOLOGY            = 3,
    PTP2_BMC_B_BETTER_A_TOPOLOGY            = 4,
    PTP2_BMC_A_SAME_B                       = 5,
    PTP2_BMC_MSG_FROM_SELF                  = 6,      /** error-1 */
    PTP2_BMC_DUPLICATED_MSG                 = 7       /** error-2 */
} ptp2_bmc_algorithm_result_t;

typedef enum  {
    PTP2_TIME_SOURCE_ATOMIC_CLOCK           = 0x10,
    PTP2_TIME_SOURCE_GPS                    = 0x20,
    PTP2_TIME_SOURCE_TERRESTRIAL_RADIO      = 0x30,
    PTP2_TIME_SOURCE_PTP                    = 0x40,
    PTP2_TIME_SOURCE_NTP                    = 0x50,
    PTP2_TIME_SOURCE_HAND_SET               = 0x60,
    PTP2_TIME_SOURCE_OTHER                  = 0x90,
    PTP2_TIME_SOURCE_INTERNAL_OSCILLATOR    = 0xA0
} ptp2_time_source_t;

typedef enum {
    PTP2_ADDRESS_NONE = 0,
    PTP2_ADDRESS_LAYER2,
    PTP2_ADDRESS_IPV4,
    PTP2_ADDRESS_IPV6
} ptp2_address_type_t;

typedef enum {
    A_BIGGER_B  = 1,
    A_SAME_B    = 0,
    A_SMALLER_B = -1
} ptp2_compare_result_t;

typedef struct {
    uint8_t         raw[PTP2_CLOCK_IDENTITY_LEN];
} ptp2_clock_identity_t;

typedef union _ptp2_port_identity_t {
    uint8_t                     raw[PTP2_PORT_IDENTITY_LEN];
    struct {
        ptp2_clock_identity_t   clock_identity;
        uint16_t                port_number;
    };
} ptp2_port_identity_t;

typedef union _ptp2_correction_t {
    uint8_t         raw[PTP2_CORRECTION_LEN];
    int64_t         nanoseconds;
} ptp2_correction_t;

typedef struct _ptp2_timestamp_t {
    uint64_t        seconds;        /**< seconds (only 48 Bit valid)  */
    uint32_t        nanoseconds;    /**< nanoseconds, full range */
} ptp2_timestamp_t;

typedef struct _ptp2_clock_quality_t {
    uint8_t     class;
    uint8_t     accuracy;
    uint16_t    offset_scaled_log_variance;
} ptp2_clock_quality_t;

typedef struct _ptp2_time_interval_t {
    int64_t         nanoseconds;
} ptp2_time_interval_t;

typedef struct _eui48_t {
    uint8_t         raw[PTP2_EUI48_LEN];
} eui48_t;

extern const ptp2_port_identity_t   PTP2_PORT_IDENTITY_ALL;
extern const ptp2_clock_identity_t  PTP2_CLOCK_IDENTITY_ALL;
extern const uint16_t               PTP2_PORT_NUMBER_ALL;
extern const ptp2_correction_t      PTP2_CORRECTION_NULL;
extern const ptp2_time_interval_t   PTP2_TIME_INTERVAL_NULL;

ptp2_compare_result_t ptp2_clock_identity_compare(const ptp2_clock_identity_t *clock_identity_a, const ptp2_clock_identity_t *clock_identity_b);
ptp2_compare_result_t ptp2_port_identity_compare(const ptp2_port_identity_t *port_identity_a, const ptp2_port_identity_t *port_identity_b);
uint32_t ptp2_milliseconds_log_interval(int8_t log_interval);

#endif

