#ifndef PKT_CAPTURE_OPS_H
#define PKT_CAPTURE_OPS_H
#include "hl_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Start traffic classification.
 *
 * @param if_name The name of the network interface. Use "all" to capture from all interfaces.
 * @param sampling_window The sampling window size.
 * @param interval The interval between samples.
 */
void impl_start_traffic_classification(const char *if_name, unsigned int sampling_window, unsigned int interval, pkt_capture_cb_t cb);

/**
 * @brief Stop traffic classification.
 */
void impl_stop_traffic_classification(void);

#ifdef __cplusplus
}
#endif

#endif // PKT_CAPTURE_OPS_H