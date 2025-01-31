
#ifndef HL_API_H
#define HL_API_H




typedef enum 
{
    CAPT_STARTED = 0,
    CAPT_DONE = 1,
    CAPT_ERROR = -1   
} pkt_capt_status_t;

/**
 * @typedef pkt_capture_cb_t
 * @brief Callback function for packet capture.
 *
 * This function is called when a packet capture is complete.
 *
 * @param file_name The name of the file where the packets are stored.
 * @param status The status of the packet capture.
 */
typedef void (*pkt_capture_cb_t)(const char * file_name, const pkt_capt_status_t);


/**
 * @struct traffic_classifier
 * @brief A structure for traffic classification functions.
 *
 * This structure contains function pointers for starting and stopping
 * traffic classification.
 */
typedef struct
{
    /**
     * @brief Start traffic classification.
     *
     * @param if_name The name of the network interface. Use "all" to capture from all interfaces.
     * @param sampling_window The sampling window size [ms].
     * @param interval The interval between samples [ms].
     */
    void (*start_traffic_classification)(const char *if_name, unsigned int sampling_window, unsigned int interval, pkt_capture_cb_t cb);

    /**
     * @brief Stop traffic classification.
     */
    void (*stop_traffic_classification)(void);

} traffic_classifier_t;



traffic_classifier_t * get_traffic_classifier(void);

#endif /* HL_API_H */