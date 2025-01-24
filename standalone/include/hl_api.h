

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
    void (*start_traffic_classification)(char *if_name, unsigned int sampling_window, unsigned int interval);

    /**
     * @brief Stop traffic classification.
     */
    void (*stop_traffic_classification)(void);
} traffic_classifier;