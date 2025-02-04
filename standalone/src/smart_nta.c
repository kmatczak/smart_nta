#include <stdio.h>
#include "pkt_capture_ops.h"

#include <stdlib.h>
#include "hl_api.h"
#include <signal.h>

static traffic_classifier_t tc;

int register_hl_api(traffic_classifier_t *tc)
{
    // Register high-level API
    tc->start_traffic_classification = impl_start_traffic_classification;
    tc->stop_traffic_classification = impl_stop_traffic_classification;

    return 0;
}

void handle_signal(int signal)
{
    // Stop traffic classification. In the final implementation, this will be called from the management
    // interface or a control plane application using TR-181 data model.
    tc.stop_traffic_classification();
    // exit(0);
}

void pkt_capt_cb_impl(const char *file_name, const pkt_capt_status_t st)
{
    printf("Callback function called with file name: %s and status:%d\n", file_name, st);
}

int main(int argc, char *argv[])
{
    // Initialize variables
    int ret = 0;
    /* Sampling time window [ms] must be smaller than interval. */
    int sampling_window = 5000;
     /* Interval between samples [ms] */
    int interval = 10000;
    /* Network interface name */
    const char *interface_name = "eth0";
    /* Directory for capture files */
    const char *capture_dir = "/tmp/pkt_capture";

    struct sigaction sa;
    
    /* Parse command line arguments */
    if (argc > 1) {
        sampling_window = atoi(argv[1]);
    }

    if (argc > 2) {
        interval = atoi(argv[2]);
    }

    if (argc > 3) {
        interface_name = argv[3];
    }

    if (argc > 4) {
        capture_dir = argv[4];
    }

    // Main program logic
    printf("Hello, this is Smart Network traffic Analyzer !\n");

    ret = register_hl_api(&tc);
    if (ret != 0)
    {
        fprintf(stderr, "Failed to register high-level API. Error code: %d\n", ret);
        return ret;
    }

    // Set up signal handler for SIGKILL
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("Error setting up signal handler");
        return 1;
    }

    // Start traffic classification. In the final implementation, this will be called from the management
    // interface or a control plane application using TR-181 data model.

    tc.start_traffic_classification(interface_name, sampling_window, interval, capture_dir, pkt_capt_cb_impl);

    return ret;
}
