#include <stdio.h>
#include "pkt_capture_ops.h"
#include "hl_api.h"

int register_hl_api(traffic_classifier *tc) {
    // Register high-level API
    tc->start_traffic_classification = impl_start_traffic_classification;
    tc->stop_traffic_classification = impl_stop_traffic_classification;

    return 0;
}


int main(int argc, char *argv[]) {
    // Initialize variables
    int ret = 0;
    traffic_classifier tc;
    int sampling_window = 1000;
    int interval = 20000;
    
    // Parse command-line arguments

    // Main program logic
    printf("Hello, this is Smart Network traffic Analyzer !\n");

    ret = register_hl_api(&tc);
    if (ret != 0) {
        fprintf(stderr, "Failed to register high-level API. Error code: %d\n", ret);
        return ret;
    }

    // Start traffic classification. In the final implementation, this will be called from the management 
    // interface or a control plane application using TR-181 data model.
    tc.start_traffic_classification("eth0", sampling_window, interval);


    // Stop traffic classification. In the final implementation, this will be called from the management 
    // interface or a control plane application using TR-181 data model.
    tc.stop_traffic_classification();
      


    return ret;
}


