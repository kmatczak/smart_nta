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

    // Parse command-line arguments

    // Main program logic
    printf("Hello, this is Smart Network traffic Analyzer !\n");

    ret = register_hl_api(&tc);
    if (ret != 0) {
        fprintf(stderr, "Failed to register high-level API. Error code: %d\n", ret);
        return ret;
    }


    return ret;
}


