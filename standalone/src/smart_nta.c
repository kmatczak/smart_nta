#include <stdio.h>
#include "pkt_capture_ops.h"
#include <stdlib.h>
#include "hl_api.h"
#include <signal.h>

static traffic_classifier tc;

int register_hl_api(traffic_classifier *tc)
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
    //exit(0);
}

int main(int argc, char *argv[])
{
    // Initialize variables
    int ret = 0;
    int sampling_window = 1000;
    int interval = 20000;
    struct sigaction sa;

    // Parse command-line arguments

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
    tc.start_traffic_classification("eth0", sampling_window, interval);

    return ret;
}
