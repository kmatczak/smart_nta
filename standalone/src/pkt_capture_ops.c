#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include "pkt_capture_ops.h"


int dummy_op(int size)
{
   char *dev, errbuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *interface_list;
   pcap_if_t *interface;
   int safety_cnt = 0;

   printf("%s:%d\n", __func__, __LINE__);

   if (pcap_findalldevs(&interface_list, errbuf) == PCAP_ERROR)
   {
      fprintf(stderr, "Could not list all interfaces: %s", errbuf);
      return -ENODEV;
   }

   for (interface = interface_list; interface != NULL; interface = interface_list->next)
   {
      printf("#%d Name: %s (%s)\n", safety_cnt, interface->name, interface->description);
      if (++safety_cnt > 10)
         break;
   }

   pcap_freealldevs(interface_list);
}

void impl_start_traffic_classification(char *if_name, unsigned int sampling_window, unsigned int interval)
{
   // Stub implementation for starting traffic classification
   printf("Starting traffic classification...\n");
}

void impl_stop_traffic_classification()
{
   // Stub implementation for stopping traffic classification
   printf("Stopping traffic classification...\n");
}
