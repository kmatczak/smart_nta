#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "pkt_capture_ops.h"

typedef struct thread_data
{
   char *if_name;
   unsigned int sampling_window;
   unsigned int interval;
   volatile int stop_flag; // Flag to control the loop
   pthread_mutex_t lock;   // Mutex to protect the stop_flag

} thread_data_t;

static thread_data_t data;

static int _find_matching_devs(char *if_name, char *if_found)
{
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *interface_list;
   pcap_if_t *interface;
   int safety_cnt = 0;
   int ret = -ENODEV;

   printf("%s:%d\n", __func__, __LINE__);

   if (pcap_findalldevs(&interface_list, errbuf) == PCAP_ERROR)
   {
      fprintf(stderr, "Could not list all interfaces: %s", errbuf);
      goto exit;
   }

   for (interface = interface_list; interface != NULL; interface = interface_list->next)
   {
      printf("#%d Name: %s (%s)\n", safety_cnt, interface->name, interface->description);
      if (strcmp(interface->name, if_name) == 0)
      {
         printf("Found matching interface: %s\n", if_name);
         strcpy(if_found, interface->name);
         ret = 0;
         break;
      }
      if (++safety_cnt > 10)
      {
         printf("Couldn't find interface for %s. Safety check: %d\n", if_name, safety_cnt);
         break;
      }
   }

exit:
   pcap_freealldevs(interface_list);
   return ret;
}

static void _packet_handler(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
   printf("Packet captured. Timestamp[s]:%ld length:%d\n", pkthdr->ts.tv_sec, pkthdr->len);
   pcap_dump(dumpfile, pkthdr, packet);
   // pcap_breakloop((pcap_t *)user);
}

static int _capture_pkts(char *if_name, unsigned int sampling_window)
{
   char errbuf[PCAP_ERRBUF_SIZE];
   char if_found[10] = "";
   pcap_t *handle;
   struct pcap_pkthdr header;
   pcap_dumper_t *dumpfile;
   char filename[40];
   char timestamp[20];
   time_t rawtime;
   struct tm *timeinfo;
   const u_char *packet;
   int safety_cnt = 0;
   int ret = -ENODEV;

   printf("%s:%d\n", __func__, __LINE__);

   ret = _find_matching_devs(if_name, if_found);
   if (ret != 0)
   {
      fprintf(stderr, "Error finding matching device for %s\n", if_name);
      return ret;
   }

   printf("Device: %s\n", if_found);

   // TODO: add real implementation of the sampling time window, as the curent meaning is not correct.
   // The pcap_open_live() function interprets it as the packet buffer timeout...
   handle = pcap_open_live(if_found, BUFSIZ, 1, sampling_window, errbuf);
   if (handle == NULL)
   {
      fprintf(stderr, "Could not open device %s: %s\n", if_found, errbuf);
      return -ENODEV;
   }

   // printf("type of link layer: %d\n", pcap_datalink(handle));
   if (pcap_datalink(handle) != DLT_EN10MB)
   {
      fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", if_found);
      return -ENODEV;
   }

   /* Get unique file name with timestamp */
   time(&rawtime);
   timeinfo = localtime(&rawtime);
   strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%S", timeinfo);
   snprintf(filename, sizeof(filename), "%s_%s.pcap", if_found, timestamp);

   printf("Dumping packets to file: %s\n", filename);
   dumpfile = pcap_dump_open(handle, filename);
   if (dumpfile == NULL)
   {
      fprintf(stderr, "Error opening dump file: %s\n", pcap_geterr(handle));
      ret = -1;
      goto exit;
   }

   if (pcap_dispatch(handle, 0, _packet_handler, (u_char *)dumpfile) < 0)
   {
      fprintf(stderr, "Error occurred while capturing packets: %s\n", pcap_geterr(handle));
      ;
      ret = -1;
   }

exit:
   pcap_dump_close(dumpfile);
   pcap_close(handle);
   return ret;
}

static void *_thread_func(void *arg)
{
   thread_data_t *data = (thread_data_t *)arg;
   printf("Thread function: %s %d\n", data->if_name, data->sampling_window);

   while (1)
   {
      pthread_mutex_lock(&data->lock);
      if (data->stop_flag)
      {
         pthread_mutex_unlock(&data->lock);
         break;
      }
      pthread_mutex_unlock(&data->lock);
      _capture_pkts(data->if_name, data->sampling_window);
      usleep(data->interval * 1000);
   }

   printf("Thread exiting...\n");
   return NULL;
}

void impl_start_traffic_classification(char *if_name, unsigned int sampling_window, unsigned int interval)
{
   pthread_t thread;

   printf("Starting traffic classification...\n");

   if (if_name == NULL)
   {
      printf("Interface name is NULL\n");
      return;
   }

   if (strcmp(if_name, "all") == 0)
   {
      printf("Capturing from all interfaces\n Not yet supported.");
      // Add logic to capture from all interfaces
      return;
   }
   else
      printf("Capturing from interface: %s\n", if_name);

   data.if_name = if_name;
   data.sampling_window = sampling_window;
   data.interval = interval;
   data.stop_flag = 0;
   pthread_mutex_init(&data.lock, NULL);
   pthread_create(&thread, NULL, (void *)_thread_func, (void *)&data);
   pthread_join(thread, NULL);
   // pthread_detach(thread);
}

void impl_stop_traffic_classification()
{
   printf("Stopping traffic classification...\n");

   pthread_mutex_lock(&data.lock);
   data.stop_flag = 1;
   pthread_mutex_unlock(&data.lock);
   pthread_mutex_destroy(&data.lock);
}
