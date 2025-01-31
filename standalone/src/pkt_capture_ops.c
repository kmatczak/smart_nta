#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "pkt_capture_ops.h"
#include "hl_api.h"

typedef struct thread_data
{
   const char *if_name;
   unsigned int sampling_window;
   unsigned int interval;
   volatile int stop_flag; // Flag to control the loop
   pkt_capture_cb_t cb;
   pthread_mutex_t lock; // Mutex to protect the stop_flag
   pcap_t *handle;

} thread_data_t;

static thread_data_t data;

static int _find_matching_devs(const char *if_name, char *if_found)
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
}

static void *_capt_thread(void *arg)
{
   thread_data_t *data = (thread_data_t *)arg;
   char errbuf[PCAP_ERRBUF_SIZE];
   char if_found[10] = "";
   // pcap_t *handle;
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

   ret = _find_matching_devs(data->if_name, if_found);
   if (ret != 0)
   {
      fprintf(stderr, "Error finding matching device for %s\n", data->if_name);
      if (data->cb)
      {
         data->cb("Error finding matching device", CAPT_ERROR);
      }
      return NULL;
   }

   printf("Device: %s\n", if_found);

   data->handle = pcap_open_live(data->if_name, BUFSIZ, 1, 1000, errbuf);
   if (data->handle == NULL)
   {
      fprintf(stderr, "Could not open device %s: %s\n", data->if_name, errbuf);
      if (data->cb)
      {
         data->cb("Error opening device", CAPT_ERROR);
      }
      return NULL;
   }

   if (pcap_datalink(data->handle) != DLT_EN10MB)
   {
      fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", data->if_name);
      if (data->cb)
      {
         data->cb("Error opening device", CAPT_ERROR);
      }
      return NULL;
   }

   /* Get unique file name with timestamp */
   time(&rawtime);
   timeinfo = localtime(&rawtime);
   strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%S", timeinfo);
   snprintf(filename, sizeof(filename), "%s_%s.pcap", if_found, timestamp);

   printf("Dumping packets to file: %s\n", filename);
   dumpfile = pcap_dump_open(data->handle, filename);
   if (dumpfile == NULL)
   {
      fprintf(stderr, "Error opening dump file: %s\n", pcap_geterr(data->handle));
      pcap_close(data->handle);
      if (data->cb)
      {
         data->cb("Error opening dump file", CAPT_ERROR);
      }
      return NULL;
   }

   ret = pcap_loop(data->handle, -1, _packet_handler, (u_char *)dumpfile);
   if (ret < 0)
   {
      if (ret == PCAP_ERROR_BREAK)
         printf("pcap_breakloop() called\n");
      else
         fprintf(stderr, "Error occurred while capturing packets: %s ret:%d \n", pcap_geterr(data->handle), ret);
   }

   printf("%s:%d\n", __func__, __LINE__);

   pcap_dump_close(dumpfile);
   pcap_close(data->handle);

   if (data->cb)
   {
      data->cb(filename, CAPT_DONE);
   }

   return NULL;
}

static void *_capt_controller_thread(void *arg)
{
   thread_data_t *data = (thread_data_t *)arg;
   pthread_t capture_thread;

   printf("Starting packet capturing on %s with sampling window %d[ms] and interval: %d[ms] \n", data->if_name, data->sampling_window, data->interval);

   while (1)
   {
      pthread_create(&capture_thread, NULL, _capt_thread, (void *)data);
      /* Capture packets during the sampling window */
      usleep(data->sampling_window * 1000);
      pcap_breakloop(data->handle);
      pthread_join(capture_thread, NULL);
      if (data->stop_flag)
      {
         break;
      }
      /* Sleep for interval */
      usleep((data->interval - data->sampling_window) * 1000);
   }

   printf("Thread exiting...\n");
   return NULL;
}

void impl_start_traffic_classification(const char *if_name, unsigned int sampling_window, unsigned int interval, pkt_capture_cb_t cb)
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
   data.cb = cb;

   pthread_mutex_init(&data.lock, NULL);
   pthread_create(&thread, NULL, (void *)_capt_controller_thread, (void *)&data);
   pthread_join(thread, NULL);
}

void impl_stop_traffic_classification()
{
   printf("Stopping traffic classification...\n");

   pthread_mutex_lock(&data.lock);
   data.stop_flag = 1;
   pcap_breakloop(data.handle);
   pthread_mutex_unlock(&data.lock);
   pthread_mutex_destroy(&data.lock);
}
