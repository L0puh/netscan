#include "netscan.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void print_usage(char* argv);

int main(int argc, char* argv[]) {
   char *name, *hostname, *IPs[MAX_IPS];;
   int opt, ip_size, start, end, len, threads;
   
   if (argc == 1) print_usage(argv[0]);

   while((opt = getopt(argc, argv, "p:o:l:t:s")) != -1){
      switch(opt){
         case 'p':
            {
               hostname = optarg;
               ping(hostname);
               break;
            }
         case 'o':
            {
               if (optind+2 < argc){
                  hostname = optarg;
                  start = atoi(argv[optind]);
                  end = atoi(argv[optind+1]);
                  threads = atoi(argv[optind+2]);
               } else {
                  fprintf(stderr, "usage: %s -o [hostname] [start port] [end port] [threads] \n", argv[0]);
                  return -1;
               }
               if (threads == 0) threads = DEFAULT_THREADS;
               int ports[end-start+1];
               len = get_open_ports(hostname, start, end, ports, threads);
               if (len <= 0) 
                  log_info("get open ports", "no open ports were found\n");
               else {
                  printf("\n[+] open ports: \n");
                  for (int i = 0; i < len; i++){
                     printf("\tport %d is open\n", ports[i]);
                  }
               }
               break;
            }
         case 'l':
            {
               hostname = optarg;
               name = get_ips_by_name(hostname, IPs, &ip_size);
               if (name != NULL){
                  printf("%s\n", name);
                  for (int i = 0; i < ip_size; i++)
                     printf("\t%s\n", IPs[i]);
               }
               break;
            }
         case 't':
            {
               int max_ttl = 30;
               hostname = optarg; 
              
               if (optind < argc){
                  max_ttl = atoi(argv[optind]);
                  if (max_ttl <= 1) {
                     log_info(__func__, "ivalid ttl");
                     return 0;
                  }
               }
               traceroute(hostname, max_ttl);
               break;
            }
         case 's':
            {
               packet_sniffer(AF_INET);
               break;
            }

         default:
            print_usage(argv[0]);
      }

   }
   return 0;
}

void print_usage(char* argv){
   fprintf(stderr, "usage:\n\
      -p [hostname]                          - ping hostname\n\
      -o [hostname] [start] [end] [threads]  - scan open ports\n\
      -l [hostname]                          - list available IPs\n\
      -s                                     - packet sniffer\n\
      -t [hostname] [max ttl (default 30)]   - traceroute\n\n\
   example: %s -o google.com 75 90\n", argv);
}
