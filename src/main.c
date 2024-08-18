#include "netscan.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void print_usage(char* argv);

int main(int argc, char* argv[]) {
   int opt, ip_size, start, end, len;
   char *name, *hostname, *IPs[MAX_IPS];;
   
   if (argc == 1) print_usage(argv[0]);

   while((opt = getopt(argc, argv, "pol?:")) != -1){
      switch(opt){
         case 'p':
            {
               if (optind < argc)
                  hostname = argv[optind];
               else {
                  fprintf(stderr, "usage: %s -p [hostname]\n", argv[0]);
                  return -1;
               }
               ping(hostname);
               break;
            }
         case 'o':
            {
               if (optind+2 < argc){
                  hostname = argv[optind];
                  start = atoi(argv[optind+1]);
                  end = atoi(argv[optind+2]);
               } else {
                  fprintf(stderr, "usage: %s -o [hostname] [start port] [end port]\n", argv[0]);
                  return -1;
               }
               
               int ports[end-start+1];
               len = get_open_ports(hostname, start, end, ports);
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
               if (optind < argc){
                  hostname = argv[optind];
               } else {
                  fprintf(stderr, "usage: %s -l [hostname]\n", argv[0]);
                  return -1;
               }
               name = get_ips_by_name(hostname, IPs, &ip_size);
               if (name != NULL){
                  printf("%s\n", name);
                  for (int i = 0; i < ip_size; i++)
                     printf("\t%s\n", IPs[i]);
               }
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
      -p [hostname]               - ping hostname\n\
      -o [hostname] [start] [end] - scan open ports\n\
      -l [hostname]               - list available IPs\n\n\
   example: %s -o google.com 75 90\n", argv);
}
