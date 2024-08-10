#include "netscan.h"
#include <stdio.h>

int main(int argc, char* argv[]) {
   int ip_size, range = 65535, len;
   char *IPs[MAX_IPS], *name;
   
   name = get_addr_by_name(argv[1], IPs, &ip_size);
   if (name != NULL){
      printf("%s\n", name);
      for (int i = 0; i < ip_size; i++)
         printf("\t%s\n", IPs[i]);
   }
   
   int ports[range];
   len = get_open_ports(argv[1], range, ports);
   if (len == -1){
      printf("error in getting open ports\n");
   } else {
      printf("open ports: \n");
      for (int i = 0; i < len; i++){
         printf("\tport %d is open\n", ports[i]);
      }
   }
   
   
   return 0;
}
