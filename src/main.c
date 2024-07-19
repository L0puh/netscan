#include "netscan.h"
#include <stdio.h>

int main(int argc, char* argv[]) {
   int ip_size;
   char *IPs[MAX_IPS];
   
   char* name = get_addr_by_name(argv[1], IPs, &ip_size);

   if (name != NULL){
      printf("%s\n", name);
      for (int i = 0; i < ip_size; i++)
         printf("\t%s\n", IPs[i]);
   }

   return 0;
}
