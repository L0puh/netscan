#include "netscan.h"
#include <stdio.h>

int main(int argc, char* argv[]) {
   char *IPs[10], *aliases[10];
   int ip_size, aliases_size;
   
   char* name = get_host(argv[1], IPs, &ip_size, aliases, &aliases_size);

   if (name != NULL){
      printf("%s\n", name);
      for (int i = 0; i < ip_size; i++)
         printf("\t%s\n", IPs[i]);
      for (int i = 0; i < aliases_size; i++)
         printf("\t%s\n", aliases[i]);
   }
   return 0;
}
