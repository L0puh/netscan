#include "netscan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

char* get_addr_by_name(const char* name, char* IPs[], int *IPs_size){
   int res, len, i;
   char *cannonname, *buff;
   struct addrinfo hints, *addr;
   bzero(&hints, sizeof(hints));
   hints.ai_flags = AI_CANONNAME;
   hints.ai_family = AF_UNSPEC;
  
   if (getaddrinfo(name, NULL, &hints, &addr) == -1){
      printf("error in getaddrinfo: %s\n", gai_strerror(errno));
      return NULL;
   }
  
   cannonname = malloc(strlen(addr->ai_canonname) * CHAR_BIT);
   strcpy(cannonname, addr->ai_canonname);

   *IPs_size = 0; i = 0;
   do {
      struct sockaddr_in *saddr = (struct sockaddr_in*) addr->ai_addr;
      len = INET_ADDRSTRLEN;
     
      if (addr->ai_family == AF_INET6)
         len = INET6_ADDRSTRLEN;
      
      buff = malloc(len);
      inet_ntop(addr->ai_family, &saddr->sin_addr, buff, len);

      if (i == 0 || strcmp(buff, IPs[i-1]) != 0){
         IPs[i] = malloc(len);
         strcpy(IPs[i++], buff);
      }
      free(buff);
   } while ((addr = addr->ai_next) != NULL && i+1 < MAX_IPS);
   *IPs_size = i;
   freeaddrinfo(addr);
   return cannonname;
}
