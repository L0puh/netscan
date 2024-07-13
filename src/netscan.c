#include "netscan.h"
#include <netinet/in.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

char* get_host(const char* name, char* IPs[], int *IPs_size, char* aliases[], int *aliases_size){
   int res;
   struct hostent *host;
   char **p_addr; 
   char addr[INET6_ADDRSTRLEN];
   if ( (host = gethostbyname(name)) == NULL){
      printf("error in gethostbyname: %s\n", hstrerror(h_errno));
      return NULL;
   }

   *IPs_size = 0; *aliases_size = 0;
   for (p_addr = host->h_aliases; *p_addr != NULL && *aliases_size < 10; p_addr++, (*aliases_size)++){
      aliases[*aliases_size] = *p_addr;
   }
   p_addr = host->h_addr_list;
   switch(host->h_addrtype){
      case AF_INET:
         for (; *p_addr != NULL && *IPs_size < 10; p_addr++, (*IPs_size)++){
            const char* addr_str = inet_ntop(host->h_addrtype, *p_addr, addr, INET_ADDRSTRLEN);
            IPs[*IPs_size] = malloc(INET_ADDRSTRLEN * sizeof(char));
            strcpy(IPs[*IPs_size], addr_str);
         }
         break;
      case AF_INET6: 
         for (; *p_addr != NULL && *IPs_size < 10; p_addr++, (*IPs_size)++){
            const char* addr_str = inet_ntop(host->h_addrtype, *p_addr, addr, INET6_ADDRSTRLEN);
            IPs[*IPs_size] = malloc(INET6_ADDRSTRLEN * sizeof(char));
            strcpy(IPs[*IPs_size], addr_str);
         }
         break;

   }
   char* host_name = malloc(strlen(host->h_name) * sizeof(char));
   strcpy(host_name, host->h_name);
   return host_name;
}

