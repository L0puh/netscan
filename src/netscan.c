#include "netscan.h"

#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>


int get_ip_version(const char* host){
   unsigned char buf[sizeof(struct in6_addr)];
   if (inet_pton(AF_INET, host, &buf) == 0){
      return AF_INET6;
   }
   return AF_INET;
}

int get_open_ports(const char* ip, int range, int *ports){
   int family, len = 0;

   if (range == 0 || ports == NULL || ip == NULL) return -1;
   if (range > 65535) {
      printf("impossible range\n");
      return -1;
   }

   family = get_ip_version(ip); 
   for (int i = 0; i <= range; i++){
      int sockfd = socket(family, SOCK_STREAM, 0);
      if (family == AF_INET){
         struct sockaddr_in server_addr;
         bzero(&server_addr, sizeof(server_addr));
         server_addr.sin_family = family;
         server_addr.sin_port = htons(i); 
         inet_pton(family, ip, &server_addr.sin_addr); 
         if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
            ports[len++] = i;
         } 
      } else {
         struct sockaddr_in6 server_addr;
         bzero(&server_addr, sizeof(server_addr));
         server_addr.sin6_family = family;
         server_addr.sin6_port = htons(i); 
         inet_pton(family, ip, &server_addr.sin6_addr); 
         if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
            ports[len++] = i;           
         } 
      }
      close(sockfd);
   }
   return len; 
}

char* get_addr_str(struct addrinfo *addr, int* len){
   char* buffer;
   struct sockaddr_in *saddr;

   saddr = (struct sockaddr_in*) addr->ai_addr;
   *len = INET_ADDRSTRLEN;
  
   if (addr->ai_family == AF_INET6)
      *len = INET6_ADDRSTRLEN;
   
   buffer = malloc(*len * CHAR_BIT);
   inet_ntop(addr->ai_family, &saddr->sin_addr, buffer, *len);
   return buffer;
}

/* get ip addresses by hostname (IPv4 and IPv6) */
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
      buff = get_addr_str(addr, &len);
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
