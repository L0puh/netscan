#include "netscan.h"
#include "utils.h"

#include <ctype.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <sys/socket.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>


int get_ip_version(const char* host){
   unsigned char buf[sizeof(struct in6_addr)];
   if (inet_pton(AF_INET, host, &buf) == 0){
      return AF_INET6;
   }
   return AF_INET;
}


int get_open_ports(const char* ip, int start, int end, int *ports){
   struct timeval timeout;
   struct hostent *host;
   struct sockaddr_in server_addr;
   int family, len, buff_size, sockfd;

   if (end == 0 || ports == NULL || ip == NULL) {
      log_info(__func__, "unable to perform port scanning\n");
      return -1;
   }
   if (end > 65535) {
      log_info(__func__, "impossible range\n");
      return -1;
   }
  
   bzero(&server_addr, sizeof(server_addr));
   server_addr.sin_family = AF_INET;
   
   if (isdigit(ip[0])){
      server_addr.sin_addr.s_addr = inet_addr(ip);
   } else if ((host = gethostbyname(ip)) != 0){
      strncpy((char*)&server_addr.sin_addr, (char*)host->h_addr, sizeof server_addr.sin_addr);
   }

   len = 0;
   for (int i = start; i <= end; i++){
      server_addr.sin_port = htons(i);

      sockfd = socket(AF_INET, SOCK_STREAM, 0);
      timeout.tv_sec = 1; timeout.tv_usec = 1;
      setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
      setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

      ASSERT(sockfd);
      if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
         ports[len++] = i;
      }
      close(sockfd);
   }
   return len; 
}


char* get_addr_str(struct addrinfo *addr, int* len){
   char* buffer;
  
   if (addr->ai_family == AF_INET){
      *len = INET_ADDRSTRLEN;
      struct sockaddr_in *saddr = (struct sockaddr_in*) addr->ai_addr;
      buffer = malloc(*len * CHAR_BIT);
      inet_ntop(addr->ai_family, &saddr->sin_addr, buffer, *len);
   }
   else {
      *len = INET6_ADDRSTRLEN;
      struct sockaddr_in6 *saddr = (struct sockaddr_in6*) addr->ai_addr;
      buffer = malloc(*len * CHAR_BIT);
      inet_ntop(addr->ai_family, &saddr->sin6_addr, buffer, *len);
   }
   return buffer;
}

/* get ip addresses by hostname (IPv4 and IPv6) */
struct addrinfo* get_addr_by_name(const char* name){
   struct addrinfo hints, *addr;
   
   bzero(&hints, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_flags = AI_CANONNAME;
  
   if (getaddrinfo(name, NULL, &hints, &addr) == -1){
      log_info("getaddrinfo failed", gai_strerror(errno));
      return NULL;
   }
   
   return addr;
}

char* get_ips_by_name(const char* name, char* IPs[], int *IPs_size){
   int res, len, i;
   char *cannonname, *buff;
   struct addrinfo hints, *addr;
   
   addr = get_addr_by_name(name); 
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



void get_options(){
   printf("[1] port scanning\n");
   printf("[2] list IPs of a hostname\n");
   printf("[3] ping hostname\n");
   printf("> ");
   int choice;
   scanf("%d", &choice);
   switch(choice){
      case 1:
         {
            int end, start, len;
            char* hostname = malloc(240);

            printf("\nenter hostname: ");
            scanf("%s", hostname);
            printf("enter start of range: ");
            scanf("%d", &start);
            printf("enter end of range: ");
            scanf("%d", &end);

            int ports[end-start+1];
            len = get_open_ports(hostname, start, end, ports);
            if (len == -1)
               printf("\n[-] error in getting open ports\n");
            else if (len == 0) 
               printf("[-] no open ports were found\n");
            else {
               printf("\n[+] open ports: \n");
               for (int i = 0; i < len; i++){
                  printf("\tport %d is open\n", ports[i]);
               }
            }
            free(hostname);
            break;
         }
      case 2:
         {
            int ip_size;
            char *name, *hostname, *IPs[MAX_IPS];;
            hostname = malloc(240);
            printf("enter hostname: ");
            scanf("%s", hostname);
            name = get_ips_by_name(hostname, IPs, &ip_size);
            if (name != NULL){
               printf("%s\n", name);
               for (int i = 0; i < ip_size; i++)
                  printf("\t%s\n", IPs[i]);
            }
            free(hostname);
            break;
         }
      case 3: 
         {
            char* hostname;
            hostname = malloc(240);
            printf("enter hostname: ");
            scanf("%s", hostname);
            ping(hostname);
            free(hostname);
            break;
         }
      default:
         printf("option doesn't exist, try again\n");
   }

}


