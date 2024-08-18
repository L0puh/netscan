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
   if (inet_pton(AF_INET, host, &buf) == 0)
      return AF_INET6;
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
      timeout.tv_sec = 1; timeout.tv_usec = 0;
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


char* get_hostname(struct sockaddr* in_addr){
   int ret_code;
   socklen_t addrlen = sizeof(*in_addr);
   char *host = malloc(NI_MAXHOST);;
   char serv[NI_MAXSERV];

   if (in_addr->sa_family == AF_INET6) return NULL;

	if ((ret_code = getnameinfo(in_addr, addrlen, host, NI_MAXHOST, serv, NI_MAXSERV, 0)) != 0){
      log_info("getnameinfo failed", gai_strerror(ret_code));
      return NULL;
   }
   return host;
}

char* get_addr_str(struct sockaddr* in_addr){
   char* str;
   struct addrinfo *addrinfo;
   switch(in_addr->sa_family){
      case AF_INET: 
         {
            str = malloc(INET_ADDRSTRLEN);
            struct sockaddr_in *addr = (struct sockaddr_in*) in_addr;
            inet_ntop(AF_INET, &addr->sin_addr, str, INET_ADDRSTRLEN);
            return str;
         
         }
      case AF_INET6:
         {
            str = malloc(INET6_ADDRSTRLEN);
            struct sockaddr_in6 *addr = (struct sockaddr_in6*) in_addr;
            inet_ntop(AF_INET6, &addr->sin6_addr, str, INET6_ADDRSTRLEN);
            return str;
         }
      default:
         return NULL;

   }

   return NULL;
}

/* get ip addresses by hostname (IPv4 and IPv6) */
struct addrinfo* get_addr_by_name(const char* name){
   struct addrinfo hints, *addr;
   
   bzero(&hints, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_flags =  AI_CANONNAME;
  
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
      buff = get_addr_str(addr->ai_addr);
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


