#include "netscan.h"
#include "utils.h"

#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

typedef struct {
   unsigned short seq;
   unsigned short ttl;
   struct timeval time;
} upd_packet_t;


struct TRACEROUTE_GLOBAL {
   int port;
   int is_alrm;
   pid_t pid;

   int packets_sent;
   int sockfd_recv;
   int sockfd_send;
   struct sockaddr* addr;
   struct sockaddr* bind_addr;
};

static struct TRACEROUTE_GLOBAL global;

void trace_alrm(int signo){
   global.is_alrm = 1;
   return;
}

void init_traceroute_socket_v4();
void init_traceroute_socket_v6();

void traceroute(char* host, int max_ttl){
   int datalen;
   struct addrinfo* addr; 

   global.pid = getpid();
   signal(SIGALRM, trace_alrm);

   addr = get_addr_by_name(host);
   if (addr->ai_addr == NULL) {
      log_info(__func__, "corrupted address");
      return;
   }
   
   datalen = sizeof(upd_packet_t);
   global.addr = addr->ai_addr;
   global.port = (global.pid & 0xffff) | 0x8000;
   global.is_alrm = 0;
   
   printf("traceroute to %s (%s), port: %d: %d hops max; %d bytes\n",
            addr->ai_canonname ? addr->ai_canonname: host,
            get_addr_str(addr->ai_addr), global.port, max_ttl, datalen);
  
   if (addr->ai_flags == AF_INET){
      init_traceroute_socket_v4();
   } else {
      init_traceroute_socket_v6();
   }
   setuid(getuid());

   global.bind_addr->sa_family = addr->ai_family;
   ASSERT(bind(global.sockfd_send, global.bind_addr, addr->ai_addrlen));
   
   trace_alrm(SIGALRM);

}

void init_traceroute_socket_v4(){
   struct sockaddr_in* addr;

   global.sockfd_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
   global.sockfd_send = socket(AF_INET, SOCK_DGRAM, 0);
   
   addr = (struct sockaddr_in*) global.bind_addr;
   addr->sin_port = htons(global.port);

}

void init_traceroute_socket_v6(){
   struct sockaddr_in6* addr;
   struct icmp6_filter filter;
   global.sockfd_recv = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
   global.sockfd_send = socket(AF_INET6, SOCK_DGRAM, 0);

   ICMP6_FILTER_SETBLOCKALL(&filter);
   ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &filter);
   ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filter);
   setsockopt(global.sockfd_recv, IPPROTO_IPV6, ICMP6_FILTER, 
                                    &filter, sizeof(filter));
  
   addr = (struct sockaddr_in6*) global.bind_addr;
   addr->sin6_port = htons(global.port);

}
