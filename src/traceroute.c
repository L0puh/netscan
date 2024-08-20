#include "netscan.h"
#include "utils.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>

static struct TRACEROUTE_GLOBAL global;

int recv_udp(int seq, struct timeval *time){
   int code;

   return code;
}

void send_loop(int max_ttl){
   int seq, done, code;
   char sendbuffer[1500];
   upd_packet_t *pck;
   struct timeval time_recv;
   
   seq = done = 0;

   for (int ttl = 1; ttl <= max_ttl; ttl++){
      if (global.addr->sa_family == AF_INET)
         setsockopt(global.sockfd_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
      else 
         setsockopt(global.sockfd_send, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));

      bzero(&global.last_addr, sizeof(*global.last_addr));
      printf("%2d ", ttl);
      fflush(stdout);

      for (int probe = 0; probe < MAX_PROBES; probe++){
         pck = (upd_packet_t*) sendbuffer;
         pck->seq = ++seq;
         pck->ttl = ttl;
         gettimeofday(&pck->time, NULL);
         set_port(global.addr, seq + PORT);
         ASSERT(sendto(global.sockfd_send, sendbuffer, 
               sizeof(upd_packet_t), 0, global.addr, sizeof(*global.addr)));
         code = recv_udp(seq, &time_recv);
         if (code == -3) printf(" *");
         else {
         }
         

      }
   }
}

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
   global.bind_addr = calloc(1, addr->ai_addrlen);
   global.port = (global.pid & 0xffff) | 0x8000;
   global.is_alrm = 0;
   
   printf("traceroute to %s (%s), port: %d: %d hops max; %d bytes\n",
                     addr->ai_canonname ? addr->ai_canonname: host,
                     get_addr_str(addr->ai_addr), global.port, max_ttl, datalen);
  
   if (addr->ai_flags == AF_INET) init_traceroute_socket_v4();
   else                           init_traceroute_socket_v6();
   
   set_port(global.bind_addr, global.port);
   setuid(getuid());

   global.bind_addr->sa_family = addr->ai_family;
   ASSERT(bind(global.sockfd_send, global.bind_addr, addr->ai_addrlen));
   
   trace_alrm(SIGALRM);
   send_loop(max_ttl);
}

void init_traceroute_socket_v4(){
   global.sockfd_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
   global.sockfd_send = socket(AF_INET, SOCK_DGRAM, 0);
}

void init_traceroute_socket_v6(){
   struct icmp6_filter filter;
   global.sockfd_recv = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
   global.sockfd_send = socket(AF_INET6, SOCK_DGRAM, 0);

   ICMP6_FILTER_SETBLOCKALL(&filter);
   ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &filter);
   ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filter);
   setsockopt(global.sockfd_recv, IPPROTO_IPV6, ICMP6_FILTER, 
                                    &filter, sizeof(filter));
}

void trace_alrm(int signo){
   global.is_alrm = 1;
   return;
}
