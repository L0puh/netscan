#include "netscan.h"
#include "utils.h"

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>

#define BUFFER_SIZE 1500
static struct TRACEROUTE_GLOBAL global;

int recv_udp(int seq, struct timeval *time){
   int header_len, icmp_len;
   socklen_t len;
   int code, bytes;
   struct icmp *icmp;
   struct ip *ip, *hip;
   struct udphdr *udp;
   char buffer[BUFFER_SIZE];

   global.is_alrm = 0;
   alarm(1);
   
   while(1){
      if (global.is_alrm) return -3;
      len = sizeof(struct sockaddr);
      ASSERT((bytes = recvfrom(global.sockfd_recv, buffer, BUFFER_SIZE, 0, global.recv_addr, &len)));
      
      ip = (struct ip*) buffer;
      header_len = ip->ip_hl << 2;
      icmp = (struct icmp*) (buffer + header_len);
      if ( (icmp_len = bytes - header_len) < 8) continue;
      
      if (icmp->icmp_type == ICMP_TIMXCEED && icmp->icmp_code == ICMP_TIMXCEED_INTRANS){
         if (icmp_len < 8 + sizeof(struct ip)) continue;

         hip = (struct ip*) (buffer + header_len + 8);
         if (icmp_len < 8 + (hip->ip_hl << 2) + 4) continue;

         udp = (struct udphdr*) (buffer + (hip->ip_hl<<2) + 8 + header_len);
         if (hip->ip_p == IPPROTO_UDP && udp->uh_sport == htons(global.port) &&
               udp->uh_dport == htons(PORT + seq)) {
            code = -2; break;
         }

      } else if (icmp->icmp_type == ICMP_UNREACH){
         if (icmp_len < 8 + sizeof(struct ip)) continue;

         hip = (struct ip*) (buffer + header_len + 8);
         if (icmp_len < 8 + (hip->ip_hl << 2) + 4) continue;

         udp = (struct udphdr*)(buffer + header_len + 8 + (hip->ip_hl << 2));
         if (hip->ip_p == IPPROTO_UDP &&
            udp->uh_sport == htons(global.port) &&
            udp->uh_dport == htons(PORT + seq))
         {
            if (icmp->icmp_code == ICMP_UNREACH_PORT) code = -1;
            else code = icmp->icmp_code;
            break;

         }
      }
      printf(" (from %s: type: %d, code: %d)\n", get_hostname(global.recv_addr), icmp->icmp_type,
            icmp->icmp_code);
   }
   alarm(0);
   gettimeofday(time, NULL);
   return code;
}

void send_loop(int max_ttl){
   double rtt;
   int seq, done, code;
   struct sockaddr* last_addr;
   char sendbuffer[BUFFER_SIZE], *hostname, *ip_str;
   upd_packet_t *pck;
   struct timeval time_recv;
  
   last_addr = calloc(1, sizeof(struct sockaddr));
   seq = done = 0;

   for (int ttl = 1; ttl <= max_ttl; ttl++){
      if (global.send_addr->sa_family == AF_INET)
         setsockopt(global.sockfd_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
      else 
         setsockopt(global.sockfd_send, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));

      printf("\t[%d] ", ttl);
      fflush(stdout);

      for (int probe = 0; probe < MAX_PROBES; probe++){
         pck = (upd_packet_t*) sendbuffer;
         pck->seq = ++seq;
         pck->ttl = ttl;
         gettimeofday(&pck->time, NULL);
         set_port(global.send_addr, seq + PORT);
         ASSERT(sendto(global.sockfd_send, sendbuffer, 
               sizeof(upd_packet_t), 0, global.send_addr, sizeof(struct sockaddr)));
        
         /* TODO: */
         /* if (global.send_addr->sa_family == AF_INET) */
            code = recv_udp(seq, &time_recv);
         /* else */ 
            /* code = recv_udp_v6(seq, &time_recv); */

         hostname = get_hostname(global.recv_addr);
         ip_str = get_addr_str(global.recv_addr);
         if (code == -3) printf(" *");
         else {
            if (cmp_addr(global.recv_addr, last_addr) != 0){ 
               printf(" %s (%s)", hostname ? hostname : ip_str, ip_str);
               memcpy(last_addr, global.recv_addr, sizeof(struct sockaddr));
            }
            time_difference(&time_recv, &pck->time);
            rtt = time_recv.tv_sec * 1000.0 + time_recv.tv_usec / 1000.0;
            printf(" %.3fms", rtt);
            if (code == -1) done++;
            /*TODO: else if (code >= 0) printf(" (ICMP %s)", get_icmp_code(code)); */ 
         }

         fflush(stdout);
      }
      printf("\n");
   }
}

void traceroute(char* host, int max_ttl){
   int datalen;
   struct addrinfo* addr; 

   global.pid = getpid();

   addr = get_addr_by_name(host);
   if (addr->ai_addr == NULL) {
      log_info(__func__, "corrupted address");
      return;
   }
   
   datalen = sizeof(upd_packet_t);
   global.send_addr = addr->ai_addr;
   global.bind_addr = calloc(1, addr->ai_addrlen);
   global.recv_addr = calloc(1, addr->ai_addrlen);
   global.port = (global.pid & 0xffff) | 0x8000;
   
   printf("traceroute to %s (%s), port: %d: %d hops max; %d bytes\n",
                     addr->ai_canonname ? addr->ai_canonname: host,
                     get_addr_str(addr->ai_addr), global.port, max_ttl, datalen);
  
   if (addr->ai_flags == AF_INET) init_traceroute_socket_v4();
   else                           init_traceroute_socket_v6();
   
   signal(SIGALRM, trace_alrm);
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
