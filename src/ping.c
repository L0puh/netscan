/**********************************

TODO:

note: compile and run 
      with sudo permissions

- support for IPv6
 ***********************************/


#include "netscan.h"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>


struct PING_GLOBAL global;

void ping(char* host){
   
   pid_t pid;
   int sockfd, size, len;
   struct addrinfo *addr;

   if (inet_addr(host) == INADDR_NONE){ 
      addr = get_addr_by_name(host);
   } else {
      //TODO FOR IPS
      log_info(__func__, "IP HOST IS NOT SUPPORTED YET");
      return;
   }
   
   if (addr->ai_family == AF_INET)
      sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
   else 
      sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  
   ASSERT(sockfd);
   size = 50*1024;
   setuid(getuid());

   ASSERT(setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)));

   printf("PING %s(%s): %d bytes\n", 
               addr->ai_canonname ? addr->ai_canonname: host, 
               get_addr_str(addr->ai_addr), DATALEN);

   signal(SIGALRM, sig_alrm);
   signal(SIGINT, sig_termination);
   global.pid = getpid() & 0xffff;
   global.sockfd = sockfd;
   global.addr = addr;
   global.received_packets = 0;
   global.sent_packets = 0;
   recv_packet(sockfd);
   sig_alrm(SIGALRM);
   
   return;
}

void sig_termination(int signo){
   printf("\nstatistics:\n\tsent: %d;\n\treceived: %d\n\t%.2f%% lost\n", global.sent_packets, global.received_packets,
            ((float)(global.sent_packets-global.received_packets)/global.sent_packets)*100.f);
   exit(0);
}

void sig_alrm(int signo){
   send_packet(global.sockfd, global.addr);
   alarm(WAIT_TIME);
}

void time_difference(struct timeval* out, struct timeval *in){
   out->tv_usec -= in->tv_usec;
   if (out->tv_usec < 0){
      --out->tv_sec;
      out->tv_usec += 1000000;
   }
   out->tv_sec-=in->tv_sec;
}


int process_packet(char *buffer, int len, struct timeval* recv_time, struct sockaddr *from_addr){
   double rtt;
   char* hostname;
   int header_len, str_len;

   struct ip *ip;
   struct icmp *icmp;
   struct timeval *sent_time;

   ip = (struct ip*) buffer;
   if (ip->ip_p != IPPROTO_ICMP && ip->ip_p != IPPROTO_ICMPV6)
      return -1;

   header_len = ip->ip_hl << 2;
   icmp = (struct icmp*) (buffer + header_len);
   len -= header_len;
   if (len < 8){
      log_info(__func__, "corrupted ICMP packet");
      return -1;
   }
   if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == global.pid) ){ 

      sent_time = (struct timeval*)icmp->icmp_data;
      time_difference(recv_time, sent_time);
      rtt = recv_time->tv_sec*1000.0 + recv_time->tv_usec/1000.0;
      hostname = get_hostname(from_addr);

      printf("%d bytes from %s: icmp_seq=%u ttl=%d rtt=%.2f ms\n",
            len, hostname ? hostname: get_addr_str(from_addr), icmp->icmp_seq, ip->ip_ttl, rtt);

   } else {
      printf("%d bytes: type = %d, code = %d\n", len, icmp->icmp_type, icmp->icmp_code);
      return -1;
   }
   return 0;
}

void recv_packet(int sockfd){
   int bytes;
   socklen_t addrlen;
   extern int errno;
   struct timeval timeval;
   struct sockaddr_storage addr;
   char recvbuff[PACKET_SIZE];

   sig_alrm(SIGALRM);
  
   while(1){
      addrlen = sizeof(addr);
      ASSERT((bytes = recvfrom(sockfd, recvbuff, sizeof(recvbuff), 0, 
                     (struct sockaddr*)&addr, &addrlen)));
      gettimeofday(&timeval, NULL);
      process_packet(recvbuff, bytes, &timeval, (struct sockaddr*) &addr);
      global.received_packets++;
   }
}

void send_packet(int sockfd, struct addrinfo *addr){
   int size;
   struct icmp *icmp;
   char sendbuf[PACKET_SIZE];

   icmp = (struct icmp *) sendbuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = global.pid;
	icmp->icmp_seq = global.sent_packets++;
	memset(icmp->icmp_data, 0xa5, DATALEN);	
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);

	size = 8 + DATALEN;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = get_checksum((u_short *) icmp, size);
  
   ASSERT(sendto(sockfd, sendbuf, size, 0, addr->ai_addr, addr->ai_addrlen));
}

unsigned short get_checksum(unsigned short *addr, size_t len){
   int sum;
   unsigned short *ptr = addr, res;

   sum = res = 0;
   while (len > 1){
      sum += *ptr++;
      len-=2;
   }
   if (len == 1){
      *(unsigned char*) (&res) = *(unsigned char*)ptr;
      sum += res;
   }
   sum = (sum >> 16) + (sum&0xffff);
   sum += (sum>>16);
   res = ~sum;
   return res;
}
