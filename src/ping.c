/**********************************
TODO:
- support for IPv6
- send and receive based on signals 
                     (not the query)
 ***********************************/


#include "netscan.h"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#define DATALEN 56
#define PACKETS_COUNT 5
#define PACKET_SIZE 4096
#define WAIT_TIME 3

struct PING_GLOBAL{
   int received_packets;
   int sent_packets;
   pid_t pid;
};

struct PING_GLOBAL global;

void recv_packet(int sockfd);
void send_packet(int sockfd, struct addrinfo*);
void sig_alrm(int signo);


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
   
   if (addr->ai_family == AF_INET){
      sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
   } else {
      sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
   }
   
   ASSERT(sockfd);
   size = 50*1024;
   setuid(getuid());

   ASSERT(setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)));

   printf("PING %s(%s): %d bytes\n", 
               addr->ai_canonname ? addr->ai_canonname: host, 
               get_addr_str(addr, &len), DATALEN);

   global.pid = getpid() & 0xffff;
   send_packet(sockfd, addr);
   recv_packet(sockfd);
   sig_alrm(SIGALRM);

   return;
}

void sig_alrm(int signo){
   printf("SENT: %d RECIEVED: %d %d%% lost\n", global.sent_packets, global.received_packets,
            (global.sent_packets-global.received_packets)/global.sent_packets*100);
   exit(0);
}

void time_difference(struct timeval* out, struct timeval *in){
   out->tv_usec -= in->tv_usec;
   if (out->tv_usec < 0){
      --out->tv_sec;
      out->tv_usec += 1000000;
   }
   out->tv_sec-=in->tv_sec;
}

int process_packetv4(char *buffer, int len, struct timeval* recv_time){
   double rtt;
   int header_len;

   struct ip *ip;
   struct icmp *icmp;
   struct timeval *sent_time;

   ip = (struct ip*) buffer;
   if (ip->ip_p != IPPROTO_ICMP)
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
      rtt = recv_time->tv_sec*1000 + (double)recv_time->tv_usec/100;
      printf("%d bytes: icmp_seq=%u ttl=%d rtt=%.3f ms\n",
            len, icmp->icmp_seq, ip->ip_ttl, rtt);
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
   struct sockaddr_in addr;
   char recvbuff[PACKET_SIZE];

   signal(SIGALRM, sig_alrm);
   
   addrlen = sizeof(addr);
   global.received_packets = 0;
   while (global.received_packets < global.sent_packets) {
      alarm(WAIT_TIME);
      ASSERT((bytes = recvfrom(sockfd, recvbuff, sizeof(recvbuff), 0, 
                     (struct sockaddr*)&addr, &addrlen)));
      gettimeofday(&timeval, NULL);
      if (process_packetv4(recvbuff, bytes, &timeval) == -1) continue;
      global.received_packets++;
   }
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

void send_packet(int sockfd, struct addrinfo *addr){
   int size;
   struct icmp *icmp;
   char sendbuff[PACKET_SIZE];
  
   size = 8 + DATALEN;
   global.sent_packets = 0;
   
   while(global.sent_packets < PACKETS_COUNT){
      icmp = (struct icmp*) sendbuff;
      icmp->icmp_type = ICMP_ECHO;
      icmp->icmp_code = 0;
      icmp->icmp_cksum = 0;
      icmp->icmp_id = global.pid;
      gettimeofday((struct timeval*) icmp->icmp_data, NULL);
      icmp->icmp_cksum = get_checksum((unsigned short*) icmp, 8+DATALEN);
      icmp->icmp_seq = global.sent_packets++;
      ASSERT(sendto(sockfd, sendbuff, size, 0, addr->ai_addr, addr->ai_addrlen));
      sleep(1);
   }
}
