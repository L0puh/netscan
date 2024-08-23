#include "netscan.h"
#include "utils.h"

#include <arpa/inet.h>
#include <netdb.h>


#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>


static struct PING_GLOBAL global;


int init_ping_socket_v4(int rcvfbuf_size){
   int sockfd;

   sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
   ASSERT(sockfd);
   ASSERT(setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvfbuf_size, sizeof(rcvfbuf_size)));

   return sockfd;
}

int init_ping_socket_v6(int rcvfbuf_size){
   int sockfd, on;

   sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
   ASSERT(sockfd);
   ASSERT(setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvfbuf_size, sizeof(rcvfbuf_size)));

   struct icmp6_filter filter;
   ICMP6_FILTER_SETBLOCKALL(&filter);
   ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
   setsockopt(sockfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
   on = 1;

#ifdef IPV6_RECVHOPLIMIT 
   setsockopt(sockfd, IPPROTO_ICMPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));
#else 
   setsockopt(sockfd, IPPROTO_ICMPV6, IPV6_HOPLIMIT, &on, sizeof(on));
#endif
   return sockfd;
}

void ping(char* host){
   pid_t pid;
   int sockfd, len, size;
   struct addrinfo *addr;

   addr = get_addr_by_name(host);
   
   if (addr->ai_addr == NULL){
      log_info(__func__, "corrupted address, unable to reach");
      return;
   }

   size = 50*1024;
   if (addr->ai_family == AF_INET)
      sockfd = init_ping_socket_v4(size);
   else 
      sockfd = init_ping_socket_v6(size);
   
   setuid(getuid());
   
   printf("PING %s(%s): %d bytes\n", 
               addr->ai_canonname ? addr->ai_canonname: host, 
               get_addr_str(addr->ai_addr), DATALEN);

   signal(SIGALRM, sig_alrm);
   signal(SIGINT, sig_int);
   global.pid = getpid() & 0xffff;
   global.sockfd = sockfd;
   global.addr = addr;
   global.received_packets = 0;
   global.sent_packets = 0;
   recv_packet(sockfd);
   sig_alrm(SIGALRM);
   
   return;
}

void sig_int(int signo){
   printf("\nstatistics:\n\tsent: %d;\n\treceived: %d\n\t%.2f%% lost\n", global.sent_packets, global.received_packets,
            ((float)(global.sent_packets-global.received_packets)/global.sent_packets)*100.f);
   exit(0);
}

void sig_alrm(int signo){
   if (global.addr->ai_family == AF_INET)
      send_packet_v4(global.sockfd, global.addr);
   else 
      send_packet_v6(global.sockfd, global.addr);
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

int process_packet_v6(char *buffer, int len, struct timeval* recv_time, struct sockaddr *from_addr, struct msghdr* msg){
   double rtt;
   int hop_limit;
   char* hostname;
   struct icmp6_hdr *icmp6;
   struct timeval *sent_time;
   struct cmsghdr *cmsg;

   icmp6 = (struct icmp6_hdr*) buffer;
   if (icmp6->icmp6_type == ICMP6_ECHO_REPLY){
      if (icmp6->icmp6_id != global.pid || len < 16) 
         return -1;
   } else if (len < 8) {
      log_info(__func__, "corrupted ICMP6 packet");
      return -1;
   }

   printf("[IPv6] ");
   if (icmp6->icmp6_type == ICMP6_ECHO_REPLY){
      sent_time = (struct timeval*) (icmp6+1);
      time_difference(recv_time, sent_time);
      rtt = recv_time->tv_sec*1000.0 + recv_time->tv_usec/1000.0;
      
      for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)){
         if (cmsg->cmsg_level == IPPROTO_ICMPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT){
            hop_limit = *(u_int32_t*) CMSG_DATA(cmsg);
            break;
         }
      }
      hostname = get_hostname(from_addr);
      printf("%d bytes from %s: icmp_seq=%u hlim=%d rtt=%.2f ms\n",
            len, hostname ? hostname: get_addr_str(from_addr), icmp6->icmp6_seq, hop_limit, rtt);
      global.received_packets++;

   } else {
      printf("%d bytes: type = %d, code = %d\n", len, icmp6->icmp6_type, icmp6->icmp6_code);
   }

   return 0;

}

int process_packet_v4(char *buffer, int len, struct timeval* recv_time, struct sockaddr *from_addr){
   double rtt;
   char* hostname;
   int header_len, str_len;

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
   printf("[IPv4] ");
   if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == global.pid) ){ 

      sent_time = (struct timeval*)icmp->icmp_data;
      time_difference(recv_time, sent_time);
      rtt = recv_time->tv_sec*1000.0 + recv_time->tv_usec/1000.0;
      hostname = get_hostname(from_addr);

      printf("%d bytes from %s: icmp_seq=%u ttl=%d rtt=%.2f ms\n",
            len, hostname ? hostname: get_addr_str(from_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
      global.received_packets++;

   } else {
      printf("%d bytes: type = %d, code = %d\n", len, icmp->icmp_type, icmp->icmp_code);
   }
   return 0;
}

void recv_packet(int sockfd){
   int bytes;
   socklen_t addrlen;
   struct msghdr msg;
   struct iovec iov;
   struct timeval timeval;
   struct sockaddr_storage addr;
   char recvbuff[PACKET_SIZE], controlbuff[PACKET_SIZE];

   sig_alrm(SIGALRM);

   iov.iov_base = recvbuff;
   iov.iov_len = sizeof(recvbuff);
   msg.msg_name = (struct sockaddr*)&addr; 
   msg.msg_iov = &iov;
   msg.msg_iovlen = 1;
   msg.msg_control = controlbuff;
  
   while(1){
      msg.msg_namelen = global.addr->ai_addrlen; 
      msg.msg_controllen = sizeof(controlbuff);
      addrlen = sizeof(addr);
      ASSERT((bytes = recvmsg(sockfd, &msg, 0)));
      gettimeofday(&timeval, NULL);
      if (addr.ss_family == AF_INET)
         process_packet_v4(recvbuff, bytes, &timeval, (struct sockaddr*) &addr);
      else 
         process_packet_v6(recvbuff, bytes, &timeval, (struct sockaddr*) &addr, &msg);
   }
}

void send_packet_v6(int sockfd, struct addrinfo *addr){
   int size;
   struct icmp6_hdr *icmp;
   char sendbuf[PACKET_SIZE];

   icmp = (struct icmp6_hdr*) sendbuf;;
   icmp->icmp6_type = ICMP6_ECHO_REQUEST;
   icmp->icmp6_code = 0;
	icmp->icmp6_id = global.pid;
	icmp->icmp6_seq = global.sent_packets++;
	memset((icmp+1), 0xa5, DATALEN);	
   gettimeofday((struct timeval*) (icmp+1), NULL);
   
   size = 8 + DATALEN;
   
   ASSERT(sendto(sockfd, sendbuf, size, 0, addr->ai_addr, addr->ai_addrlen));
}
void send_packet_v4(int sockfd, struct addrinfo *addr){
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

unsigned short get_checksum(unsigned short *data, size_t len){
   int sum;
   unsigned short *ptr = data, res;

   sum = res = 0;
   while (len > 1){
      sum += *ptr++;
      len-=2;
   }
   if (len == 1){
      *(unsigned char*) (&res) = *(unsigned char*)ptr;
      sum += res;
   }
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum>>16);
   res = ~sum;
   return res;
}

