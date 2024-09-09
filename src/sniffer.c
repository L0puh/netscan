#include "netscan.h"
#include "utils.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <unistd.h>

static struct SNIFFER_GLOBAL global;



void print_dump(unsigned char* data, int len){
   int i, j;

   for (i = 0; i < len; i++){
      if (i != 0 && i % 16 == 0){
         printf("\t");
         for (j = i-16; j < i; j++){
            if (data[j] >= 32 && data[j] <= 128)
               printf("%c", (unsigned char)data[j]);
            else printf(".");
         }
         printf("\n");
      }
      if (i % 16 == 0) printf("\t");
      printf(" %02x", (unsigned int)data[i]);

      if (i == len-1){
         printf("\t");
         for (j = i-i%16; j <= i; j++){
            if (data[j] >= 32 && data[j] <= 128)
               printf("%c", (unsigned char)data[j]);
            else printf(".");
         }
      }
   }
   puts("\n\n");
}

void print_tcp(struct iphdr* hdr, unsigned char* buffer, int buff_len){
   int len, bytes;
   len = hdr->ihl * 4;

   struct tcphdr *tcp = (struct tcphdr*)(buffer + len);

   bytes = tcp->doff * 4;
   printf("TCP PACKET:\n");
   printf("\tsource port: %u | destination port: %u\n", ntohs(tcp->source), ntohs(tcp->dest));
   printf("\tseq: %u ack: %u\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
   printf("\tchecksum: %u window: %u urgent ptr: %u\n", ntohl(tcp->check), 
                                 ntohl(tcp->window), ntohl(tcp->urg_ptr));
   printf("FLAGS:\n\turgent: %d\n\tack: %d\n\tpush: %d\n\treset: %d\n\tsync: %d\n\tfinish: %d\n",
         tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin);
 
   printf("IP HEADER:\n");  print_dump(buffer, len);
   printf("TCP HEADER:\n"); print_dump(buffer+len, bytes);
   printf("DATA:\n");       print_dump(buffer+len+bytes, (buff_len-bytes-len));
   printf("HEADER LENGTH: %u dwords (%u bytes)\n", tcp->doff, bytes*2);

}

void print_udp(struct iphdr* hdr, unsigned char* buffer, int buff_len){
   int len, size;

   len = hdr->ihl * 4;
   struct udphdr* udp = (struct udphdr*)(buffer+len);
   size = sizeof(*udp);

   printf("UDP PACKET:\n");
   printf("\tsource port: %u | destination port: %u\n", ntohs(udp->source), ntohs(udp->dest));
   printf("\tlen: %u checksum: %u\n", ntohs(udp->len), ntohs(udp->check));
   printf("IP HEADER:\n");  print_dump(buffer, len);
   printf("UDP HEADER:\n"); print_dump(buffer+len, size);
   printf("DATA:\n");       print_dump(buffer+len+size, (buff_len-size-len));

}

void print_icmp(struct iphdr* hdr, unsigned char* buffer, int buff_len){
   int len, size;
   len = hdr->ihl * 4;
   
   struct icmp* icmp = (struct icmp*)(buffer + len);
   size = sizeof(*icmp);

   printf("ICMP PACKET:\n");
   printf("\tchecksum: %u, code: %u, type: %u\n", 
                        ntohs(icmp->icmp_cksum), 
                        ntohs(icmp->icmp_code), 
                        ntohs(icmp->icmp_type));

   printf("IP HEADER:\n");  print_dump(buffer, len);
   printf("UDP HEADER:\n"); print_dump(buffer+len, size);
   printf("DATA:\n");       print_dump(buffer+len+size, (buff_len-size-len));

}

void process_packet(unsigned char* buffer, int buffer_len, int flags){
   struct iphdr *hdr;
   hdr = (struct iphdr*) buffer;
   switch(hdr->protocol){
      case IPPROTO_ICMP:
         global.count_icmp++;
         if (flags & UDP_ONLY || flags & TCP_ONLY || !(flags & VERBOSE)) break;
         print_icmp(hdr, buffer, buffer_len);
         break;
      case IPPROTO_IGMP:
         global.count_igmp++;
         break;
      case IPPROTO_TCP:
         global.count_tcp++;
         if (flags & UDP_ONLY || !(flags & VERBOSE)) break;
         print_tcp(hdr, buffer, buffer_len);
         break;
      case IPPROTO_UDP:
         global.count_udp++;
         if (flags & TCP_ONLY || !(flags & VERBOSE)) break;
         print_udp(hdr, buffer, buffer_len);
         break;
      default:
         global.count_other++;
   }
}


void sig_int(int signo){
   struct timeval time;
   
   gettimeofday(&time, NULL);
   time_difference(&time, &global.time);
   printf("\n\nFINISHED:\n\tRECEIVED PACKETS: %d\n\tMAX SIZE: %d\n\tTOTAL SIZE: %d\n\tTIME: %lds\n\n",  
         global.rcv_count, global.max_size, global.total_size, time.tv_sec);
   printf("\tICMP: %d IGMP: %d TCP: %d UDP: %d OTHER: %d\n", global.count_icmp, global.count_igmp, 
                                             global.count_tcp, global.count_udp, global.count_other);
   exit(0);
}

void packet_sniffer(int proto, int flags){
   int sockfd, bytes;
   char *hostname, *str_ip;
   socklen_t addr_size;
   struct sockaddr_in addr;
   unsigned char buffer[TOTAL_SIZE];

   if (proto == AF_INET6){
      log_info(__func__, "IPv6 isn't supported yet");
      return;
   }      
  
   global.rcv_count = global.max_size = global.total_size = 0;
   gettimeofday(&global.time, NULL);

   sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
   setuid(getuid());

   signal(SIGINT, sig_int);

   while(1){
      addr_size = sizeof(addr); 
      bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addr_size);
      ASSERT(bytes);
      hostname = get_hostname((struct sockaddr*)&addr);
      str_ip = get_addr_str((struct sockaddr*)&addr);

      if (flags & SKIP_LOCALHOST){
         if (hostname != NULL)
            if (strcmp(hostname, "localhost") == 0) continue;
         if (strcmp(str_ip, "127.0.0.1") == 0) continue; //FIXME
      }

      printf("## Received a packet from %s (%s), total size: %d\n", hostname ? hostname: str_ip, str_ip, bytes);
      global.rcv_count++;
      global.total_size += bytes;
      if (global.max_size < bytes) global.max_size = bytes;
      process_packet(buffer, bytes, flags);
   }
   
   close(sockfd);
   sig_int(SIGINT);

   return;
}
