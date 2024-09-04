#include "netscan.h"
#include "utils.h"
#include <netinet/ip.h>
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
   }

   printf("\t");
   for (j = i-i%16; j <= i; j++){
      if (data[j] >= 32 && data[j] <= 128)
         printf("%c", (unsigned char)data[j]);
      else printf(".");
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
   printf("DATA:\n");       print_dump(buffer+len+bytes, (buff_len-bytes-(hdr->ihl*4)));
   printf("HEADER LENGTH: %u dwords (%u bytes)\n", tcp->doff, bytes*2);

}

void process_packet(unsigned char* buffer, int buffer_len){
   struct iphdr *hdr;
   hdr = (struct iphdr*) buffer;
   switch(hdr->protocol){
      case IPPROTO_ICMP:
         global.count_icmp++;
         break;
      case IPPROTO_IGMP:
         global.count_igmp++;
         break;
      case IPPROTO_TCP:
         global.count_tcp++;
         print_tcp(hdr, buffer, buffer_len);
         break;
      case IPPROTO_UDP:
         global.count_udp++;
         /* print_udp(); */
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

void packet_sniffer(int proto){
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
      printf("\nReceived a packet from %s (%s), total size: %d\n", hostname ? hostname: str_ip, str_ip, bytes);
      global.rcv_count++;
      global.total_size += bytes;
      if (global.max_size < bytes) global.max_size = bytes;
      process_packet(buffer, bytes);
   }
   
   close(sockfd);
   sig_int(SIGINT);

   return;
}
