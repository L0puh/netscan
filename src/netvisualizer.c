#include "netscan.h"

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>


void sig_int(int signo){
   exit(0);
}

int visualizer(int proto){
   int sockfd, bytes;
   char *hostname, *str_ip;
   unsigned char buffer[TOTAL_SIZE];

   sockfd = socket(proto, SOCK_RAW, IPPROTO_TCP);
   setuid(getuid());

   signal(SIGINT, sig_int);
   while(1){
      if (proto == AF_INET) {
         struct packet_t pckt;
         pckt.data = buffer;
         pckt.data_len = sizeof(buffer);
         bytes = capture_packet(sockfd, &pckt);
         hostname = get_hostname((struct sockaddr*)&pckt.addr);
         str_ip = get_addr_str((struct sockaddr*)&pckt.addr);
      } else {
         struct packet_v6_t pckt;
         pckt.data = buffer;
         pckt.data_len = sizeof(buffer);
         bytes = capture_packet_v6(sockfd, &pckt);
         hostname = get_hostname((struct sockaddr*)&pckt.addr);
         str_ip = get_addr_str((struct sockaddr*)&pckt.addr);
      }
      //TODO
   }
}
