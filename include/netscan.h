#ifndef NETSCAN_H
#define NETSCAN_H

#define MAX_IPS 40

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DATALEN 56
#define PACKETS_COUNT 5
#define PACKET_SIZE 4096
#define WAIT_TIME 1

struct PING_GLOBAL{
   int received_packets;
   int sent_packets;
   pid_t pid;
   struct addrinfo* addr;
   int sockfd;
};


void  get_options();
int   get_ip_version(const char* host);
int   get_open_ports(const char* ip, int start, int end, int *ports);
char* get_ips_by_name(const char* name, char* IPs[], int *IPs_size);
char* get_hostname(struct sockaddr* in_addr);
char* get_addr_str(struct sockaddr* in_addr);

struct addrinfo* get_addr_by_name(const char* name);



/****************** PING ***************************/

void ping(char* host);
void recv_packet(int sockfd);

void time_difference(struct timeval* out, struct timeval *in);

int init_ping_socket_v4(int rcvfbuf_size);
int init_ping_socket_v6(int rcvfbuf_size);

void send_packet_v6(int sockfd, struct addrinfo *addr);
void send_packet_v4(int sockfd, struct addrinfo *addr);

int  process_packet_v4(char *buffer, int len, struct timeval* recv_time, struct sockaddr *from_addr);
int  process_packet_v6(char *buffer, int len, struct timeval* recv_time, struct sockaddr *from_addr);

void sig_alrm(int signo);
void sig_termination(int signo);

unsigned short get_checksum(unsigned short *data, size_t len);

#endif
