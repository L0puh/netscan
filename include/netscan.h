#ifndef NETSCAN_H
#define NETSCAN_H


#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#define DATALEN 56
#define PACKETS_COUNT 5
#define PACKET_SIZE 4096
#define WAIT_TIME 1
#define PORT 30000
#define MAX_PROBES 3
#define MAX_IPS 40

struct PING_GLOBAL{
   int received_packets;
   int sent_packets;
   pid_t pid;
   struct addrinfo* addr;
   int sockfd;
};


struct TRACEROUTE_GLOBAL {
   int port;
   int is_alrm;
   pid_t pid;

   int packets_sent;
   int sockfd_recv;
   int sockfd_send;
   struct sockaddr* addr;
   struct sockaddr* last_addr;
   struct sockaddr* bind_addr;
};

typedef struct {
   unsigned short seq;
   unsigned short ttl;
   struct timeval time;
} upd_packet_t;


/****************** NETSCAN ***************************/

int   get_ip_version(const char* host);
int   get_open_ports(const char* ip, int start, int end, int *ports);
char* get_ips_by_name(const char* name, char* IPs[], int *IPs_size);
char* get_hostname(struct sockaddr* in_addr);
char* get_addr_str(struct sockaddr* in_addr);

struct addrinfo* get_addr_by_name(const char* name);

void set_port(struct sockaddr* addr, int port);

/****************** PING ***************************/

void ping(char* host);
void recv_packet(int sockfd);

void time_difference(struct timeval* out, struct timeval *in);

int init_ping_socket_v4(int rcvfbuf_size);
int init_ping_socket_v6(int rcvfbuf_size);

void send_packet_v6(int sockfd, struct addrinfo *addr);
void send_packet_v4(int sockfd, struct addrinfo *addr);

int  process_packet_v4(char *buffer, int len, struct timeval* recv_time, struct sockaddr *from_addr);
int  process_packet_v6(char *buffer, int len, struct timeval*, struct sockaddr*, struct msghdr*);

void ping_alrm(int signo);
void ping_termination(int signo);

unsigned short get_checksum(unsigned short *data, size_t len);



/****************** TRACEROUTE ***************************/

void traceroute(char* host, int max_ttl);

void init_traceroute_socket_v4();
void init_traceroute_socket_v6();

void trace_alrm(int signo);

#endif
