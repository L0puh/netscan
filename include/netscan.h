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
#define PACKET_SIZE 4096 /* ping packet */
#define TOTAL_SIZE 65536 /* buffer for packet in sniffer */ 
#define BUFFER_SIZE 1500 /* traceroute packet */
#define WAIT_TIME 1
#define PORT 30000
#define MAX_PROBES 3
#define MAX_IPS 40
#define DEFAULT_THREADS 5

struct PING_GLOBAL{
   int received_packets;
   int sent_packets;
   pid_t pid;
   struct addrinfo* addr;
   int sockfd;
};

struct SNIFFER_GLOBAL {
   int rcv_count;
   int total_size;
   int max_size;
   int count_tcp;
   int count_icmp;
   int count_igmp;
   int count_udp;
   int count_other;
   struct timeval time;
};

struct TRACEROUTE_GLOBAL {
   int port;
   pid_t pid;
   int is_alrm;

   int packets_sent;
   int sockfd_recv;
   int sockfd_send;
   socklen_t addr_len;
   struct sockaddr* send_addr;
   struct sockaddr* recv_addr;
   struct sockaddr* bind_addr;
   
   int done;
   double max_time;
};

typedef struct {
   unsigned short seq;
   unsigned short ttl;
   struct timeval time;
} upd_packet_t;

typedef struct {
   int id;
   int end;
   int start;
   
   int *len;
   int *ports;
   pthread_mutex_t *mtx;
   struct sockaddr_in serv;
} ports_param_t;

/****************** NETSCAN ***************************/

int   get_ip_version(const char* host);
int   get_open_ports(const char* ip, int start, int end, int *ports, int threads);
char* get_ips_by_name(const char* name, char* IPs[], int *IPs_size);
char* get_hostname(struct sockaddr* in_addr);
char* get_addr_str(struct sockaddr* in_addr);

struct addrinfo* get_addr_by_name(const char* name);

void set_port(struct sockaddr* addr, int port);
int cmp_addr(struct sockaddr* x, struct sockaddr* y);

static void sig_alrm(int signo);
static void sig_int(int signo);

void* handle_thread(void* param);
void search_ports(int *len, int start, int end, struct sockaddr_in server_addr, int *ports, pthread_mutex_t *mtx);

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

unsigned short get_checksum(unsigned short *data, size_t len);

/****************** TRACEROUTE ***************************/

void traceroute(char* host, int max_ttl);

void init_traceroute_socket_v4();
void init_traceroute_socket_v6();

char* get_icmp_code(int code);
void send_loop(int max_ttl);

int recv_udp_v6(int seq, struct timeval *time);
int recv_udp(int seq, struct timeval *time);



/****************** PACKET SNIFFER ***************************/

void packet_sniffer(int proto);
void process_packet(unsigned char* buffer, int buffer_len);

void print_dump(unsigned char* data, int len);
void print_tcp(struct iphdr* hdr, unsigned char* buffer, int buff_len);

#endif
