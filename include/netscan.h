#ifndef NETSCAN_H
#define NETSCAN_H

#define MAX_IPS 40

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int   get_ip_version(const char* host);
int   get_open_ports(const char* ip, int start, int end, int *ports);
char* get_ips_by_name(const char* name, char* IPs[], int *IPs_size);
char* get_addr_str(struct addrinfo *addr, int* len);
struct addrinfo* get_addr_by_name(const char* name);

void get_options();


#endif
