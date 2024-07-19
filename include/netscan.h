#ifndef NETSCAN_H
#define NETSCAN_H

#define MAX_IPS 40

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

char* get_addr_by_name(const char* name, char* IPs[], int *IPs_size);

#endif
