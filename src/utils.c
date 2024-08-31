#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void log_error(const char* file, int line, const char* function){
   if (errno != 0){
      if (errno == EINTR) return;
      printf("[-] ERROR (%s: %s [%d]): %s\n", file, function, line, strerror(errno)); 
      exit(-1);
   } else {
      printf("[-] WARNING: (%s: %s [%d]): %s\n", file, function, line, strerror(errno)); 
   }
}

void log_info(const char* where, const char* what){
   printf("[+] INFO (%s): %s\n", where, what);
}
void log_infoi(int line, const char* what){
   printf("[+] INFO %d: %s\n", line, what);
}
