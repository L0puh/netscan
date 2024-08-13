#include "netscan.h"

int main(int argc, char* argv[]) {
   if (argc == 1){
      get_options(); 
   } else {
      ping(argv[1]);
      /* TODO: parse flags */
   }
   return 0;
}
