#include "utils.h"
#include "netscan.h"

#include <cjson/cJSON.h>
#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_is_valid_json(cJSON* json, char* name){
   cJSON *n;

   n = cJSON_GetObjectItemCaseSensitive(json, name);
   if (cJSON_IsString(n) && (n->valuestring != NULL)) {
      printf("%s: %s\n", name, n->valuestring);
   } else if (cJSON_IsNumber(n)) {
      if (n->valueint == 404 && strcmp(name, "status") == 0){
         log_info("wrong ip", "provide a valid ip address");
      }
   }
}

void parse_info(struct memory_t info){
   cJSON *json;

   json = cJSON_Parse(info.memory);
   if (json == NULL){
      const char *error_ptr = cJSON_GetErrorPtr();
      if (error_ptr != NULL)
         log_info(__func__, error_ptr);
      cJSON_Delete(json);
      exit(-1);
   }
   
   print_is_valid_json(json, "status");
   print_is_valid_json(json, "ip");
   print_is_valid_json(json, "hostname");
   print_is_valid_json(json, "anycast");
   print_is_valid_json(json, "city");
   print_is_valid_json(json, "region");
   print_is_valid_json(json, "country");
   print_is_valid_json(json, "loc");
   print_is_valid_json(json, "org");
   print_is_valid_json(json, "postal");
   print_is_valid_json(json, "timezome");

   cJSON_Delete(json);
   free(info.memory);
}


size_t memory_callback(void *content, size_t size, size_t nmemb, void* userp){
   size_t sz = size * nmemb;
   struct memory_t *mem = (struct memory_t*) userp;

   char *ptr = realloc(mem->memory, mem->size + sz + 1);
   if (ptr == NULL){
      log_info(__func__, "realloc failure");
      return 0;
   }
   mem->memory = ptr;
   memcpy(&(mem->memory[mem->size]), content, sz);
   mem->size += sz;
   mem->memory[mem->size] = 0;
   return sz;
}

void ipinfo(char* ip){
   struct memory_t info;
   info = get_info(ip);
   if (info.size > 0) parse_info(info);
   else log_info("ipinfo", "no information obtained");
}

struct memory_t get_info(char* ip){
   char* url;
   CURL *handler;
   CURLcode res;
   struct memory_t chunk;
  
   url = malloc(4098);

   sprintf(url, "ipinfo.io/%s/json", ip);
   chunk.memory = malloc(1);  
   chunk.size = 0;

   handler = curl_easy_init();
   if(handler) {
      curl_easy_setopt(handler, CURLOPT_URL, url);
      curl_easy_setopt(handler, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(handler, CURLOPT_WRITEFUNCTION, memory_callback);
      curl_easy_setopt(handler, CURLOPT_WRITEDATA, (void *)&chunk);
      curl_easy_setopt(handler, CURLOPT_USERAGENT, "libcurl-agent/1.0");

      res = curl_easy_perform(handler);

      if(res != CURLE_OK) 
         log_info(__func__, curl_easy_strerror(res));
      curl_easy_cleanup(handler);
      return chunk;
   } else log_info(__func__, "failed init curl");
   return chunk;
}
