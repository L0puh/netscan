#include "netscan.h"

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <glad/glad.h>
#include <GLFW/glfw3.h>

void sig_int(int signo){
   exit(0);
}


void init_window(){
   GLFWwindow *window;
   const float w = 400, h = 400;

   if (!glfwInit()) {
      return;
   }
   glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
   glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
   glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
   window = glfwCreateWindow(w, h, "window", 0, 0);

   glfwMakeContextCurrent(window);
   if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress)){
      return;
   }

   const GLfloat bg[] = {1, 0, 0, 0};
   while (!glfwWindowShouldClose(window)){
      glClearBufferfv(GL_COLOR, 0, bg);
      glfwSwapBuffers(window);
      glfwPollEvents();
   }
}


int visualizer(int proto){
   int sockfd, bytes;
   char *hostname, *str_ip;
   unsigned char buffer[TOTAL_SIZE];

   sockfd = socket(proto, SOCK_RAW, IPPROTO_TCP);
   setuid(getuid());

   signal(SIGINT, sig_int);
   init_window(); //FIXME
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
   }
}
