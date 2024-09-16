#include "netscan.h"
#include "utils.h"

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

static struct VISUALISER_GLOBAL global;

void sig_int(int signo){
   exit(0);
}

GLFWwindow* init_window(){
   GLFWwindow *window;
   const float width = 640, heigth = 400;

   global.window_width = width;
   global.window_height = heigth;

   if (!glfwInit()) {
      log_info(__func__, "error in glfw init");
      exit(-1);
   }
   glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
   glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
   glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

   window = glfwCreateWindow(width, heigth, "window", 0, 0);
   if (!window){
      log_info(__func__, "failed create window");
      exit(-1);
   }
   glfwMakeContextCurrent(window);
   
   frame_buffer_size(window, width, heigth);
   glMatrixMode(GL_PROJECTION);
   glLoadIdentity();
   glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
   glColor3f(1.0f, 0.0f, 0.0f);
   glfwSetFramebufferSizeCallback(window, frame_buffer_size);

   return window;
}


void draw_function(){
   glBegin(GL_LINE_STRIP);
   float lim = global.window_width;
   for (float x = -1 * lim; x <= lim; x += 1) {
     float y = 100.0 * sin(x * (M_PI / 180)); 
     glVertex2f(x, y); 
     glVertex2f(x + 1, 100.0 * sin((x + 1) * (M_PI / 180)));
   }
   glEnd();
}



int visualiser(int proto){
   int sockfd, bytes;
   GLFWwindow *window;
   float dots[MAX_DOTS];
   unsigned char buffer[TOTAL_SIZE];

   sockfd = socket(proto, SOCK_RAW, IPPROTO_TCP);
   setuid(getuid());
   signal(SIGINT, sig_int);

   window = init_window(); 
   global.speed = 0.02f;
  

   while (!glfwWindowShouldClose(window)){
      glClear(GL_COLOR_BUFFER_BIT);

      /* bytes = get_bytes(sockfd, proto, buffer); */
      /* if (i + 1 < MAX_DOTS) */
         /* dots[i++] = bytes * 0.01f; */
      draw_function();
      glfwSwapBuffers(window);
      glfwPollEvents();
   }
   glfwTerminate();
   return 0;
}

void frame_buffer_size(GLFWwindow *window, int width, int height){
   glViewport(0, 0, width, height);
   global.window_width = width;
   global.window_height = height;
   glOrtho(-1*global.window_width, global.window_width, 
            -1*global.window_height, global.window_height, -1, 1); 
}

int get_bytes(int sockfd, int proto, unsigned char* buffer){
   int bytes;
   if (proto == AF_INET) {
      struct packet_t pckt;
      pckt.data = buffer;
      pckt.data_len = TOTAL_SIZE; 
      bytes = capture_packet(sockfd, &pckt);
   } else {
      struct packet_v6_t pckt;
      pckt.data = buffer;
      pckt.data_len = TOTAL_SIZE; 
      bytes = capture_packet_v6(sockfd, &pckt);
   }
   return bytes;
}
