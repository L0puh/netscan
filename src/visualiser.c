#include "netscan.h"

#include <GL/gl.h>
#include <GL/glu.h>
#include <GL/glut.h>

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

static struct VISUALISER_GLOBAL global;

void sig_int(int signo){ exit(0); }

void text_output(int x, int y, char* string){
   int len;

   glRasterPos2f(x, y);
   len = strlen(string);
   for (int i = 0; i < len; i++){
      glutBitmapCharacter(GLUT_BITMAP_9_BY_15, string[i]);
   }
}
void reshape(int width, int height){
   glViewport(0, 0, width, height);
   glMatrixMode(GL_PROJECTION);
   glLoadIdentity();
   gluOrtho2D(-width, width, height, -height);
   global.window_width  = width;
   global.window_height = height;
   glMatrixMode(GL_MODELVIEW);
}

void tick() { glutPostRedisplay(); }

void skip_localhost(int choice){
   if (choice) {
      global.skip_localhost = !global.skip_localhost;
      printf("[+] localhost is %s\n", global.skip_localhost ? "OFF": "ON");
   }
}

void init_glut(){
   int argc = 0;
   const float width = 640, heigth = 480;

   global.window_width = width;
   global.window_height = heigth;

   glutInit(&argc, NULL);
   glutInitDisplayMode(GLUT_DOUBLE | GLUT_RGB);
   glutInitWindowSize(width, heigth);
   glutCreateWindow("window");
   glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
   
   glutDisplayFunc(display);
   glutReshapeFunc(reshape);
   glutIdleFunc(tick);

   int menu = glutCreateMenu(skip_localhost);
   glutAddMenuEntry("skip localhost", 1);
   glutAttachMenu(GLUT_RIGHT_BUTTON);
   
   glutMainLoop();

}

void draw_function(float *bytes, size_t size){
   float lim, y, x;

   lim = global.window_width;
   glBegin(GL_LINE_STRIP);
   glColor3f(1.0f, 0.0f, 0.0f);
   
   x = -lim;
   pthread_mutex_lock(&global.mtx);
   for (int i = 0; i < size; i++) {
      x += global.speed;
      if (x >= lim) x = -lim;
      y = bytes[i++]; 
      glVertex2f(x, y);
   }
   pthread_mutex_unlock(&global.mtx);
   glEnd();
}

int visualiser(int proto){
   pthread_t ptr;
   int sockfd, bytes;
   float *dots = malloc(MAX_DOTS);
   unsigned char *buffer = malloc(TOTAL_SIZE);

   sockfd = socket(proto, SOCK_RAW, IPPROTO_TCP);
   setuid(getuid());
   signal(SIGINT, sig_int);
   
   global.speed = 10.5f;
   global.last_hostname = malloc(1024);
   global.msg = malloc(1024);
   global.scale = 100.0f;
   global.buffer = buffer;
   global.dots = dots;
   global.sockfd = sockfd;
   global.proto = proto;
   global.i = 0;
   
   pthread_mutex_init(&global.mtx, 0);
   pthread_create(&ptr, NULL, process_bytes, (void*)&global.i);
   pthread_detach(ptr);
   init_glut();

   free(dots);
   free(buffer);
   free(global.last_hostname);
  
   return 0;
}


int get_bytes(int sockfd, int proto, unsigned char* buffer){
   int bytes;
   char *ip_str, *hostname;
   struct sockaddr* addr;
   if (proto == AF_INET) {
      struct packet_t pckt;
      pckt.data = buffer;
      pckt.data_len = TOTAL_SIZE; 
      bytes = capture_packet(sockfd, &pckt);
      addr = (struct sockaddr*)&pckt.addr;
   } else {
      struct packet_v6_t pckt;
      pckt.data = buffer;
      pckt.data_len = TOTAL_SIZE; 
      bytes = capture_packet_v6(sockfd, &pckt);
      addr = (struct sockaddr*)&pckt.addr;
   }
   hostname = get_hostname(addr);
   if (hostname != NULL) 
      global.last_hostname = hostname;
   else {
      ip_str = get_addr_str(addr);
      global.last_hostname = ip_str;
   }
   return bytes;
}

void* process_bytes(void* p){
   int bytes, i=global.i;
   char *msg = malloc(2048);
   while(1) {
      bytes = get_bytes(global.sockfd, global.proto, global.buffer);
      if (global.skip_localhost && strcmp(global.last_hostname, "localhost") == 0)
         continue;
      sprintf(msg, "[%d] %d bytes: %s", i, bytes, global.last_hostname);
     
      pthread_mutex_lock(&global.mtx);
      if (i + 1 < MAX_DOTS){
         global.dots[i++] = sin(bytes) * global.scale;
      } else i = 0;

      global.i = i;
      global.msg = msg;

      pthread_mutex_unlock(&global.mtx);
   }
      
   free(msg);
   pthread_exit(NULL);
}

void display(void){
   int bytes=0, i = global.i;
  
   glClear(GL_COLOR_BUFFER_BIT);

   glColor3f(0.0f, 1.0f, 0.0f);
   text_output(-(global.window_width*0.9), (global.window_height*0.5), global.msg); 
   draw_function(global.dots, i);
   
   glutSwapBuffers();
}
