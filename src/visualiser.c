#include "netscan.h"

#include <GL/gl.h>
#include <GL/glu.h>
#include <GL/glut.h>

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
   glutMainLoop();

}

void draw_function(float *bytes, size_t size){
   float lim, y, x;

   lim = global.window_width;
   glBegin(GL_LINE_STRIP);
   glColor3f(1.0f, 0.0f, 0.0f);
   
   x = -lim;
   for (int i = 0; i < size; i++) {
      x += global.speed;
      if (x >= lim) x = -lim;
      y = bytes[i++]; 
      glVertex2f(x, y);
   }
   glEnd();
}

int visualiser(int proto){
   int sockfd, bytes;
   float *dots = malloc(MAX_DOTS);
   unsigned char *buffer = malloc(TOTAL_SIZE);

   sockfd = socket(proto, SOCK_RAW, IPPROTO_TCP);
   setuid(getuid());
   signal(SIGINT, sig_int);
   
   global.speed = 10.5f;
   global.scale = 100.0f;
   global.buffer = buffer;
   global.dots = dots;
   global.sockfd = sockfd;
   global.proto = proto;
   global.i = 0;
   
   init_glut();

   free(dots);
   free(buffer);
  
   return 0;
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

void display(void){
   char *msg = malloc(2048);
   int bytes, i = global.i;
  
   glClear(GL_COLOR_BUFFER_BIT);

   bytes = get_bytes(global.sockfd, global.proto, global.buffer);
   /* bytes = random() * 0.000001f; */
   if (i + 1 < MAX_DOTS)
      global.dots[global.i++] = sin(bytes) * global.scale;
   else i = 0;

   sprintf(msg, "[%d] %d bytes", i, bytes);
   glColor3f(0.0f, 1.0f, 0.0f);
   text_output(-(global.window_width*0.9), (global.window_height*0.5), msg); 
   draw_function(global.dots, i);

   glutSwapBuffers();
   free(msg);
}
