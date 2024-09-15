#include "netscan.h"
#include "utils.h"

#include <GL/gl.h>
#include <cglm/vec3.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static struct VISUALISER_GLOBAL global;

const char* vertex_shader_src =  "#version 330 core\n"
      "layout (location = 0) in vec3 pos;\n"
      "uniform mat4 model;\n"
      "void main()\n"
      "{\n"
      "  gl_Position = model * vec4(pos, 1.0);\n"
      "}\0";

const char* fragment_shader_src = "#version 330 core\n"
      "out vec4 FragColor;\n"
      "void main()\n"
      "{\n"
      "  FragColor = vec4(1.0f, 1.0f, 1.0f, 1.0f);\n"
      "}\0";

void sig_int(int signo){
   exit(0);
}


GLFWwindow* init_window(){
   GLFWwindow *window;
   const float width = 400, heigth = 400;

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

   glfwMakeContextCurrent(window);
   if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress)){
      log_info(__func__, "error in glad load");
      exit(-1);
   }
   glfwSetFramebufferSizeCallback(window, frame_buffer_size);
   return window;
}


void draw(struct object_t obj){
   int loc;
   loc = glGetUniformLocation(obj.shader, "model");
   if (loc == -1) {
      log_info(__func__, "location is invalid");
      exit(-1);
   }
   glUseProgram(obj.shader);
   glUniformMatrix4fv(loc, 1, GL_FALSE, &obj.model[0][0]);
   glBindVertexArray(obj.VAO);
   glDrawArrays(GL_POINTS, 0, 1);
}


int create_shader(){
   int res;
   char info[512];
   int shader, vtx, frg;

   vtx = glCreateShader(GL_VERTEX_SHADER);
   glShaderSource(vtx, 1, &vertex_shader_src, NULL);
   glCompileShader(vtx);

   frg = glCreateShader(GL_FRAGMENT_SHADER);
   glShaderSource(frg, 1, &fragment_shader_src, NULL);
   glCompileShader(frg);

   shader = glCreateProgram();
   glAttachShader(shader, vtx);
   glAttachShader(shader, frg);
   glLinkProgram(shader);
   glGetProgramiv(shader, GL_LINK_STATUS, &res);
   
   if (!res){
      glGetProgramInfoLog(shader, 512, NULL, info);
      log_info(__func__, info);
      exit(-1);
   }  else log_info(__func__, "shader is linked"); 

   glDeleteShader(vtx);
   glDeleteShader(frg);
   
   return shader;
}


void create_VAO(struct object_t *obj, float *vertices, size_t size){
   unsigned int VAO, VBO;


   glGenVertexArrays(1, &VAO);
   glGenBuffers(1, &VBO);
   glBindVertexArray(VAO);
   
   glBindBuffer(GL_ARRAY_BUFFER, VBO);
   glBufferData(GL_ARRAY_BUFFER, size, vertices, GL_STATIC_DRAW);
   glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 3 * sizeof(float), (void*)0);
   glEnableVertexAttribArray(0);

   glBindBuffer(GL_ARRAY_BUFFER, 0);
   glBindVertexArray(0);

   obj->VAO = VAO;
   obj->VBO = VBO;
}


int visualiser(int proto){
   mat4 model;
   struct object_t obj;
   int sockfd, bytes;
   GLFWwindow *window;
   unsigned char buffer[TOTAL_SIZE];

   sockfd = socket(proto, SOCK_RAW, IPPROTO_TCP);
   setuid(getuid());
   signal(SIGINT, sig_int);
   window = init_window(); 
   obj.shader = create_shader();
  
   vec3 pos;
   vec3 init_pos = {-0.5f, 0.0f, 0.0f}; 
   float init_vertices[] = {
      init_pos[0], init_pos[1], init_pos[2],
   };
  
   glm_vec3_copy(init_pos, pos);
   const GLfloat bg[] = {0, 0, 0, 0};
   
   create_VAO(&obj, init_vertices, sizeof init_vertices);

   const int MAX_DOTS = 10000;
   vec3 dots[MAX_DOTS];
   float gap = 0.002;
   glPointSize(5.0f);
   int i = 0;
   glm_vec3_copy(pos, dots[i++]);



   while (!glfwWindowShouldClose(window)){
      glClearBufferfv(GL_COLOR, 0, bg);

      bytes = get_bytes(sockfd, proto, buffer);
      if (bytes <= 8) continue;

      pos[0] += gap;
      pos[1] = (bytes * 0.001); 
      if (i+1 < MAX_DOTS) {
         glm_vec3_copy(pos, dots[i++]);
      } else {
         i = 0; glm_vec3_copy(init_pos, pos);
      }

      for (int j = 0; j < i; j++)
      {
         glm_mat4_identity(model);
         glm_translate(model, dots[j]);
         glm_mat4_copy(model, obj.model);
         draw(obj); 
      }
      glfwSwapBuffers(window);
      glfwPollEvents();
   }

   return 0;
}

void frame_buffer_size(GLFWwindow *window, int width, int height){
   glViewport(0, 0, width, height);
   global.window_width = width;
   global.window_height = height;
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
