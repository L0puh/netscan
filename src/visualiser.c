#include "netscan.h"
#include "utils.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cglm/cglm.h>
#include <glad/glad.h>
#include <GLFW/glfw3.h>


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
   return window;
}


struct line_t {
   int shader;
   unsigned int VBO, VAO;
};

void draw_line(struct line_t line, mat4 model){
   int loc;
   loc = glGetUniformLocation(line.shader, "model");
   if (loc == -1) {
      log_info(__func__, "location is invalid");
      exit(-1);
   }
   glUseProgram(line.shader);
   glUniformMatrix4fv(loc, 1, GL_FALSE, &model[0][0]);
   glBindVertexArray(line.VAO);
   glDrawArrays(GL_LINES, 0, 2);
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


void create_VAO(struct line_t *line, float *vertices, size_t size){
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

   line->VAO = VAO;
   line->VBO = VBO;
}

int visualizer(int proto){
   struct line_t line;
   int sockfd, bytes;
   GLFWwindow *window;
   unsigned char buffer[TOTAL_SIZE];

   sockfd = socket(proto, SOCK_RAW, IPPROTO_TCP);
   setuid(getuid());

   signal(SIGINT, sig_int);
   window = init_window(); 
   
   const GLfloat bg[] = {0, 0, 0, 0};

   line.shader = create_shader();
   float gap = 4.0f;

   vec3 start_pos = {-1.0f, -1.0f, 0.0f}; 
   vec3 end_pos = {1.0f, 1.0f, 0.0f}; 
   int i = 0;

   while (!glfwWindowShouldClose(window)){
      glClearBufferfv(GL_COLOR, 0, bg);

      float init_vertices[6] = {
         start_pos[0], start_pos[1], start_pos[2],
         end_pos[0], end_pos[1], end_pos[2]
      };
      mat4 model = {1.0f};
      vec3 pos = {0.0f, 0.0f, 0.0f};
      glm_translate(model, pos);
      create_VAO(&line, init_vertices, sizeof init_vertices);
      draw_line(line, model); 

      glfwSwapBuffers(window);
      glfwPollEvents();
   }

   return 0;
}

int get_bytes(int sockfd, int proto, unsigned char* buffer){
   int bytes;
   if (proto == AF_INET) {
      struct packet_t pckt;
      pckt.data = buffer;
      pckt.data_len = sizeof(buffer);
      bytes = capture_packet(sockfd, &pckt);
   } else {
      struct packet_v6_t pckt;
      pckt.data = buffer;
      pckt.data_len = sizeof(buffer);
      bytes = capture_packet_v6(sockfd, &pckt);
   }
   return bytes;
}
