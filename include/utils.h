#ifndef UTILS_H
#define UTILS_H

#define ASSERT(res) { if (res < 0) { log_error(__FILE__, __LINE__, __func__); } } 

void log_error(const char* file, int line, const char* function);
void log_info(const char* where, const char* what);

#endif
