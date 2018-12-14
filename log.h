#ifndef LOG_H
#define LOG_H

#include <stdint.h>

int raid_log(char* ip_port, const char* msg);
void log_init(char* path, char* storage_name);
#endif