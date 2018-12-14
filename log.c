#include "log.h"
#include <stdlib.h>
#include "string.h"
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

static char path[1024];
static char storage_name[256];
void log_init(char* path_, char* storage_name_){
	path[strlen(path_)] = '\0';
	memcpy(path, path_, strlen(path_));

	storage_name[strlen(storage_name_)] = '\0';
	memcpy(storage_name, storage_name_, strlen(storage_name_));
}

int raid_log(char* ip_port, const char* msg)
{
	// int fd = open(path, O_RDWR | O_APPEND);
	FILE* f = fopen(path, "a+");
	if(f == NULL){
		printf("%s\n", "file not found");
		return -1;
	}
	//char buff[4096];
	time_t current_time = time(NULL);
	char* c_time_string = ctime(&current_time);
	fprintf(f, "[%s] %s %s : %s\n", c_time_string, storage_name, ip_port, msg);
	// fflush(f);
	fclose(f);
	return 0;
}

