#define FUSE_USE_VERSION 26

#include "stdio.h"
#include <stdlib.h>
#include "string.h"
#include <fuse.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <unistd.h>
#include <arpa/inet.h>
#include "request.h"
#include "log.h"
#include "dirent.h"
#include <pthread.h>

#define LINE_SIZE 256
#define BUFSIZE 1024
#define HASH_SIZE 16
// char* errorlog = "/home/vagrant/raid/bruh/error.log";

typedef void* (*para_func)(void*);

static pthread_mutex_t sys_lock;
static int timelapse_1;
static int timelapse_2;

static int socket_connect(char* server, int* sfd_p,struct sockaddr_in* addr);


// static int sfd;
static int sfd_2;
static int sfd_1;

static struct sockaddr_in addr_1;
static struct sockaddr_in addr_2;

static char errorlog[1024];
static int cache_size;
static char cache_replacment[256];
static int timeout;
static char diskname[256];
static char mountpoint[1024];
static int raid;
static char server1[256];
static char server2[256];
static char hotswap[256];

struct para_info{
	int sfd;
	int num;
	const char* path;
	void* buf;
	int size;
	off_t offset;
	struct stat* stbuf;
	struct fuse_file_info* fi;
	off_t newsize;
	mode_t mode;
	dev_t dev;
	const char* newpath;
	int* ret_val;
	struct utimbuf* ubuf;
	struct flock *lock;
	int cmd;
	unsigned char* hash;

};

static int hash_cmp(unsigned char *hash1, unsigned char *hash2)
{
	int i = 0;
	for(i = 0; i < 16; i++)
	{
		if(hash1[i] != hash2[i]){
			return 0;
		}
	}
	return 1;
}

static int request_paralel(para_func func, struct para_info** info){

	pthread_t thread1, thread2;
	pthread_create(&thread1, NULL, func, (void*)info[0]);
	pthread_create(&thread2, NULL, func, (void*)info[1]);

	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

	if(info[0]->ret_val[0] == -EPIPE || info[0]->ret_val[1] == -EPIPE){
	}
	if(info[0]->ret_val[0] < 0 || info[0]->ret_val[1] < 0){
	}

	int ret = info[0]->ret_val[0] > info[1]->ret_val[1] ? info[0]->ret_val[0] : info[1]->ret_val[1];
	free(info[0]->ret_val);
	free(info[0]);
	free(info[1]);
	return ret;
}

static int safe_read(int sfd, void* buff, int size){
	int num_read = read(sfd, buff, size);        
	if(num_read == -1){
		return 0;
	}
	return 1;
}

static int safe_write(int sfd, void* buff, int size){
	int num_write = write(sfd, buff, size);
	if(num_write == -1){
		return 0;
	}
	return 1;
}

static int send_initial_request(int sfd, int request_num, int size)
{
	int request[2];
	request[0] = request_num;
	request[1] = size;

	if(!safe_write(sfd, request, 2 * sizeof(int))){
		return 0;
	}

	int response;
	if(!safe_read(sfd, &response, sizeof(int))){
		return 0;
	}


	if(response == -1)
		return 0;
	
	return 1;
}

static int seq_getattr(int sfd, const char *path, struct stat *stbuf){
	memset(stbuf, 0, sizeof(struct stat));

	// if(strcmp(path, "/.xdg-volume-info") == 0 ||
	// 	strncmp(path, "/.", strlen("/.")) == 0 ||
	// 	strcmp(path, "/autorun.inf") == 0 ||
	// 	strcmp(path, "") == 0)
	// 	return -ENOENT;

	int len = strlen(path);
	if(!send_initial_request(sfd, GETATTR, len)){
		return -EPIPE;
	}

	write(sfd, path, len);

	char statbuf[sizeof(int) + sizeof(struct stat)];
	read(sfd, statbuf,sizeof(int) + sizeof(struct stat));
	int response = *(int *)statbuf;
	if(response < 0){
		return response;
	}

	memcpy(stbuf, statbuf + sizeof(int), sizeof(struct stat));

	return 0;
}

int net_raid_getattr(const char *path, struct stat *stbuf)
{
	pthread_mutex_lock(&sys_lock);

	int ret_val = seq_getattr(sfd_1, path, stbuf);
	if(ret_val  == -EPIPE || ret_val == -ENOENT){
		int ret_val2 = seq_getattr(sfd_2, path, stbuf);
		if(!(ret_val == -ENOENT && ret_val2 == -EPIPE)){
			ret_val = ret_val2;
		}	
	}
	pthread_mutex_unlock(&sys_lock);
	return ret_val;

}


static int seq_readdir(int sfd, const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi){
	int len = strlen(path);
	if(!send_initial_request(sfd, READDIR, len)){
		return -EPIPE;
	}

	write(sfd, path, len);

	int name_len;
	struct stat st;
	char buff[sizeof(int) + sizeof(struct stat)];
	read(sfd, buff, sizeof(int) + sizeof(struct stat));
	memcpy(&st, buff + sizeof(int), sizeof(struct stat));
	name_len = *(int*)buff;
	if(name_len < 0)
		return name_len;
	while(name_len != 0){
		write(sfd, &name_len, sizeof(int));
		char name[name_len +1];
		name[name_len] = '\0';
		read(sfd, name, name_len);
		filler(buf, name, &st, 0);

		write(sfd, &name_len, sizeof(int));

		read(sfd, buff, sizeof(int) + sizeof(struct stat));
		memcpy(&st, buff + sizeof(int), sizeof(stat));
		name_len = *(int*)buff;
	}


	return 0;


}

int net_raid_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{	

	pthread_mutex_lock(&sys_lock);

	int ret_val = seq_readdir(sfd_1, path, buf, filler, offset, fi);
	if(ret_val  == -EPIPE){
		//memset(buf, 0, size);
		ret_val = seq_readdir(sfd_2, path, buf, filler, offset, fi);
	}
	pthread_mutex_unlock(&sys_lock);
	return ret_val;

}

static void* para_open(void* attr){
	struct para_info* info = (struct para_info*)attr;
	int sfd = info->sfd;
	int num = info->num;
	struct fuse_file_info * fi = info->fi;
	const char *path = info->path;

	int len = strlen(path);
	if(!send_initial_request(sfd, OPEN, len)){
		info->ret_val[num] = -EPIPE;
		return NULL;
	}

	char path_flags[len + sizeof(int)];
	memcpy(path_flags, path, len);
	memcpy(path_flags + len, &fi->flags, sizeof(int));
	write(sfd, path_flags, len + sizeof(int));

	char hash_buf[sizeof(int) + HASH_SIZE];
	read(sfd, hash_buf, sizeof(int) + HASH_SIZE);
	int server_res = *(int*)hash_buf;
	if(server_res == 0 || server_res == 2)
		memcpy(info->hash, hash_buf + sizeof(int), HASH_SIZE);
	info->ret_val[num] = server_res;

	return NULL;
	
}

static void transfer_data(int sender, int reciever, int remain_data){
	char buffer[BUFSIZE];
	int len;
	int reciever_file_ready;

	int to_read = remain_data < BUFSIZE ? remain_data : BUFSIZE;
	while ((remain_data > 0) && ((len = read(sender, buffer, to_read)) > 0))
    {
    	write(reciever, buffer, to_read);
    	read(reciever, &reciever_file_ready, sizeof(int));
    	write(sender, &reciever_file_ready, sizeof(int));
    	if(reciever_file_ready == -1)
    		break;
    	remain_data -= len;
    	to_read = remain_data < BUFSIZE ? remain_data : BUFSIZE;
    }
}

static int transfer_file(int sender, int reciever){
	int file_size;
	int reciever_file_ready;
	char status[sizeof(int) + sizeof(mode_t) + sizeof(dev_t)];
	read(sender, status, sizeof(int) + sizeof(mode_t) + sizeof(dev_t));
	file_size = *(int*)status;
	write(reciever, status, sizeof(int) + sizeof(mode_t) + sizeof(dev_t));
	read(reciever,&reciever_file_ready, sizeof(int));

	write(sender,&reciever_file_ready, sizeof(int));
	if(file_size < 0 || reciever_file_ready < 0){
		return -1;
	}

	transfer_data(sender, reciever, file_size);
	raid_log(server1, "FILE TRANSFER COMPLETE");
	raid_log(server2, "FILE TRANSFER COMPLETE");

    return 0;

}

static int process_alive_response(int res1, int res2){
	int res = 0;
	if(res1 != -EPIPE){
		write(sfd_1, &res, sizeof(int));
		return 0;
	}
	if(res2 != -EPIPE){
		write(sfd_2, &res, sizeof(int));
		return 0;
	}
	return -EPIPE;
}

static int process_responses(int res1, int res2, unsigned char* hash1, unsigned char* hash2)
{
	int client_1 = 0;;
	int client_2 = 0;
	int reciever = -1;
	int sender = -1;

	if(res1 == 0 && res2 == 0)
	{	
		if(hash_cmp(hash1, hash2))
		{
			client_1 = 0;
			client_2 = 0;
		}else{

			raid_log(server1, "FILE INCONSISTENCY DETECTED: WILL SEND FILE ");
			raid_log(server2, "FILE INCONSISTENCY DETECTED: WILL RECIEVE FILE");
			client_1 = 1;
			client_2 = 2;
			sender = sfd_1;
			reciever =  sfd_2;
		}
		
	}else if(res1 == 0 && res2 == 2){

		if(hash_cmp(hash1, hash2))
		{
			client_1 = 0;
			client_2 = 0;
		}else{
			raid_log(server1, "FILE INCONSISTENCY DETECTED: WILL RECIEVE FILE");
			raid_log(server2, "FILE INCONSISTENCY DETECTED: WILL SEND FILE");
			client_1 = 2;
			client_2 = 1;
			sender = sfd_2;
			reciever =  sfd_1;
		}

	}
	else if((res1 == 0 || res1 == 2) && (res2 == 1 || res2 == 3))
	{	
		raid_log(server1, "FILE INCONSISTENCY DETECTED: WILL SEND FILE");
		raid_log(server2, "FILE INCONSISTENCY DETECTED: WILL RECIEVE FILE");
		client_1 = 1;
		client_2 = 2;
		sender = sfd_1;
		reciever =  sfd_2;
	}else if((res1 == 1 || res1 == 3) && (res2 == 0 || res2 == 2))
	{
		raid_log(server1, "FILE INCONSISTENCY DETECTED: WILL RECIEVE FILE");
		raid_log(server2, "FILE INCONSISTENCY DETECTED: WILL SEND FILE");
		client_1 = 2;
		client_2 = 1;
		sender = sfd_2;
		reciever =  sfd_1;
	}
	write(sfd_1, &client_1, sizeof(int));
	write(sfd_2, &client_2, sizeof(int));
	if(reciever != -1 && sender != -1)
		return transfer_file(sender, reciever);

	return 0;
}

int net_raid_open(const char *path, struct fuse_file_info *fi)
{

	pthread_mutex_lock(&sys_lock);

	struct para_info* info[2];
	int i =0;
	int* ret_val = malloc(sizeof(int) * 2);

	for(; i < 2; i++)
	{
		info[i] = malloc(sizeof(struct para_info));
		info[i]->path = path;
		info[i]->num = i;
		info[i]->ret_val = ret_val;
		info[i]->fi = fi;
		info[i]->hash = malloc(HASH_SIZE);
	}

	info[0]->sfd = sfd_1;
	info[1]->sfd = sfd_2;

	//return request_paralel(para_open, info);
	pthread_t thread1, thread2;
	pthread_create(&thread1, NULL, para_open, (void*)info[0]);
	pthread_create(&thread2, NULL, para_open, (void*)info[1]);

	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

	if(ret_val[0] == -EPIPE || ret_val[1] == -EPIPE){
		int r = process_alive_response(ret_val[0], ret_val[1]);
		free(ret_val);
		free(info[0]->hash);
		free(info[1]->hash);
		free(info[0]);
		free(info[1]);
		pthread_mutex_unlock(&sys_lock);
		return r;
	}

	if(ret_val[1] == -ENOENT && (ret_val[0] == 0 || ret_val[0] == 2)){
		ret_val[1] = 1;
	}
	else if(ret_val[0] == -ENOENT && (ret_val[1] == 0 || ret_val[1] == 2)){
		ret_val[0] = 1;
	}


	int ret = process_responses(ret_val[0], ret_val[1], info[0]->hash, info[1]->hash);

	free(info[0]->hash);
	free(info[1]->hash);
	free(ret_val);
	free(info[0]);
	free(info[1]);
	pthread_mutex_unlock(&sys_lock);
	return ret;

}


static int seq_read(int sfd, const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi){
	
	int len = strlen(path);
	if(!send_initial_request(sfd, READ, len)){
		return -EPIPE;
	}

	char buff[2*sizeof(int)+ len];
	*(int*)buff = size;
	*((int*)buff + 1) = offset;

	memcpy(buff + 2*sizeof(int), path, len);


	write(sfd, buff, 2 * sizeof(int) + len);

	char data[BUFSIZE];
	int remain_data = size;
	int to_read = remain_data < BUFSIZE ? remain_data : BUFSIZE;
	int pos = 0;
	int response = 0;
	while(remain_data > 0 ){
		read(sfd, &to_read, sizeof(int));
		if(to_read == 0)
			break;
		write(sfd, &response, sizeof(int));
		read(sfd, data, to_read);
		memcpy(buf + pos, data, to_read);
		pos+=to_read;
		write(sfd, &response, sizeof(int));
		remain_data -= to_read;
	}

	return pos;
}

int net_raid_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{ 	

	pthread_mutex_lock(&sys_lock);

	int ret_val = seq_read(sfd_1, path, buf, size, offset, fi);
	if(ret_val  == -EPIPE || ret_val == -ENOENT){
		memset(buf, 0, size);
		ret_val = seq_read(sfd_2, path, buf, size, offset, fi);
	}
	pthread_mutex_unlock(&sys_lock);
	return ret_val;

}

static int seq_write(int sfd, const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi, int degraded){

	int len = strlen(path);
	if(!send_initial_request(sfd, WRITE, len)){
		return -EPIPE;
	}

	char path_size[2*sizeof(int) + len];
	*(int*)path_size = size;
	*(int*)((int*)path_size+1) = degraded;

	memcpy(path_size + 2*sizeof(int), path, len);
	write(sfd, path_size, 2*sizeof(int) + len);
	int response;
	read(sfd, &response, sizeof(int));
	if(response < 0){
		return response;
	}

	char buff[sizeof(int) + size];
	*(int*)buff = offset;

	memcpy(buff + sizeof(int), buf, size);
	write(sfd, buff, sizeof(int) + size);

	char buff_written[2*sizeof(int)];
	read(sfd, buff_written, 2 * sizeof(int));
	int res = *(int*)buff_written;
	int bytes_written = *((int*)buff_written + 1);

	if(res == -1){
		return -bytes_written;
	}

	return bytes_written;
}


int net_raid_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	pthread_mutex_lock(&sys_lock);

	int res1 = seq_write(sfd_1, path, buf, size, offset, fi, 0);

	if(res1 == -EPIPE){
		int res2 = seq_write(sfd_2, path, buf, size, offset, fi, 1);
		pthread_mutex_unlock(&sys_lock);
		return res2;
	}

	if(res1 < 0 || res1 < size){
		pthread_mutex_unlock(&sys_lock);
		return res1;
	}
	seq_write(sfd_2, path, buf, size, offset, fi, 0);
	pthread_mutex_unlock(&sys_lock);
	return res1;
}


static void* para_truncate(void* attr){
	struct para_info* info = (struct para_info*)attr;
	int sfd = info->sfd;
	int num = info->num;
	int newsize = info->newsize;
	const char * path = info->path;

	int len = strlen(path);
	if(!send_initial_request(sfd, TRUNCATE, len)){
		info->ret_val[num] = -EPIPE;
		return NULL;
	}
	int response; 

	char buff[sizeof(off_t) + len];
	*(off_t*)buff = newsize;
	memcpy(buff + sizeof(off_t), path, len);
	write(sfd, buff, sizeof(off_t) + len);


	read(sfd, &response, sizeof(int));
	info->ret_val[num] = response;
	return NULL;

}

int net_raid_truncate(const char *path, off_t newsize)
{
	pthread_mutex_lock(&sys_lock);

	struct para_info* info[2];
	int i =0;
	int* ret_val = malloc(sizeof(int) * 2);
	for(; i < 2; i++)
	{
		info[i] = malloc(sizeof(struct para_info));
		info[i]->path = path;
		info[i]->num = i;
		info[i]->newsize = newsize;
		info[i]->ret_val = ret_val;
	}
	info[0]->sfd = sfd_1;
	info[1]->sfd = sfd_2;


	int res = request_paralel(para_truncate, info);
	pthread_mutex_unlock(&sys_lock);
	return res;
}


int net_raid_release(const char *path, struct fuse_file_info *fi)
{

	return 0;
}

static void* para_rename(void* attr){
	struct para_info* info = (struct para_info*)attr;
	int sfd = info->sfd;
	int num = info->num;
	const char* path = info->path;
	const char* newpath = info->newpath;

	int len = strlen(path);
	if(!send_initial_request(sfd, RENAME, len)){
		info->ret_val[num] = -EPIPE;
		return NULL; 
	}
	int response;

	char buff[sizeof(int) + len];
	*(int*)buff = strlen(newpath);
	memcpy(buff + sizeof(int), path, len);
	write(sfd, buff, sizeof(int) + len);

	read(sfd, &response, sizeof(int));
	if(response == -1)
		info->ret_val[num] = response;

	write(sfd, newpath, strlen(newpath));

	read(sfd, &response, sizeof(int));
	info->ret_val[num] = response;
	return NULL;
}


int net_raid_rename(const char *path, const char *newpath)
{      
	pthread_mutex_lock(&sys_lock);


	struct para_info* info[2];
	int i =0;
	int* ret_val = malloc(sizeof(int) * 2);
	for(; i < 2; i++)
	{
		info[i] = malloc(sizeof(struct para_info));
		info[i]->path = path;
		info[i]->newpath = newpath;
		info[i]->num = i;
		info[i]->ret_val = ret_val;
	}
	info[0]->sfd = sfd_1;
	info[1]->sfd = sfd_2;

	int res = request_paralel(para_rename, info);
	pthread_mutex_unlock(&sys_lock);
	return res;

}

static void* para_unlink(void* attr){
	struct para_info* info = (struct para_info*)attr;
	int sfd = info->sfd;
	int num = info->num;
	const char *path = info->path;

	int len = strlen(path);
	if(!send_initial_request(sfd, UNLINK, len)){
		info->ret_val[num] = -EPIPE;
		return NULL;
	}
	int response;

	write(sfd, path, len);

	read(sfd, &response, sizeof(int));
	info->ret_val[num] = response;
	return NULL;

}

int net_raid_unlink(const char *path)
{
	pthread_mutex_lock(&sys_lock);

	struct para_info* info[2];
	int i =0;
	int* ret_val = malloc(sizeof(int) * 2);
	for(; i < 2; i++)
	{
		info[i] = malloc(sizeof(struct para_info));
		info[i]->path = path;
		info[i]->num = i;
		info[i]->ret_val = ret_val;
	}
	info[0]->sfd = sfd_1;
	info[1]->sfd = sfd_2;

	int res = request_paralel(para_unlink, info);
	pthread_mutex_unlock(&sys_lock);
	return res;
}

static void* para_rmdir(void* attr){
	struct para_info* info = (struct para_info*)attr;
	int sfd = info->sfd;
	int num = info->num;
	const char *path = info->path;

	int len = strlen(path);
	if(!send_initial_request(sfd, RMDIR, len)){
		info->ret_val[num] = -EPIPE;
		return NULL;
	}
	int response;

	write(sfd, path, len);

	read(sfd, &response, sizeof(int));

	info->ret_val[num] =  response;
	return NULL;
}


int net_raid_rmdir(const char *path)
{
	pthread_mutex_lock(&sys_lock);

	struct para_info* info[2];
	int i =0;
	int* ret_val = malloc(sizeof(int) * 2);
	for(; i < 2; i++)
	{
		info[i] = malloc(sizeof(struct para_info));
		info[i]->path = path;
		info[i]->num = i;
		info[i]->ret_val = ret_val;
	}
	info[0]->sfd = sfd_1;
	info[1]->sfd = sfd_2;

	int res = request_paralel(para_rmdir, info);
	pthread_mutex_unlock(&sys_lock);
	return res;

}

static void* para_opendir(void* attr){
	struct para_info* info = (struct para_info*)attr;
	int sfd = info->sfd;
	int num = info->num;
	struct fuse_file_info * fi = info->fi;
	const char *path = info->path;

	int len = strlen(path);
	if(!send_initial_request(sfd, OPENDIR, len)){
		info->ret_val[num] = -EPIPE;
		return NULL;
	}

	char path_flags[len + sizeof(int)];
	memcpy(path_flags, path, len);
	memcpy(path_flags + len, &fi->flags, sizeof(int));
	write(sfd, path_flags, len);

	char response_buff[sizeof(int) + sizeof(void*)];
	read(sfd, response_buff, sizeof(int) + sizeof(void*));

	if(*(void**)(response_buff + sizeof(int)) == NULL){
		info->ret_val[num] = *(int*)response_buff;
		return NULL;
	}

	info->ret_val[num] = 0;
	return NULL;
}

int net_raid_opendir(const char * path, struct fuse_file_info * fi)
{
	pthread_mutex_lock(&sys_lock);

	struct para_info* info[2];
	int i =0;
	int* ret_val = malloc(sizeof(int) * 2);
	for(; i < 2; i++)
	{
		info[i] = malloc(sizeof(struct para_info));
		info[i]->path = path;
		info[i]->fi =  fi;
		info[i]->num = i;
		info[i]->ret_val = ret_val;
	}
	info[0]->sfd = sfd_1;
	info[1]->sfd = sfd_2;

	int res = request_paralel(para_opendir, info);
	pthread_mutex_unlock(&sys_lock);
	return res;

}

int net_raid_releasedir (const char * path, struct fuse_file_info * fi)
{
	return 0;
}


static void* para_mkdir(void* attr){
	struct para_info* info = (struct para_info*)attr;
	int sfd = info->sfd;
	int num = info->num;
	const char *path = info->path;
	mode_t mode = info->mode;

	int len = strlen(path);
	if(!send_initial_request(sfd, MKDIR, len)){
		info->ret_val[num] = -EPIPE;
		return NULL;
	}

	char path_mode[len + sizeof(mode_t)];
	memcpy(path_mode, path,len);
	*(mode_t*)(path_mode + len) = mode;
	write(sfd, path_mode, len + sizeof(mode_t));

	int retstat;
	read(sfd, &retstat, sizeof(int));

	info->ret_val[num] = retstat;
	return NULL;

}


int net_raid_mkdir(const char * path, mode_t mode)
{	

	pthread_mutex_lock(&sys_lock);

	struct para_info* info[2];
	int i =0;
	int* ret_val = malloc(sizeof(int) * 2);
	for(; i < 2; i++)
	{
		info[i] = malloc(sizeof(struct para_info));
		info[i]->path = path;
		info[i]->mode =  mode;
		info[i]->num = i;
		info[i]->ret_val = ret_val;
	}
	info[0]->sfd = sfd_1;
	info[1]->sfd = sfd_2;

	int res = request_paralel(para_mkdir, info);
	pthread_mutex_unlock(&sys_lock);
	return res;
}

static void* para_mknod(void* attr){
	struct para_info* info = (struct para_info*)attr;
	int sfd = info->sfd;
	int num = info->num;
	const char *path = info->path;
	mode_t mode = info->mode;
	dev_t dev = info->dev;

	int len = strlen(path);
	if(!send_initial_request(sfd, MKNOD, len)){
		info->ret_val[num] = -EPIPE;
		return NULL;
	}

	char path_mode[len+ sizeof(mode_t) + sizeof(dev_t)];
	memcpy(path_mode, path, len);
	*(mode_t*)(path_mode + len) = mode;
	*(dev_t*)(path_mode + len + sizeof(mode_t)) = dev;
	write(sfd, path_mode, len + sizeof(mode_t) + sizeof(dev_t));

	int retstat;
	read(sfd, &retstat, sizeof(int));

	info->ret_val[num] = retstat;

	return NULL;
}


int net_raid_mknod(const char *path, mode_t mode, dev_t dev)
{
	pthread_mutex_lock(&sys_lock);
	struct para_info* info[2];
	int i =0;
	int* ret_val = malloc(sizeof(int) * 2);
	for(; i < 2; i++)
	{
		info[i] = malloc(sizeof(struct para_info));
		info[i]->path = path;
		info[i]->mode =  mode;
		info[i]->dev = dev;
		info[i]->num = i;
		info[i]->ret_val = ret_val;
	}
	info[0]->sfd = sfd_1;
	info[1]->sfd = sfd_2;

	int res = request_paralel(para_mknod, info);
	pthread_mutex_unlock(&sys_lock);
	return res;

}



static void* para_utime(void* attr){
	struct para_info* info = (struct para_info*)attr;
	int sfd = info->sfd;
	int num = info->num;
	const char *path = info->path;
	struct utimbuf* ubuf = info->ubuf;

	int len = strlen(path);
	if(!send_initial_request(sfd, UTIME, len)){
		info->ret_val[num] = -EPIPE;
		return NULL;
	}
	int response;

	char timebuf[len + sizeof(struct utimbuf)];
	memcpy(timebuf, path, len);
	memcpy(timebuf + len, ubuf, sizeof(struct utimbuf));

	write(sfd, timebuf, len + sizeof(struct utimbuf));

	read(sfd, &response, sizeof(int));

	info->ret_val[num] = response;
	return NULL;

}

int net_raid_utime(const char *path, struct utimbuf *ubuf)
{	
	pthread_mutex_lock(&sys_lock);

	struct para_info* info[2];
	int i =0;
	int* ret_val = malloc(sizeof(int) * 2);
	for(; i < 2; i++)
	{
		info[i] = malloc(sizeof(struct para_info));
		info[i]->path = path;
		info[i]->ubuf = ubuf;
		info[i]->num = i;
		info[i]->ret_val = ret_val;
	}
	info[0]->sfd = sfd_1;
	info[1]->sfd = sfd_2;

	int res = request_paralel(para_utime, info);
	pthread_mutex_unlock(&sys_lock);
	return res;
}

static void* para_lock(void* attr){
	struct para_info* info = (struct para_info*)attr;
	int sfd = info->sfd;
	int num = info->num;
	const char *path = info->path;
	struct flock* lock = info->lock;
	int cmd = info->cmd;

	int len = strlen(path);
	if(!send_initial_request(sfd, LOCK, len)){
		info->ret_val[num] = -EPIPE;
		return NULL;
	}

	char buff[sizeof(int) + sizeof(struct flock) + len];
	*(int*)buff = cmd;
	memcpy(buff + sizeof(int), lock, sizeof(struct flock));
	memcpy(buff + sizeof(int) + sizeof(struct flock), path, len);
	write(sfd, buff,sizeof(int) + sizeof(struct flock) + len);

	int response;
	read(sfd, &response, sizeof(int));
	info->ret_val[num] = response;
	return NULL;

}

int net_raid_lock(const char *path, struct fuse_file_info *fi, 
	 int cmd, struct flock *lock){

	pthread_mutex_lock(&sys_lock);

	struct para_info* info[2];
	int i =0;
	int* ret_val = malloc(sizeof(int) * 2);
	for(; i < 2; i++)
	{
		info[i] = malloc(sizeof(struct para_info));
		info[i]->path = path;
		info[i]->lock = lock;
		info[i]->num = i;
		info[i]->cmd = cmd;
		info[i]->ret_val = ret_val;

	}
	info[0]->sfd = sfd_1;
	info[1]->sfd = sfd_2;

	int res = request_paralel(para_lock, info);
	pthread_mutex_unlock(&sys_lock);
	return res;

}

static int transfer_storage(int sender, int reciever){
	int response;
	while(1){
		int stat_sz = 2*sizeof(int) + sizeof(mode_t) + sizeof(dev_t);
		char status[stat_sz];
		read(sender, status, stat_sz);
		int path_len = *(int*)status;
		write(reciever, status, stat_sz);
		if(path_len == -1)
			break;
		read(reciever, &response, sizeof(int));
		write(sender, &response, sizeof(int));

		int file_size = *(int*)((int*)status + 1);
		char path[path_len];

		read(sender, path, path_len);
		write(reciever, path, path_len);

		read(reciever, &response, sizeof(int));
		write(sender, &response, sizeof(int));

		if(response < 0)
			return 0;
		mode_t mode = *(mode_t*)(status + 2*sizeof(int));

		if(S_ISREG(mode)){
			transfer_data(sender, reciever, file_size);
		}
	}
	return 1;
}

static int add_hotswap(int sender, int* reciever){
	if(!socket_connect(hotswap, reciever, &addr_1)){
		raid_log(hotswap, "COULD NOT CONNECT TO HOTSWAP");
		return 0;
	}
	else
		raid_log(hotswap, "CONNECTED AS HOTSWAP : PREPARE FOR STORAGE TRANSFER");
	
	send_initial_request(*reciever, STORAGE_TRANS_TO,  0);
	send_initial_request(sender, STORAGE_TRANS_FROM,  0);

	if(transfer_storage(sender, *reciever)){
		raid_log(hotswap, "STORAGE TRANSFER COMPLETE");
		return 1;
	}
	else{
		raid_log(hotswap, "STORAGE TRANSFER FAILURE");
		return 0;
	}
}


static void* healthcheck(void* info){

	int request[2];
	request[0] = HEALTHCHECK;
	while(1){ 
		pthread_mutex_lock(&sys_lock); 

		if(write(sfd_1, request, sizeof(int)*2) == -1){
			if(timelapse_1 == 0)
				raid_log(server1, "CONNECTION LOST");

			if(timelapse_2 > timeout)
				break;

			close(sfd_1);

			if(timelapse_1 == timeout){
				if(!add_hotswap(sfd_2, &sfd_1))
					exit(-1);
				memcpy(server1, hotswap, 256);
			}else{
				timelapse_1 ++;
				if(socket_connect(server1, &sfd_1, &addr_1)){
					raid_log(server1, "CONNECTION REOPENED");
				}
			}
		}else
			timelapse_1 = 0;


		if(write(sfd_2, request, sizeof(int)*2) == -1){
			if(timelapse_2 == 0)
				raid_log(server2, "CONNECTION LOST");

			if(timelapse_1 > timeout)
				break;

			close(sfd_2);

			if(timelapse_2 == timeout){
				if(!add_hotswap(sfd_1, &sfd_2))
					exit(-1);
				memcpy(server2, hotswap, 256);

			}else{
				timelapse_2 ++;
				if(socket_connect(server2, &sfd_2, &addr_2)){
					raid_log(server2, "CONNECTION REOPENED");
				}
			}
		}else 
			timelapse_2 = 0;

		pthread_mutex_unlock(&sys_lock);
		sleep(1);
	}

	return NULL;
}

static void launch_healthcheck(){
	pthread_mutex_init(&sys_lock, NULL);
	pthread_t health_thread;
	pthread_create(&health_thread,NULL, healthcheck, NULL);
}

void *net_raid_init(struct fuse_conn_info *conn)
{   
	launch_healthcheck();
    return NULL;
}

static struct fuse_operations net_raid_oper = {
	.getattr	= net_raid_getattr,
	.readdir	= net_raid_readdir,
	.open		= net_raid_open,
	.read		= net_raid_read,
	.write      = net_raid_write,
	.release    = net_raid_release,
	.unlink     = net_raid_unlink,
	.rmdir      = net_raid_rmdir,
	.mkdir      = net_raid_mkdir,
	.opendir    = net_raid_opendir,
	.truncate   = net_raid_truncate,
	//.releasedir = net_raid_releasedir,
	.rename     = net_raid_rename,
	//.create     = net_raid_create
	.mknod      = net_raid_mknod,
	.utime      = net_raid_utime,
	.lock       = net_raid_lock,
	.init       =net_raid_init
};

static int socket_connect(char* server, int* sfd_p,struct sockaddr_in* addr)
{

	int ip;

	*sfd_p = socket(AF_INET, SOCK_STREAM, 0);
	char server_buff[256];
	strcpy(server_buff, server);

	char* ad = strtok(server_buff, ":");
	int port = atoi(strtok(NULL, ":"));

	inet_pton(AF_INET, ad, &ip);

	addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = ip;

    if(connect(*sfd_p, (struct sockaddr *) addr, sizeof(struct sockaddr_in)) == -1)
    	return 0;
    return 1;

}

static void start_fuse(char* program_name){
	int pid = fork();

	if(pid == 0){
		log_init(errorlog, diskname);
		char* net_raid_argv[2];
		net_raid_argv[0] = program_name;
		net_raid_argv[1] = mountpoint;

		if(socket_connect(server1, &sfd_1, &addr_1)){
			raid_log(server1, "OPEN CONNECTION");
		}else{
			raid_log(server1, "UNABLE TO OPEN CONNECTION");
		}

		if(socket_connect(server2, &sfd_2, &addr_2)){

			raid_log(server2, "OPEN CONNECTION");
		}else{
			raid_log(server2, "UNABLE TO OPEN CONNECTION");
		}

		fuse_main(2, net_raid_argv, &net_raid_oper, NULL);
		exit(0);
	}
}

static void launch_mountpoints(char* argv[]){
	FILE* f;
	if((f = fopen(argv[1], "r")) == NULL)
	{
		printf("%s\n", "Failed to open config file");
		exit(-1);
	}
	int moutpoints_started = 0;
	char config_line[LINE_SIZE];

	while(!feof(f)){
		fgets(config_line, LINE_SIZE, f);
		if(strstr(config_line, "errorlog = "))
		{
			sscanf(config_line,"errorlog = %s", errorlog);
		}
		else if(strstr(config_line, "cache_size = "))
		{
			sscanf(config_line,"cache_size = %d", &cache_size);
		}
		else if(strstr(config_line, "cache_replacment = "))
		{
			sscanf(config_line,"cache_replacment = %s", cache_replacment);
		}
		else if(strstr(config_line, "timeout = "))
		{
			sscanf(config_line,"timeout = %d", &timeout);
		}
		else if(strstr(config_line, "diskname = "))
		{
			moutpoints_started = 1;
			sscanf(config_line,"diskname = %s", diskname);
		}
		else if(strstr(config_line, "mountpoint = "))
		{
			sscanf(config_line,"mountpoint = %s", mountpoint);
		}
		else if(strstr(config_line, "raid = "))
		{
			sscanf(config_line,"raid = %d", &raid);
		}
		else if(strstr(config_line, "servers = "))
		{
			sscanf(config_line,"servers = %s %s", server1, server2);
			memset(server1 + strlen(server1) - 1, 0, 1);
		}
		else if(strstr(config_line, "hotswap = "))
		{
			sscanf(config_line,"hotswap = %s", hotswap);
		}
		else 
		{
			if(moutpoints_started)
				start_fuse(argv[0]);
		}
	}
	fclose(f);
	start_fuse(argv[0]);
}

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("specify path to config_file\n");
		return 0;
	}
	printf("%s\n", "starting net raid client" );
	launch_mountpoints(argv);

	return 0;
}