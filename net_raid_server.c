#include <stdio.h>
#include "string.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <unistd.h> 
#include <fcntl.h>
#include <stdlib.h>
#include "log.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include "md5.h"
#include <sys/sendfile.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include "request.h"
#include <fuse.h>



#define BACKLOG 10
#define HASH_SIZE 16
#define BUF_SIZE 1024


static char* server;
static int port;
static char* storage_dir;
static unsigned char empty[HASH_SIZE];

static void send_file(int cfd, int fd);
static void recieve_data(int cfd, int fd, int remain_data);
static void recieve_file(int cfd, int fd, char* path);
static unsigned char* get_hash(int fd, unsigned char *digest);
static void get_full_path(char* path, char* rel_path, int size);
static int hash_cmp(unsigned char *hash1, unsigned char *hash2);
static void send_data(int cfd, int fd, int remain_data, int off);
static int transfer_storage(int cfd, char* path, char* rel);
static void recieve_storage(int cfd);



static unsigned char* get_hash(int fd, unsigned char *hash)
{

     MD5_CTX ctx;
     char chaine[BUF_SIZE];
     MD5_Init(&ctx);
     int bytes_read=0;
     int off = 0;
     while((bytes_read = pread(fd, chaine, BUF_SIZE, off)) > 0){
     	chaine[bytes_read] = '\0';
     	MD5_Update(&ctx,chaine, bytes_read);
     	off+=bytes_read;
     }
     MD5_Final(hash, &ctx);
     return hash;
}

static void get_full_path(char* path, char* rel_path, int size)
{
	path[strlen(storage_dir)+size] = '\0';
	memcpy(path, storage_dir, strlen(storage_dir));
	memcpy(path + strlen(storage_dir), rel_path, size);

}

static int hash_cmp(unsigned char *hash1, unsigned char *hash2)
{
	int i = 0;
	for(; i < HASH_SIZE; i++){
		if(hash1[i] != hash2[i])
			return 0;
	}
	return 1;
}


static void send_data(int cfd, int fd, int remain_data, int off){
	off_t offset = off;
    int sent_bytes;
    int client_response;
    while((remain_data > 0) && ((sent_bytes = sendfile(cfd, fd, &offset, BUF_SIZE)) > 0))
     {
    	remain_data -= sent_bytes;
    	read(cfd, &client_response, sizeof(int));
    	if(client_response < 0)
    		break;
    }
}
static void send_file(int cfd, int fd){

	struct stat file_stat;

	int client_response;
	char status[sizeof(int) + sizeof(mode_t) + sizeof(dev_t)];
	if(fstat(fd, &file_stat) < 0)
		*(int*)status = -1;
	else{
		*(int*)status = file_stat.st_size;
		*(mode_t*)(status + sizeof(int)) = file_stat.st_mode;
		*(dev_t*)(status + sizeof(int) + sizeof(mode_t)) = file_stat.st_dev;
	}


	write(cfd, status, sizeof(int) + sizeof(mode_t) + sizeof(dev_t));
	read(cfd, &client_response, sizeof(int));

	if(client_response == -1){
		return;
	}

	int remain_data = file_stat.st_size;
	send_data(cfd, fd, remain_data, 0);

    close(fd);

}

static void recieve_data(int cfd, int fd, int remain_data){
	char buffer[BUF_SIZE];
	int len;
	off_t offset = 0;

	int to_read = remain_data < BUF_SIZE ? remain_data : BUF_SIZE;
	while ((remain_data > 0) && ((len = read(cfd, buffer, to_read)) > 0))
    {
    	int res = pwrite(fd, buffer, to_read, offset);

    	write(cfd, &res, sizeof(int));
    	if(res == -1){
    		break;
    	}
    	offset += len;
    	remain_data -=len;
    	to_read = remain_data < BUF_SIZE ? remain_data : BUF_SIZE;
    }
}

static void recieve_file(int cfd, int fd, char* path){
	// printf("im gonna be recieving a file\n");
	char status[sizeof(int) + sizeof(mode_t) + sizeof(dev_t)];
	read(cfd, status, sizeof(int) + sizeof(mode_t) + sizeof(dev_t));

	int response = 0;

	if(fd >= 0){
		// make a new file
		close(fd);
		unlink(path);
	}else{

		response = -1;
	}

	mode_t mode = *(mode_t*)(status + sizeof(int));
	dev_t dev = *(dev_t*)(status + sizeof(int) + sizeof(mode_t));
		
	if (S_ISREG(mode)) {
		response = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
	if (response >= 0)
	  	response = close(response);
    } else if (S_ISFIFO(mode))
	   	response = mkfifo(path, mode);
	else
	   	response = mknod(path, mode, dev);

	fd = open(path, O_RDWR);

	write(cfd, &response, sizeof(int));

	int size =  *(int*)status;

	recieve_data(cfd, fd, size);

    unsigned char digest [16];
	get_hash(fd, digest);
	setxattr(path, "user.hash", digest, HASH_SIZE, 0);

    close(fd);

}

static void getattr_handle(int cfd, int path_len)
{
	printf("getattr\n");

	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;

	char path[strlen(storage_dir)+size+1];
	path[strlen(storage_dir)+size] = '\0';
	memcpy(path, storage_dir, strlen(storage_dir));
	read(cfd, (char*)path+strlen(storage_dir), size);
	printf("%s\n", (char*)path+strlen(storage_dir));

	struct stat stbuf;
	int res = lstat(path, &stbuf);
	char buff[sizeof(int) + sizeof(struct stat)];
	if(res == -1){
		*(int*)buff = -errno;
	}
	else
		*(int*)buff = 0;

	memcpy(buff + sizeof(int) ,&stbuf, sizeof(struct stat));
	write(cfd, buff, sizeof(struct stat));

}
static void open_handle(int cfd, int path_len)
{
	printf("open req\n");
	int response[2];
	response[0] = 0;
	write(cfd, &response[0], sizeof(int));
	int size = path_len;

	char buff[size + sizeof(int)];
	read(cfd, buff, size + sizeof(int));

	char path[strlen(storage_dir)+size+1];
	path[strlen(storage_dir)+size] = '\0';
	memcpy(path, storage_dir, strlen(storage_dir));

	memcpy(path + strlen(storage_dir), buff, size);

	int flags;
	memcpy(&flags, buff + size, sizeof(int));

	int fd = open(path, O_RDWR);
	char hash[sizeof(int) + HASH_SIZE];
	if(fd == -1)
	{
		*(int*)hash = -errno;

		write(cfd, hash, sizeof(int) + HASH_SIZE);
	}else{
		unsigned char new[HASH_SIZE];
		get_hash(fd,new);
		memcpy(hash+sizeof(int), new, HASH_SIZE);
		if(getxattr(path, "user.hash", hash + sizeof(int), HASH_SIZE) == -1 && errno == ENODATA){
			if(hash_cmp(new, empty)){
				*(int*)hash = 0;
			}
			else{
				*(int*)hash = 1;
			}

		}else{
			if(hash_cmp(new, (unsigned char*)hash + sizeof(int)))
				*(int*)hash = 0;
			else{
				*(int*)hash = 1;
			}
		}
		int deg = 1;
		if(getxattr(path, "user.degraded", &deg, sizeof(int)) != -1 && deg == 1){
			*(int*) hash += 2;
		}
		write(cfd, hash, sizeof(int) + HASH_SIZE);
	}

	int cl_res;
	read(cfd, &cl_res, sizeof(int));
	if(cl_res == 0){
		close(fd);
		return;
	}
	else if(cl_res == 1)
		send_file(cfd, fd);
	else if(cl_res == 2)
		recieve_file(cfd, fd, path);

	int deg_init = 0;
	setxattr(path, "user.degraded", &deg_init, sizeof(int), 0);
}

static void read_handle(int cfd, int path_len)
{
	printf("read req\n");
	int response = 0;
	write(cfd, &response, sizeof(int));

	char buff[2 * sizeof(int) + path_len ];
	read(cfd, buff, 2 * sizeof(int) + path_len);


	int read_size = *(int*)buff;
	int offset =  *((int*)buff + 1);
	char path[strlen(storage_dir) + path_len + 1];
	get_full_path(path, buff + 2 * sizeof(int), path_len);
	int fd = open(path, O_RDONLY);

	int remain_data = read_size;
	char data[BUF_SIZE];
	int client_response;
    while(remain_data > 0){
    	int to_send = remain_data < BUF_SIZE ? remain_data : BUF_SIZE;
    	int res = pread(fd, data, to_send, offset);
    	write(cfd, &res, sizeof(int));
    	if(res == 0){
    		break;
    	}
    	read(cfd, &client_response, sizeof(int));
    	write(cfd, data, res);
    	read(cfd, &client_response, sizeof(int));
    	remain_data -= res;
    	offset += res;
    }
    close(fd);

	printf("%s\n", "read done" );
}

static void write_handle(int cfd, int path_len)
{
	printf("write req\n");

	int response = 0;
	write(cfd, &response, sizeof(int));

	char path_size[2*sizeof(int) + path_len];
	read(cfd, path_size, 2*sizeof(int) + path_len);
	int size = *(int*)path_size;
	int degraded = *(int*)((int*)path_size + 1);

	char path[path_len + strlen(storage_dir)+1];
	get_full_path(path, path_size + 2*sizeof(int), path_len);

	int fd = open(path, O_RDWR);
	if(fd == -1)
	{
		int err = -errno;
		printf("error %d\n", errno);
		write(cfd, &err, sizeof(int));
		return;
	}else{
		write(cfd, &fd, sizeof(int));
	}

	char buff[sizeof(int)  + size];
	read(cfd, buff, sizeof(int)+ size);

	int offset =  *(int*)buff;
	int res = pwrite(fd, buff + sizeof(int), size, offset);
	int buff_written[2];
	if(res == -1){
		printf("error %d\n", errno);
		buff_written[0] = -1;
		buff_written[1] = errno;
	}else{

		buff_written[0] = 0;
		buff_written[1] = res;
		unsigned char digest [16];
		get_hash(fd, digest);
		setxattr(path, "user.hash", digest, HASH_SIZE, 0);


		int deg = 1;

		if(degraded && (getxattr(path, "user.degraded", &deg, sizeof(int)) == -1 || deg == 0)){
			setxattr(path, "user.degraded", &degraded, sizeof(int), 0);
		}


	}
	write(cfd, buff_written, 2* sizeof(int));
	close(fd);
}

static void truncate_handle(int cfd, int path_len)
{
	printf("truncate req\n");
	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;

	char buff[sizeof(off_t) + size];
	read(cfd, buff, sizeof(off_t) + size);

	off_t newsize = *(off_t *)buff;

	char path[strlen(storage_dir)+size+1];
	path[strlen(storage_dir)+size] = '\0';
	memcpy(path, storage_dir, strlen(storage_dir));
	memcpy(path+strlen(storage_dir), buff + sizeof(off_t), size);

	int res = truncate(path, newsize);
	if(res == -1){
		res = -errno;
	}
	write(cfd, &res, sizeof(int));
	printf("truncted\n");

}

static void rename_handle(int cfd, int path_len)
{
	printf("rename req\n");
	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;

	char buff[sizeof(int) + size];
	read(cfd, buff, sizeof(int) + size);
	int newsize = *(int*)buff;
	char fp[size + strlen(storage_dir) + 1];
	char fpn[newsize + strlen(storage_dir) + 1];

	get_full_path(fp, buff+sizeof(int), size);

	write(cfd, &response, sizeof(int));

	memcpy(fpn, storage_dir, strlen(storage_dir));
	fpn[newsize + strlen(storage_dir)] = '\0';
	read(cfd, fpn + strlen(storage_dir), newsize);

	int res = rename(fp, fpn);
	if(res == -1)
		res = -errno;
	write(cfd, &res, sizeof(int));
	printf("renamed %s to %s\n", fp, fpn);

}

static void release_handle(int cfd, int path_len)
{
	printf("release req\n");
	int response = 0;
	write(cfd, &response, sizeof(int));

	char path_rel[path_len];
	read(cfd, path_rel, path_len);
	char path[path_len + strlen(storage_dir) + 1];
	get_full_path(path, path_rel, path_len);

	int fd = open(path, O_RDONLY);

	int res = close(fd);
	if(res == -1){
		write(cfd, &errno, sizeof(int));
	}
	else{
		res = 0;
		write(cfd, &res, sizeof(int));
	}

	printf("released\n");

}

static void unlink_handle(int cfd, int path_len)
{
	printf("unlink req\n");
	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;

	char path_rel[size];
	read(cfd, path_rel, size);
	char path[size + strlen(storage_dir) + 1];
	get_full_path(path, path_rel, size);

	int retstat = unlink(path);
	if(retstat == -1)
		retstat = -errno;

	write(cfd, &retstat, sizeof(int));
	printf("%s\n", "unlinked");
}

static void rmdir_handle(int cfd, int path_len)
{
	printf("rmdir req\n");
	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;

	char path_rel[size];
	read(cfd, path_rel, size);
	char path[size + strlen(storage_dir) + 1];
	get_full_path(path, path_rel, size);

	int retstat = rmdir(path);
	if(retstat == -1)
		retstat = -errno;

	write(cfd, &retstat, sizeof(int));
	// printf("%s\n", "dir removed" );
}
static void mkdir_handle(int cfd, int path_len)
{
	printf("mkdir req\n");
	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;

	char path_mode[size + sizeof(mode_t)];
	read(cfd, path_mode, size + sizeof(mode_t));
	char path[size + strlen(storage_dir) + 1];
	get_full_path(path, path_mode, size);
	mode_t mode = *(mode_t *)(path_mode + size);

	int retstat = mkdir(path, mode);
	if(retstat == -1)
		retstat = -errno;
	write(cfd, &retstat, sizeof(int));

	printf("%s\n", "mkdir made");
}

static void opendir_handle(int cfd, int path_len)
{
	printf("opendir req\n");
	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;

	char buff[size + sizeof(int)];
	read(cfd, buff, size + sizeof(int));

	char path[strlen(storage_dir)+size+1];
	path[strlen(storage_dir)+size] = '\0';
	memcpy(path, storage_dir, strlen(storage_dir));

	memcpy(path + strlen(storage_dir), buff, size);


	int flags;
	memcpy(&flags, buff + size, sizeof(int));
	DIR *dp;

    dp = opendir(path);

    char respone_buff[sizeof(int) + sizeof(void*)];
	if(dp == NULL){
		*(void**)(respone_buff + sizeof(int)) = NULL; 
		*(int*)respone_buff = -errno;
		write(cfd, respone_buff, sizeof(int));
	}
	else{
		*(void**)(respone_buff + sizeof(int)) = dp; 
		write(cfd, respone_buff, sizeof(int) + sizeof(void*));
	}
	closedir(dp);
	printf("opened dir\n");
}

static void releasedir_handle(int cfd, int path_len)
{
	printf("releasedir req\n");
	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;

	char path_rel[size];
	read(cfd, path_rel, size);
	char path[size + strlen(storage_dir) + 1];
	get_full_path(path, path_rel, size);

	DIR* dp = opendir(path);

	int res = closedir(dp);
	if(res == -1)
		write(cfd, &errno, sizeof(int));
	else{
		res = 0;
		write(cfd, &res, sizeof(int));
	}
	printf("released dir %s\n", path);

}

static void create_handle(int cfd, int path_len)
{
	printf("create req\n");
}

static void readdir_handle(int cfd, int path_len)
{
	printf("readdir req %d\n", path_len);
	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;


	char path_rel[size];
	read(cfd, path_rel, size);
	char path[size + strlen(storage_dir) + 1];
	get_full_path(path, path_rel, size);

	DIR* dp = opendir(path);
	struct dirent *de;

	if (dp == NULL){
		int failure = -errno;
		write(cfd, &failure, sizeof(int));
	}

	int name_length;
	while ((de = readdir(dp)) != NULL) {
		name_length = strlen(de->d_name);
		struct stat st;
		memset(&st, 0, sizeof(st));

		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		char dir_stat[sizeof(int) + sizeof(struct stat)];

		*(int*)dir_stat = name_length;
		memcpy(dir_stat + sizeof(int), &st, sizeof(struct stat));

		write(cfd, &dir_stat, sizeof(int) + sizeof(struct stat));
		int res = 0;
		read(cfd, &res, sizeof(int));
		write(cfd, de->d_name, name_length);	
		read(cfd, &res, sizeof(int));
	} 

	name_length = 0;
	write(cfd, &name_length, sizeof(int));
	closedir(dp);
	printf("%s\n","dir read\n" );
}

static void mknod_handle(int cfd, int path_len)
{
	printf("mknod req\n");
	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;

	char path_mode[size + sizeof(mode_t) + sizeof(dev_t)];
	read(cfd, path_mode, size + sizeof(mode_t) + sizeof(dev_t));
	char path[size + strlen(storage_dir) + 1];
	get_full_path(path, path_mode, size);
	mode_t mode = *(mode_t *)(path_mode + size);
	dev_t dev = *(dev_t*)(path_mode + sizeof(mode_t));

	int retstat;
	if (S_ISREG(mode)) {
	retstat = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
	if (retstat >= 0)
	    retstat = close(retstat);
    } else
	if (S_ISFIFO(mode))
	    retstat = mkfifo(path, mode);
	else
	    retstat = mknod(path, mode, dev);
	if(retstat == -1)
		retstat = -errno;

	int deg_init = 0;
	setxattr(path, "user.degraded", &deg_init, sizeof(int), 0);


	write(cfd, &retstat, sizeof(int));
	printf("%s\n", "node made");
}

static void utime_handle(int cfd, int path_len)
{
	printf("utime req\n");
	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;

	char ubuf[size + sizeof(struct utimbuf)];
	read(cfd, ubuf, size + sizeof(struct utimbuf));


	char path[size + strlen(storage_dir) + 1];
	get_full_path(path, ubuf, size);

	int res = utime(path, (struct utimbuf *)(ubuf + size));

	if(res == -1)
		res = -errno;
	else
		res = 0;

	write(cfd, &res, sizeof(int));
	printf("%s %d\n","time set", res);
}

static void lock_handle(int cfd, int path_len)
{
	printf("%s\n", "lock" );
	int response = 0;
	write(cfd, &response, sizeof(int));
	int size = path_len;

	char buff[sizeof(int) + sizeof(struct flock) + size];
	read(cfd, buff,sizeof(int) + sizeof(struct flock) + size);
	int cmd = *(int*)buff;
	struct flock lock;
	memcpy(&lock, buff + sizeof(int), sizeof(struct flock));
	char path[strlen(storage_dir) + size + 1];
	get_full_path(path,buff + sizeof(int) + sizeof(struct flock), size);
	
	int fd = open(path, O_WRONLY);

	if (fd == -1)
		response = -errno;
	else if (cmd != F_GETLK && cmd != F_SETLK && cmd != F_SETLKW)
		response = -EINVAL;
	else if (fcntl(fd, cmd, &lock) == -1)
		response = -errno;
	else
		response = 0;
	write(cfd, &response, sizeof(int));
	printf("%s\n", "lock done");

}

static void get_empty_hash(){
	MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx,"", 0);
    MD5_Final(empty, &ctx);
}

static void healthcheck_handle(int cfd){
	printf("%s\n", "healthcheck" );
}


static int transfer_storage(int cfd, char* path, char* rel){

	DIR* dp = opendir(path);

	struct dirent *de;

	if (dp == NULL){
		int failure = -errno;
		write(cfd, &failure, sizeof(int));
	}

	int response;
	int name_length;
	while ((de = readdir(dp)) != NULL) {
		name_length = strlen(de->d_name);
		printf("%s\n", de->d_name );
		if((strcmp(de->d_name, ".") == 0) || (strcmp(de->d_name, "..") == 0))
			continue;
		
		char path_server[strlen(path) + name_length + 2];
		char path_client[strlen(rel) + name_length + 2];

		path_server[strlen(path)+name_length+1] = '\0';
		path_server[strlen(path)]='/';
		path_client[strlen(rel)+name_length + 1] = '\0';
		path_client[strlen(rel)]='/';

		memcpy(path_server, path, strlen(path));
		memcpy(path_server + strlen(path) +1, de->d_name, name_length);
		memcpy(path_client, rel, strlen(rel));
		memcpy(path_client + strlen(rel) +1, de->d_name, name_length);

		struct stat stbuf;
		lstat(path_server, &stbuf);

		char status[2*sizeof(int) + sizeof(mode_t) + sizeof(dev_t)];
		*(int*)status = strlen(path_client);
		*(int*)((int*)status + 1) = stbuf.st_size;
		*(mode_t*)(status + 2*sizeof(int)) = stbuf.st_mode;
		*(dev_t*)(status + 2*sizeof(int) + sizeof(mode_t)) = stbuf.st_dev;
		write(cfd, status, 2*sizeof(int) + sizeof(mode_t) + sizeof(dev_t));

		read(cfd, &response, sizeof(int));

		write(cfd, path_client, strlen(path_client));

		read(cfd, &response, sizeof(int));
		if(response < 0){
			closedir(dp);
			return 0;
		}
		if(S_ISDIR(stbuf.st_mode)){
			if(!transfer_storage(cfd, path_server, path_client)){
				closedir(dp);
				return 0;
			}
		}else if(S_ISREG(stbuf.st_mode)){
			int fd = open(path_server, O_RDONLY);

			int deg_init = 0;
			setxattr(path, "user.degraded", &deg_init, sizeof(int), 0);
			send_data(cfd, fd, stbuf.st_size, 0);
		}
	}
	if(strcmp(path, storage_dir) == 0){

		char status[2*sizeof(int) + sizeof(mode_t) + sizeof(dev_t)];
		*(int*)status = -1;
		write(cfd, status, 2*sizeof(int) + sizeof(mode_t) + sizeof(dev_t));
	}

	closedir(dp);
	return 1;

}

static void recieve_storage(int cfd){
	printf("%s\n", "recieving storage" );
	char status[2*sizeof(int) + sizeof(mode_t) + sizeof(dev_t)];
	int status_size = 2*sizeof(int) + sizeof(mode_t) + sizeof(dev_t); 
	int response = 0;
	while(1){
		// printf("%s\n", "new loop" );
		read(cfd, status, status_size);
		int path_len = *(int*)status;
		if(path_len == -1)
			break;
		int file_size = *(int*)((int*)status+1);
		mode_t mode = *(mode_t*)(status + 2*sizeof(int));
		dev_t dev = *(dev_t*)(status + 2*sizeof(int) + sizeof(mode_t));

		char path[path_len];
		write(cfd, &response, sizeof(int));
		read(cfd, path, path_len);

		char full_path[strlen(storage_dir) + path_len + 1];
		get_full_path(full_path, path, path_len);
		printf("%s\n", full_path);
		int res;
		if(S_ISDIR(mode)){

			res = mkdir(full_path, mode);
			if(res == 0)
				write(cfd, &res, sizeof(int));
			else{
				write(cfd, &res, sizeof(int));
				break;
			}

		}else if(S_ISREG(mode)){
			response = mknod(full_path, mode, dev);
			res = open(full_path, O_RDWR);
			int fd = res;
			if(fd > 0)
				write(cfd, &res, sizeof(int));
			else{
				write(cfd, &res, sizeof(int));
				break;
			}
			int deg_init = 0;
			setxattr(path, "user.degraded", &deg_init, sizeof(int), 0);
			recieve_data(cfd, fd, file_size);
			close(fd);
		}
	}
}

static void storage_from_handle(int cfd){
	int response = 0;
	write(cfd, &response, sizeof(int));

	transfer_storage(cfd, storage_dir, "");
}

static void storage_to_handle(int cfd){
	int response = 0;
	write(cfd, &response, sizeof(int));

	recieve_storage(cfd);
}


void client_handler(int cfd) {
	get_empty_hash();
	while(1){
	int request;
	int requests[2];
	read(cfd, requests, 2 * sizeof(int));
	request = requests[0];
	requests[0] = 0;
	if(request == GETATTR)
		getattr_handle(cfd, requests[1]);
	else if(request == OPEN)
		open_handle(cfd, requests[1]);
	else if(request ==  READ)
		read_handle(cfd, requests[1]);
	else if(request == WRITE)
		write_handle(cfd, requests[1]);
	else if(request == RENAME)
		rename_handle(cfd, requests[1]); 
	else if(request == RELEASE)
		release_handle(cfd, requests[1]);
	else if(request == UNLINK)
		unlink_handle(cfd, requests[1]);
	else if(request == RMDIR)
		rmdir_handle(cfd, requests[1]);
	else if(request == MKDIR)
		mkdir_handle(cfd, requests[1]);
	else if(request == READDIR)
		readdir_handle(cfd, requests[1]);
	else if(request == OPENDIR)
		opendir_handle(cfd, requests[1]);
	else if(request == CREATE)
		create_handle(cfd, requests[1]);
	else if(request == RELEASEDIR)
		releasedir_handle(cfd, requests[1]);
	else if(request == TRUNCATE)
		truncate_handle(cfd, requests[1]);
	else if(request == MKNOD)
		mknod_handle(cfd, requests[1]);
	else if(request == UTIME)
		utime_handle(cfd, requests[1]);
	else if(request == LOCK)
	 	lock_handle(cfd, requests[1]);
	else if(request == HEALTHCHECK)
		healthcheck_handle(cfd);
	else if(request == STORAGE_TRANS_TO)
		storage_to_handle(cfd);
	else if(request == STORAGE_TRANS_FROM)
		storage_from_handle(cfd);
	else 
		break;
	}
}

int main(int argc, char* argv[])
{
	server = argv[1];
	port = atoi(argv[2]);
	storage_dir = argv[3];

	int sfd, cfd;
	int optval = 1;
    struct sockaddr_in addr;
    struct sockaddr_in peer_addr;
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
    listen(sfd, BACKLOG);

    while (1) 
    {
        socklen_t peer_addr_size = sizeof(struct sockaddr_in);
        cfd = accept(sfd, (struct sockaddr *) &peer_addr, &peer_addr_size);
        printf("connected to a new client\n");
        switch(fork()) {
            case -1:
                exit(100);
            case 0:
                close(sfd);
                client_handler(cfd);
                printf("exiting\n");
                exit(0);
            default:
                close(cfd);
        }
    }
    close(sfd);

}