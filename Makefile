all: net_raid_client net_raid_server

net_raid_client: net_raid_client.c log.c
				gcc -Wall net_raid_client.c log.c `pkg-config fuse --cflags --libs` -o net_raid_client

net_raid_server: net_raid_server.c 
				gcc -Wall -D_FILE_OFFSET_BITS=64 net_raid_server.c log.c md5.c -o net_raid_server 

clean: 
	  rm net_raid_client net_raid_server