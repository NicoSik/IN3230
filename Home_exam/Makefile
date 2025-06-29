CC=gcc
CFLAGS=-Wall -Wextra -g

all: mip_daemon ping_server ping_client

mip_daemon: mip_daemon.c
	$(CC) $(CFLAGS) -o mip_daemon mip_daemon.c

ping_server: ping_server.c
	$(CC) $(CFLAGS) -o ping_server ping_server.c

ping_client: ping_client.c
	$(CC) $(CFLAGS) -o ping_client ping_client.c

clean:
	rm -f mip_daemon ping_server ping_client
