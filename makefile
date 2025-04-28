CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lssl -lcrypto -lpthread

all: vpn_server vpn_client

vpn_server: vpn_server.c encryption.c authentication.c network_utils.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

vpn_client: vpn_client.c encryption.c authentication.c network_utils.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f vpn_server vpn_client

.PHONY: all clean
