#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <arpa/inet.h>
#include "vpn_config.h"

int connect_to_server(const char *server_ip);

#endif
