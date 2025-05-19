
#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>




int authenticate(const char *username, const char *password);
int validate_certificate(const char *cert_file);
int authenticate_client(SSL *ssl);

#endif
