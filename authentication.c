#include "authentication.h"
#include <string.h>
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct {
    const char *username;
    const char *password;
} User;

User valid_users[] = {
    {"mehwish", "secure123"},
    {"tasbiha", "vpnpass"},
    {"areeza",  "hello123"},
};

#define USER_COUNT (sizeof(valid_users) / sizeof(User))

int authenticate(const char *username, const char *password) {
    for (int i = 0; i < (int)USER_COUNT; i++) { 
        if (strcmp(username, valid_users[i].username) == 0 &&
            strcmp(password, valid_users[i].password) == 0) {
            return 1; 
        }
    }
    return 0; 
}

int authenticate_client(SSL *ssl) {
    char username[50], password[50];
    
    SSL_read(ssl, username, sizeof(username));
    SSL_read(ssl, password, sizeof(password));
    
    if (authenticate(username, password)) {
        SSL_write(ssl, "AUTH_OK", 7);
        printf("[+] Authenticated: %s\n", username);
        return 1;
    } else {
        SSL_write(ssl, "AUTH_FAIL", 9);
        printf("[-] Authentication failed.\n");
        return 0;
    }
}


int validate_certificate(const char *cert_file) {
    FILE *fp = fopen(cert_file, "r");
    if (!fp) {
        perror("Certificate file not found");
        return 0;
    }

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!cert) {
        fprintf(stderr, "Failed to read certificate.\n");
        return 0;
    }

    
    printf("[+] Certificate loaded and basic check passed.\n");
    X509_free(cert);
    return 1;
}

