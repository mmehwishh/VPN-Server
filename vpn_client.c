#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "network_utils.h"
#include "encryption.h"
#include "authentication.h"
#include "vpn_config.h"

SSL_CTX* initialize_ssl_context() {
    SSL_CTX *ctx;
    
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    
    if (!SSL_CTX_load_verify_locations(ctx, CA_CERTIFICATE, NULL)) {
        fprintf(stderr, "Error loading CA certificate\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);

    return ctx;
}

int authenticate_with_server(SSL *ssl) {
    char username[50], password[50];
    char response[10] = {0};

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0';

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';

    SSL_write(ssl, username, strlen(username));
    SSL_write(ssl, password, strlen(password));

    SSL_read(ssl, response, sizeof(response));
    
    if (strcmp(response, "AUTH_OK") == 0) {
        printf("[+] Authentication successful\n");
        if (SSL_read(ssl, aes_key, sizeof(aes_key)) <= 0 ||
            SSL_read(ssl, hmac_key, sizeof(hmac_key)) <= 0) {
            fprintf(stderr, "[-] Key exchange failed\n");
            return 0;
        }
        return 1;
    } else {
        printf("[-] Authentication failed\n");
        return 0;
    }
}


void print_help() {
    printf("\nVPN Commands:\n");
    printf("connect <host> - Establish VPN connection\n");
    printf("disconnect    - Terminate connection\n");
    printf("status        - Show connection info\n");
    printf("ping <host>   - Test connectivity\n");
    printf("help          - Show this help\n");
    printf("exit          - Quit VPN client\n\n");
}

void client_loop(SSL *ssl) {
    char message[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE];
    char decrypted[BUFFER_SIZE];
    int enc_len, recv_len;

    print_help();

    while (1) {
        printf("VPN> ");
        if (!fgets(message, sizeof(message), stdin)) {
            break;
        }
        message[strcspn(message, "\n")] = '\0';

        if (strcmp(message, "exit") == 0 || 
            strcmp(message, "disconnect") == 0) {
            enc_len = encrypt_packet(message, encrypted);
            SSL_write(ssl, encrypted, enc_len);
            break;
        }
        else if (strcmp(message, "help") == 0) {
            print_help();
            continue;
        }

        enc_len = encrypt_packet(message, encrypted);
        if (enc_len <= 0 || SSL_write(ssl, encrypted, enc_len) <= 0) {
            printf("[-] Send failed\n");
            break;
        }

        recv_len = SSL_read(ssl, encrypted, sizeof(encrypted));
        if (recv_len <= 0) {
            printf("[-] Receive failed\n");
            break;
        }

        if (decrypt_packet(encrypted, recv_len, decrypted) <= 0) {
            printf("[-] Decryption failed\n");
            break;
        }
        
        printf("\n[VPN Server]:\n%s\n\n", decrypted);
    }

    cleanup_encryption();
    printf("[!] VPN session ended\n");
}
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <server_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    SSL_CTX *ctx = initialize_ssl_context();
    int sock = connect_to_server(argv[1]);
    
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (!authenticate_with_server(ssl)) {
        goto cleanup;
    }

    client_loop(ssl);

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}
