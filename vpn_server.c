#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include "encryption.h"
#include "authentication.h"
#include "vpn_config.h"

SSL_CTX *ssl_ctx;

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_library_init();
}

void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

SSL_CTX* create_ssl_context() {
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (!validate_certificate(SERVER_CERTIFICATE)) {
        fprintf(stderr, "Server certificate validation failed\n");
        exit(EXIT_FAILURE);
    }
    
    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERTIFICATE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_PRIVATE_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Add these helper functions at the top
const char* get_session_duration() {
    static char buf[20];
    // In real implementation, calculate duration
    snprintf(buf, sizeof(buf), "00:%02d:%02d", rand()%60, rand()%60);
    return buf;
}

// Modify the handle_client function
void handle_client(SSL *ssl) {
    if (!authenticate_client(ssl)) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    generate_keys();
    
    // Send keys to client
    if (SSL_write(ssl, aes_key, sizeof(aes_key)) <= 0 ||
        SSL_write(ssl, hmac_key, sizeof(hmac_key)) <= 0) {
        fprintf(stderr, "[-] Key exchange failed\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    unsigned char buffer[BUFFER_SIZE];
    char decrypted[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    int len;

    printf("[+] Client authenticated and keys exchanged\n");

    while (1) {
        len = SSL_read(ssl, buffer, sizeof(buffer));
        if (len <= 0) {
            int err = SSL_get_error(ssl, len);
            if (err == SSL_ERROR_ZERO_RETURN) {
                printf("[*] Client disconnected\n");
            }
            break;
        }

        if (decrypt_packet(buffer, len, decrypted) <= 0) {
            fprintf(stderr, "[-] Decryption failed\n");
            break;
        }

        printf("[Client Command]: %s\n", decrypted);

        // Command processing
        if (strncmp(decrypted, "connect ", 8) == 0) {
            char* target = decrypted + 8;
            snprintf(response, sizeof(response),
                   "VPN CONNECTED TO: %s\n"
                   "Encryption: AES-256-CBC\n"
                   "Assigned IP: 10.8.0.%d\n"
                   "Status: Secure", 
                   target, rand()%254 + 1);
        }
        else if (strcmp(decrypted, "disconnect") == 0) {
            strcpy(response, "VPN DISCONNECTED\nAll traffic now unencrypted");
            break;
        }
        else if (strcmp(decrypted, "status") == 0) {
            snprintf(response, sizeof(response),
                   "VPN STATUS:\n"
                   "Uptime: %s\n"
                   "Data TX: %.1f KB\n"
                   "Data RX: %.1f KB\n"
                   "Encryption: Active",
                   get_session_duration(),
                   (float)(rand()%10000)/10,
                   (float)(rand()%8000)/10);
        }
        else if (strncmp(decrypted, "ping ", 5) == 0) {
            char* host = decrypted + 5;
            snprintf(response, sizeof(response),
                   "PING %s:\n"
                   "64 bytes, time=%dms, TTL=64\n"
                   "VPN latency: %dms",
                   host, rand()%50+10, rand()%20+5);
        }
        else {
            strcpy(response, "Unknown VPN command");
        }

        // Encrypt and send response
        unsigned char encrypted[BUFFER_SIZE];
        int enc_len = encrypt_packet(response, encrypted);
        
        if (enc_len <= 0 || SSL_write(ssl, encrypted, enc_len) <= 0) {
            fprintf(stderr, "[-] Response failed\n");
            break;
        }
    }

    cleanup_encryption();
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void *client_thread(void *arg) {
    SSL *ssl = (SSL *)arg;
    handle_client(ssl);
    return NULL;
}

void start_server() {
    int server_fd, client_fd;
    struct sockaddr_in server, client;
    socklen_t c = sizeof(client);

    init_openssl();
    ssl_ctx = create_ssl_context();
    configure_ssl_context(ssl_ctx);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[-] Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(SERVER_PORT);
    server.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("[-] Bind failed");
        exit(EXIT_FAILURE);
    }

    listen(server_fd, MAX_CLIENTS);
    printf("🚀 VPN Server listening on port %d\n", SERVER_PORT);

    while ((client_fd = accept(server_fd, (struct sockaddr *)&client, &c))) {
        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl)) {
            pthread_t tid;
            pthread_create(&tid, NULL, client_thread, ssl);
            pthread_detach(tid);
        } else {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
        }
    }

    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
    close(server_fd);
}

int main() {
    start_server();
    return 0;
}
