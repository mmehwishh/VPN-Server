#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "encryption.h"

unsigned char aes_key[AES_256_KEY_SIZE];
unsigned char hmac_key[HMAC_SIZE];

void generate_keys() {
    if (!RAND_bytes(aes_key, sizeof(aes_key))) {
        fprintf(stderr, "[-] AES key generation failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!RAND_bytes(hmac_key, sizeof(hmac_key))) {
        fprintf(stderr, "[-] HMAC key generation failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int encrypt_packet(const char *plaintext, unsigned char *encrypted) {
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[IV_SIZE];
    int len;
    int ciphertext_len;
    int plaintext_len = strlen(plaintext);

    if (!RAND_bytes(iv, IV_SIZE)) {
        fprintf(stderr, "[-] IV generation failed\n");
        return -1;
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "[-] Cipher context creation failed\n");
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) {
        fprintf(stderr, "[-] Encryption init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    memcpy(encrypted, iv, IV_SIZE); // Prepend IV

    if (1 != EVP_EncryptUpdate(ctx, encrypted + IV_SIZE, &len, 
                             (unsigned char *)plaintext, plaintext_len)) {
        fprintf(stderr, "[-] Encryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, encrypted + IV_SIZE + len, &len)) {
        fprintf(stderr, "[-] Encryption final failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return IV_SIZE + ciphertext_len;
}

int decrypt_packet(const unsigned char *ciphertext, int ciphertext_len, char *decrypted) {
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[IV_SIZE];
    int len;
    int plaintext_len;

    if (ciphertext_len <= IV_SIZE) {
        fprintf(stderr, "[-] Ciphertext too short\n");
        return -1;
    }

    memcpy(iv, ciphertext, IV_SIZE);
    int data_len = ciphertext_len - IV_SIZE;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "[-] Cipher context creation failed\n");
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) {
        fprintf(stderr, "[-] Decryption init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, (unsigned char *)decrypted, &len, 
                             ciphertext + IV_SIZE, data_len)) {
        fprintf(stderr, "[-] Decryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted + len, &len)) {
        fprintf(stderr, "[-] Decryption final failed - Bad key or corrupted data\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    decrypted[plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void cleanup_encryption() {
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(hmac_key, sizeof(hmac_key));
}
