#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/evp.h>
#include <openssl/rsa.h>

#define AES_256_KEY_SIZE 32
#define IV_SIZE 16
#define HMAC_SIZE 32

// Declare the shared keys as extern
extern unsigned char aes_key[AES_256_KEY_SIZE];
extern unsigned char hmac_key[HMAC_SIZE];

void generate_keys();
int encrypt_packet(const char *plaintext, unsigned char *encrypted);
int decrypt_packet(const unsigned char *ciphertext, int ciphertext_len, char *decrypted);
void cleanup_encryption();

#endif
