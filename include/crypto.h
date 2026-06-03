
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint8_t S[256];
    uint8_t i;
    uint8_t j;
} rc4_context_t;

// RC4 functions
void rc4_init(rc4_context_t* ctx, const uint8_t* key, size_t key_len);
void rc4_crypt(rc4_context_t* ctx, const uint8_t* input, uint8_t* output, size_t len);
void rc4_encrypt_decrypt(const uint8_t* key, size_t key_len, const uint8_t* input, uint8_t* output, size_t len);

// Advanced cryptographic functions
void aes256_encrypt(uint8_t* data, size_t len, const uint8_t* key);
void aes256_decrypt(uint8_t* data, size_t len, const uint8_t* key);
void chacha20_encrypt(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* nonce);
void chacha20_decrypt(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* nonce);

#endif
