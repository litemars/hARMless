#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "includes/crypto.h"

int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext, size_t *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    int total_len = 0;
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    
    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *plaintext, size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    int total_len = 0;
    
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    
    *plaintext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

void generate_random_key(uint8_t *key, size_t key_len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, key, key_len);
        close(fd);
    } else {
        // Fallback to simpler random
        for (size_t i = 0; i < key_len; i++) {
            key[i] = rand() & 0xFF;
        }
    }
}

void generate_random_iv(uint8_t *iv, size_t iv_len) {
    generate_random_key(iv, iv_len);
}

void xor_encrypt_key(uint8_t *key, size_t key_len, uint8_t xor_byte) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] ^= xor_byte;
    }
}
