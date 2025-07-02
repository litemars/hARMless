#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "includes/crypto.h"
#include "includes/common.h"

int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext, size_t *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ERROR_PRINT("Failed to create EVP cipher context");
        return -1;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ERROR_PRINT("Failed to initialize AES encryption");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    int total_len = 0;
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        ERROR_PRINT("Failed to encrypt data");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        ERROR_PRINT("Failed to finalize encryption");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    
    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    
    DEBUG_PRINT("AES encryption: %zu bytes -> %d bytes", plaintext_len, total_len);
    return 0;
}

int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *plaintext, size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ERROR_PRINT("Failed to create EVP cipher context");
        return -1;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ERROR_PRINT("Failed to initialize AES decryption");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    int total_len = 0;
    
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        ERROR_PRINT("Failed to decrypt data");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        ERROR_PRINT("Failed to finalize decryption");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;
    
    *plaintext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    
    DEBUG_PRINT("AES decryption: %zu bytes -> %d bytes", ciphertext_len, total_len);
    return 0;
}

// Simple encryption for use in minimal loader (no OpenSSL dependency)
int simple_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *key, size_t key_len,
                   uint8_t *ciphertext, size_t *ciphertext_len) {
    // Simple XOR-based encryption for loader compatibility
    // This is NOT secure but works for demonstration
    
    if (key_len == 0) {
        ERROR_PRINT("Key length cannot be zero");
        return -1;
    }
    
    for (size_t i = 0; i < plaintext_len; i++) {
        ciphertext[i] = plaintext[i] ^ key[i % key_len];
    }
    
    *ciphertext_len = plaintext_len;
    return 0;
}

int simple_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *key, size_t key_len,
                   uint8_t *plaintext, size_t *plaintext_len) {
    // XOR decryption (symmetric with encryption)
    
    if (key_len == 0) {
        ERROR_PRINT("Key length cannot be zero");
        return -1;
    }
    
    for (size_t i = 0; i < ciphertext_len; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % key_len];
    }
    
    *plaintext_len = ciphertext_len;
    return 0;
}

void generate_random_key(uint8_t *key, size_t key_len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t bytes_read = read(fd, key, key_len);
        close(fd);
        
        if (bytes_read == (ssize_t)key_len) {
            DEBUG_PRINT("Generated %zu bytes of random key data", key_len);
            return;
        }
    }
    
    // Fallback to simpler random (less secure)
    // WARNING_PRINT("Using fallback random number generation");
    srand(time(NULL));
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rand() & 0xFF;
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

void derive_key_from_payload(const uint8_t *payload, size_t payload_len,
                             uint8_t *derived_key, size_t key_len) {
    // Simple key derivation from payload
    // In practice, you'd use a proper KDF like PBKDF2
    
    for (size_t i = 0; i < key_len; i++) {
        derived_key[i] = 0;
    }
    
    for (size_t i = 0; i < payload_len; i++) {
        derived_key[i % key_len] ^= payload[i];
    }
    
    // Add some complexity
    for (size_t i = 0; i < key_len; i++) {
        derived_key[i] ^= (uint8_t)(i + 0x5A);
    }
}

int validate_encrypted_data(const uint8_t *ciphertext, size_t ciphertext_len) {
    if (!ciphertext || ciphertext_len == 0) {
        return -1;
    }
    
    // Basic validation - check for patterns that suggest unencrypted data
    size_t zero_count = 0;
    size_t pattern_count = 0;
    
    for (size_t i = 0; i < ciphertext_len; i++) {
        if (ciphertext[i] == 0) {
            zero_count++;
        }
        
        if (i > 0 && ciphertext[i] == ciphertext[i-1]) {
            pattern_count++;
        }
    }
    
    // If more than 50% zeros or too many patterns, likely not encrypted
    if (zero_count > ciphertext_len / 2 || pattern_count > ciphertext_len / 3) {
        DEBUG_PRINT("Data appears to be unencrypted (zeros: %zu, patterns: %zu)", 
                     zero_count, pattern_count);
        return -1;
    }
    
    return 0;
}