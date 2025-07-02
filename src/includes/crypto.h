#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// AES encryption/decryption functions (consistent implementation)
int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext, size_t *ciphertext_len);

int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *plaintext, size_t *plaintext_len);

// Key and IV generation
void generate_random_key(uint8_t *key, size_t key_len);
void generate_random_iv(uint8_t *iv, size_t iv_len);

// Simple encryption for loader (must match packer)
int simple_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *key, size_t key_len,
                   uint8_t *ciphertext, size_t *ciphertext_len);

int simple_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *key, size_t key_len,
                   uint8_t *plaintext, size_t *plaintext_len);

// Key obfuscation utilities
void xor_encrypt_key(uint8_t *key, size_t key_len, uint8_t xor_byte);
void derive_key_from_payload(const uint8_t *payload, size_t payload_len,
                             uint8_t *derived_key, size_t key_len);

// Crypto validation
int validate_encrypted_data(const uint8_t *ciphertext, size_t ciphertext_len);

#endif // CRYPTO_H
