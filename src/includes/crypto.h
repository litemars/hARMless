#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// AES encryption/decryption functions
int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext, size_t *ciphertext_len);

int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *plaintext, size_t *plaintext_len);

void generate_random_key(uint8_t *key, size_t key_len);
void generate_random_iv(uint8_t *iv, size_t iv_len);

// Simple XOR encryption for key obfuscation
void xor_encrypt_key(uint8_t *key, size_t key_len, uint8_t xor_byte);

#endif // CRYPTO_H
