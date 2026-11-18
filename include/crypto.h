#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int aes256_gcm_encrypt(uint8_t* data, size_t len, const uint8_t* key,
                       const uint8_t* iv, uint8_t* tag);
int aes256_gcm_decrypt(uint8_t* data, size_t len, const uint8_t* key,
                       const uint8_t* iv, const uint8_t* tag);

#endif
