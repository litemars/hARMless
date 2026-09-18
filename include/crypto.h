
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int aes256_ctr_crypt(uint8_t* data, size_t len, const uint8_t* key,
                     const uint8_t* iv);

#endif
