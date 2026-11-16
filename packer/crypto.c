#include "crypto.h"
#include "common.h"
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#if defined(__aarch64__)
const volatile uint32_t hARMless_sc[SC_TABLE_LEN] = {
    [SC_IDX_READ]              =  63u ^ SC_XOR_KEY,
    [SC_IDX_WRITE]             =  64u ^ SC_XOR_KEY,
    [SC_IDX_OPEN]              =  56u ^ SC_XOR_KEY,
    [SC_IDX_CLOSE]             =  57u ^ SC_XOR_KEY,
    [SC_IDX_MMAP]              = 222u ^ SC_XOR_KEY,
    [SC_IDX_MUNMAP]            = 215u ^ SC_XOR_KEY,
    [SC_IDX_EXECVE]            = 221u ^ SC_XOR_KEY,
    [SC_IDX_MEMFD_CREATE]      = 279u ^ SC_XOR_KEY,
    [SC_IDX_FTRUNCATE]         =  46u ^ SC_XOR_KEY,
    [SC_IDX_LSEEK]             =  62u ^ SC_XOR_KEY,
    [SC_IDX_MPROTECT]          = 226u ^ SC_XOR_KEY,
    [SC_IDX_MSYNC]             = 227u ^ SC_XOR_KEY,
    [SC_IDX_IO_URING_SETUP]    = 425u ^ SC_XOR_KEY,
    [SC_IDX_IO_URING_ENTER]    = 426u ^ SC_XOR_KEY,
    [SC_IDX_IO_URING_REGISTER] = 427u ^ SC_XOR_KEY,
};
#elif defined(__x86_64__)
const volatile uint32_t hARMless_sc[SC_TABLE_LEN] = {
    [SC_IDX_READ]              =   0u ^ SC_XOR_KEY,
    [SC_IDX_WRITE]             =   1u ^ SC_XOR_KEY,
    [SC_IDX_OPEN]              =   2u ^ SC_XOR_KEY,
    [SC_IDX_CLOSE]             =   3u ^ SC_XOR_KEY,
    [SC_IDX_MMAP]              =   9u ^ SC_XOR_KEY,
    [SC_IDX_MUNMAP]            =  11u ^ SC_XOR_KEY,
    [SC_IDX_EXECVE]            =  59u ^ SC_XOR_KEY,
    [SC_IDX_MEMFD_CREATE]      = 319u ^ SC_XOR_KEY,
    [SC_IDX_FTRUNCATE]         =  77u ^ SC_XOR_KEY,
    [SC_IDX_LSEEK]             =   8u ^ SC_XOR_KEY,
    [SC_IDX_MPROTECT]          =  10u ^ SC_XOR_KEY,
    [SC_IDX_MSYNC]             =  26u ^ SC_XOR_KEY,
    [SC_IDX_IO_URING_SETUP]    = 425u ^ SC_XOR_KEY,
    [SC_IDX_IO_URING_ENTER]    = 426u ^ SC_XOR_KEY,
    [SC_IDX_IO_URING_REGISTER] = 427u ^ SC_XOR_KEY,
};
#else
#error "Unsupported architecture: only aarch64 and x86_64 are supported"
#endif

__attribute__((used))
volatile uint32_t g_sc_xor_key = SC_XOR_KEY;

static EVP_CIPHER_CTX* gcm_context_create(
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    EVP_CIPHER_CTX* storage
#else
    void* storage
#endif
) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    EVP_CIPHER_CTX_init(storage);
    return storage;
#else
    (void)storage;
    return EVP_CIPHER_CTX_new();
#endif
}

static void gcm_context_destroy(EVP_CIPHER_CTX* ctx) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif
}

int aes256_gcm_encrypt(uint8_t* data, size_t len, const uint8_t* key,
                       const uint8_t* iv, uint8_t* tag) {
    EVP_CIPHER_CTX* ctx;
    uint8_t final_block[EVP_MAX_BLOCK_LENGTH];
    int output_len = 0;
    int final_len = 0;
    int ok;
    if (!data || !key || !iv || !tag || len > INT_MAX) return 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    EVP_CIPHER_CTX storage;
    ctx = gcm_context_create(&storage);
#else
    ctx = gcm_context_create(NULL);
#endif

    if (!ctx) return 0;
    ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
         EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) == 1 &&
         EVP_EncryptUpdate(ctx, data, &output_len, data, (int)len) == 1 &&
         output_len == (int)len &&
         EVP_EncryptFinal_ex(ctx, final_block, &final_len) == 1 &&
         final_len == 0 &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    gcm_context_destroy(ctx);
    return ok;
}

int aes256_gcm_decrypt(uint8_t* data, size_t len, const uint8_t* key,
                       const uint8_t* iv, const uint8_t* tag) {
    EVP_CIPHER_CTX* ctx;
    uint8_t final_block[EVP_MAX_BLOCK_LENGTH];
    int output_len = 0;
    int final_len = 0;
    int ok;
    if (!data || !key || !iv || !tag || len > INT_MAX) return 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    EVP_CIPHER_CTX storage;
    ctx = gcm_context_create(&storage);
#else
    ctx = gcm_context_create(NULL);
#endif

    if (!ctx) return 0;
    ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
         EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) == 1 &&
         EVP_DecryptUpdate(ctx, data, &output_len, data, (int)len) == 1 &&
         output_len == (int)len &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                             (void*)(uintptr_t)tag) == 1 &&
         EVP_DecryptFinal_ex(ctx, final_block, &final_len) == 1 &&
         final_len == 0;
    gcm_context_destroy(ctx);
    return ok;
}
