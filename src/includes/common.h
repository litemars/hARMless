#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

// Common definitions
#define MAX_PATH_LEN 4096
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define MAGIC_SIGNATURE 0xDEADBEEF

// Syscall numbers for AArch64
#define __NR_read 63
#define __NR_write 64
#define __NR_open 56
#define __NR_close 57
#define __NR_mmap 222
#define __NR_munmap 215
#define __NR_mprotect 226
#define __NR_memfd_create 279
#define __NR_execve 221
#define __NR_exit 93

// memfd_create flags
#define MFD_CLOEXEC 0x0001U

// Memory protection flags
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

// mmap flags
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED 0x10

// Packed binary header
typedef struct {
    uint32_t magic;
    uint32_t payload_size;
    uint32_t original_entry;
    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[AES_IV_SIZE];
} __attribute__((packed)) packed_header_t;

// Debug macros
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) do { \
    char msg[256]; \
    snprintf(msg, sizeof(msg), "[DEBUG] " fmt "\n", ##__VA_ARGS__); \
    write(2, msg, strlen(msg)); \
} while(0)
#else
#define DEBUG_PRINT(fmt, ...) do {} while(0)
#endif

#endif // COMMON_H
