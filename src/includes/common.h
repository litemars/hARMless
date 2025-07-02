#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <elf.h>

// Common definitions and constants
#define MAX_PATH_LEN 4096
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define MAGIC_SIGNATURE 0xDEADBEEF
#define PAGE_SIZE 0x1000

// AArch64 syscall numbers (correct values)
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
#define __NR_ftruncate 46

// memfd_create flags
#define MFD_CLOEXEC 0x0001U
#define MFD_ALLOW_SEALING 0x0002U

// Memory protection flags
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

// mmap flags
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED 0x10
#define MAP_SHARED 0x01

// ELF segment types
#define PT_NOTE 4
#define PT_LOAD 1

// ELF segment flags
#define PF_X 0x1       // Execute
#define PF_W 0x2       // Write
#define PF_R 0x4       // Read

// Packed binary metadata
typedef struct {
    uint32_t magic;
    uint32_t payload_size;
    uint64_t original_entry;
    uint32_t original_phnum;
    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[AES_IV_SIZE];
    uint8_t reserved[16];
} __attribute__((packed)) packed_header_t;

// ELF injection metadata
typedef struct {
    uint64_t injection_vaddr;
    uint64_t injection_offset;
    uint32_t injection_size;
    uint64_t original_entry;
    int injected_phdr_index;
} injection_info_t;

// Function pointer types for loader
typedef void (*original_entry_func_t)(void);

// Debug macros
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) do { \
    char msg[256]; \
    int len = snprintf(msg, sizeof(msg), "[DEBUG] " fmt "\n", ##__VA_ARGS__); \
    write(2, msg, len); \
} while(0)
#else
#define DEBUG_PRINT(fmt, ...) do {} while(0)
#endif

// Error handling macros
#define ERROR_PRINT(fmt, ...) do { \
    char msg[256]; \
    int len = snprintf(msg, sizeof(msg), "[ERROR] " fmt "\n", ##__VA_ARGS__); \
    write(2, msg, len); \
} while(0)

#define INFO_PRINT(fmt, ...) do { \
    char msg[256]; \
    int len = snprintf(msg, sizeof(msg), "[INFO] " fmt "\n", ##__VA_ARGS__); \
    write(1, msg, len); \
} while(0)

// Utility macros
#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))
#define IS_ALIGNED(x, align) (((x) & ((align) - 1)) == 0)

// Min/Max macros
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#endif // COMMON_H