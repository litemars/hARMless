#include "includes/common.h"

// Position-independent runtime loader for AArch64
// This loader decrypts and executes the original ELF binary
// It uses only syscalls and position-independent code

// System call wrapper for AArch64
static long syscall6(long num, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
    register long x8 asm("x8") = num;
    register long x0 asm("x0") = arg0;
    register long x1 asm("x1") = arg1;
    register long x2 asm("x2") = arg2;
    register long x3 asm("x3") = arg3;
    register long x4 asm("x4") = arg4;
    register long x5 asm("x5") = arg5;
    
    asm volatile("svc #0"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                 : "memory");
    
    return x0;
}

// Individual syscall wrappers
static long sys_write(int fd, const void *buf, size_t count) {
    return syscall6(__NR_write, fd, (long)buf, count, 0, 0, 0);
}

static long sys_exit(int status) {
    return syscall6(__NR_exit, status, 0, 0, 0, 0, 0);
}

static long sys_memfd_create(const char *name, unsigned int flags) {
    return syscall6(__NR_memfd_create, (long)name, flags, 0, 0, 0, 0);
}

static long sys_ftruncate(int fd, off_t length) {
    return syscall6(__NR_ftruncate, fd, length, 0, 0, 0, 0);
}

static long sys_write_fd(int fd, const void *buf, size_t count) {
    return syscall6(__NR_write, fd, (long)buf, count, 0, 0, 0);
}

static long sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
    return syscall6(__NR_execve, (long)pathname, (long)argv, (long)envp, 0, 0, 0);
}

static long sys_close(int fd) {
    return syscall6(__NR_close, fd, 0, 0, 0, 0, 0);
}

// Simple string functions (position-independent)
static size_t my_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static void *my_memcpy(void *dest, const void *src, size_t n) {
    char *d = dest;
    const char *s = src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}

void *memcpy(void *dest, const void *src, unsigned long n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    for (unsigned long i = 0; i < n; ++i)
        d[i] = s[i];
    return dest;
}

static void *my_memset(void *s, int c, size_t n) {
    char *p = s;
    for (size_t i = 0; i < n; i++) {
        p[i] = c;
    }
    return s;
}

static int my_memcmp(const void *s1, const void *s2, size_t n) {
    const char *p1 = s1;
    const char *p2 = s2;
    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

// Simple integer to string conversion
static int int_to_str(int num, char *str, int base) {
    int i = 0;
    int is_negative = 0;
    
    if (num == 0) {
        str[i++] = '0';
        str[i] = '\0';
        return 1;
    }
    
    if (num < 0 && base == 10) {
        is_negative = 1;
        num = -num;
    }
    
    while (num != 0) {
        int rem = num % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num = num / base;
    }
    
    if (is_negative) {
        str[i++] = '-';
    }
    
    str[i] = '\0';
    
    // Reverse the string
    int start = 0;
    int end = i - 1;
    while (start < end) {
        char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        start++;
        end--;
    }
    
    return i;
}

// AES decryption using AES-NI if available, otherwise simple XOR fallback
static int aes_decrypt_loader(const uint8_t *ciphertext, size_t ciphertext_len,
                              const uint8_t *key, const uint8_t *iv,
                              uint8_t *plaintext, size_t *plaintext_len) {
    // For the loader, we use simple XOR decryption to avoid dependencies
    // This matches the simple_encrypt function in crypto.c
    
    if (ciphertext_len == 0) {
        return -1;
    }
    
    // Use first 32 bytes of key for XOR
    for (size_t i = 0; i < ciphertext_len; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % AES_KEY_SIZE];
    }
    
    *plaintext_len = ciphertext_len;
    return 0;
}

// Get current position in code (position-independent way)
static void* get_current_position(void) {
    void *pc;
    asm volatile("adr %0, ." : "=r"(pc));
    return pc;
}

// Find the packed header by scanning backwards from current position
static packed_header_t* find_packed_header(void) {
    char *current_pos = (char*)get_current_position();
    
    // Search backwards for magic signature
    for (int offset = 0; offset < 0x10000; offset += 4) {
        uint32_t *potential_magic = (uint32_t*)(current_pos + offset);
        if (*potential_magic == MAGIC_SIGNATURE) {
            return (packed_header_t*)potential_magic;
        }
    }
    
    // Search forwards as well
    for (int offset = 0; offset < 0x10000; offset += 4) {
        uint32_t *potential_magic = (uint32_t*)(current_pos - offset);
        if (*potential_magic == MAGIC_SIGNATURE) {
            return (packed_header_t*)potential_magic;
        }
    }
    
    return NULL;
}

// Main loader function - decrypts and executes original binary
void loader_main(void) {
    // Find the packed header
    packed_header_t *header = find_packed_header();
    if (!header) {
        sys_exit(1); // Header not found
    }
    
    // Verify magic signature
    if (header->magic != MAGIC_SIGNATURE) {
        sys_exit(2); // Invalid magic
    }
    
    // Get encrypted payload (located right after header)
    uint8_t *encrypted_payload = (uint8_t *)(header + 1);
    
    // Create memory file descriptor for the decrypted binary
    char memfd_name[] = "packed_bin";
    int memfd = sys_memfd_create(memfd_name, MFD_CLOEXEC);
    if (memfd < 0) {
        sys_exit(3); // Failed to create memfd
    }
    
    // Set the size of the memory file
    if (sys_ftruncate(memfd, header->payload_size * 2) < 0) {
        sys_close(memfd);
        sys_exit(4); // Failed to set size
    }
    
    // Allocate buffer for decrypted payload
    // Note: In a real implementation, you might use mmap for large payloads
    static uint8_t decrypt_buffer[0x100000]; // 1MB max payload
    
    if (header->payload_size > sizeof(decrypt_buffer)) {
        sys_close(memfd);
        sys_exit(5); // Payload too large
    }
    
    // Decrypt the payload
    size_t decrypted_size;
    if (aes_decrypt_loader(encrypted_payload, header->payload_size,
                           header->key, header->iv,
                           decrypt_buffer, &decrypted_size) != 0) {
        sys_close(memfd);
        sys_exit(6); // Decryption failed
    }
    
    // Write decrypted payload to memory file
    if (sys_write_fd(memfd, decrypt_buffer, decrypted_size) != (long)decrypted_size) {
        sys_close(memfd);
        sys_exit(7); // Failed to write
    }
    
    // Prepare execution path
    char fd_path[64];
    char *path_ptr = fd_path;
    
    // Build path "/proc/self/fd/N"
    const char *proc_prefix = "/proc/self/fd/";
    for (const char *p = proc_prefix; *p; p++) {
        *path_ptr++ = *p;
    }
    
    // Convert memfd to string and append
    char fd_str[16];
    int fd_len = int_to_str(memfd, fd_str, 10);
    for (int i = 0; i < fd_len; i++) {
        *path_ptr++ = fd_str[i];
    }
    *path_ptr = '\0';
    
    // Prepare arguments for execve
    char *argv[] = { fd_path, NULL };
    char *envp[] = { NULL };
    
    // Execute the decrypted binary
    sys_execve(fd_path, argv, envp);
    
    // If execve returns, it failed
    sys_close(memfd);
    sys_exit(8); // Execution failed
}

// Secondary entry point for debugging
void loader_debug_info(void) {
    const char debug_msg[] = "AArch64 Loader: Starting decryption...\n";
    sys_write(2, debug_msg, sizeof(debug_msg) - 1);
    
    loader_main();
}