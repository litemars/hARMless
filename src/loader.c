#include "includes/common.h"

// Minimal runtime loader implementation for AArch64
// This gets compiled as a standalone binary and injected into packed executables

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

// Simplified system calls
static long sys_write(int fd, const void *buf, size_t count) {
    return syscall6(__NR_write, fd, (long)buf, count, 0, 0, 0);
}

static long sys_exit(int status) {
    return syscall6(__NR_exit, status, 0, 0, 0, 0, 0);
}

static long sys_memfd_create(const char *name, unsigned int flags) {
    return syscall6(__NR_memfd_create, (long)name, flags, 0, 0, 0, 0);
}

static long sys_write_fd(int fd, const void *buf, size_t count) {
    return syscall6(__NR_write, fd, (long)buf, count, 0, 0, 0);
}

static long sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
    return syscall6(__NR_execve, (long)pathname, (long)argv, (long)envp, 0, 0, 0);
}

// Simple string functions
static size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static void *memcpy(void *dest, const void *src, size_t n) {
    char *d = dest;
    const char *s = src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}

// Simple AES decryption (placeholder - in real implementation, use a small AES library)
static int simple_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                         const uint8_t *key, const uint8_t *iv,
                         uint8_t *plaintext, size_t *plaintext_len) {
    // For demonstration: XOR decryption (NOT SECURE - replace with real AES)
    uint8_t xor_key = key[0];
    for (size_t i = 0; i < ciphertext_len; i++) {
        plaintext[i] = ciphertext[i] ^ xor_key;
    }
    *plaintext_len = ciphertext_len;
    return 0;
}

// Main loader function
void loader_main(void) {
    // Find the packed header (located right after loader code)
    extern char _end[];
    packed_header_t *header = (packed_header_t *)_end;
    
    // Verify magic signature
    if (header->magic != MAGIC_SIGNATURE) {
        sys_exit(1);
    }
    
    // Get encrypted payload
    uint8_t *encrypted_payload = (uint8_t *)(header + 1);
    
    // Create memory file descriptor
    int memfd = sys_memfd_create("packed", MFD_CLOEXEC);
    if (memfd < 0) {
        sys_exit(2);
    }
    
    // Decrypt payload
    uint8_t *decrypted_payload = (uint8_t *)0x10000000; // Fixed address for simplicity
    size_t decrypted_size;
    
    if (simple_decrypt(encrypted_payload, header->payload_size,
                      header->key, header->iv,
                      decrypted_payload, &decrypted_size) != 0) {
        sys_exit(3);
    }
    
    // Write decrypted payload to memfd
    if (sys_write_fd(memfd, decrypted_payload, decrypted_size) != (long)decrypted_size) {
        sys_exit(4);
    }
    
    // Prepare for execution
    char fd_path[32];
    char *fd_ptr = fd_path;
    const char *prefix = "/proc/self/fd/";
    
    // Copy prefix
    for (int i = 0; prefix[i]; i++) {
        *fd_ptr++ = prefix[i];
    }
    
    // Convert memfd to string
    int temp_fd = memfd;
    char digits[16];
    int digit_count = 0;
    
    if (temp_fd == 0) {
        digits[digit_count++] = '0';
    } else {
        while (temp_fd > 0) {
            digits[digit_count++] = '0' + (temp_fd % 10);
            temp_fd /= 10;
        }
    }
    
    // Reverse digits
    for (int i = digit_count - 1; i >= 0; i--) {
        *fd_ptr++ = digits[i];
    }
    *fd_ptr = '\0';
    
    // Execute the decrypted binary
    char *argv[] = { fd_path, NULL };
    char *envp[] = { NULL };
    
    sys_execve(fd_path, argv, envp);
    
    // If we reach here, exec failed
    sys_exit(5);
}
