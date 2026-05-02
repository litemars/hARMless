#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#define PACKED_MAGIC 0x41524D36 // "ARM6"

typedef struct {
    uint32_t magic;              
    uint32_t original_size;
    uint32_t packed_size;
    uint32_t crc32;
    uint8_t primary_key[32];     // AES-256 key
    uint8_t secondary_key[32];   // ChaCha20 key
    uint8_t tertiary_key[32];    // RC4 key
    uint8_t nonce[16];           
    uint8_t salt[16];            
} pack_header_t;

// Linux-specific mmap flags (not exposed without _GNU_SOURCE)
#ifndef MAP_ANON
#define MAP_ANON     0x20   /* ARM64/x86: anonymous mapping           */
#endif
#ifndef MAP_POPULATE
#define MAP_POPULATE 0x8000 /* ARM64/x86: prefault pages at mmap time */
#endif

#define SC_XOR_KEY 0xDEADBEEFU

#define SC_IDX_READ              0
#define SC_IDX_WRITE             1
#define SC_IDX_OPEN              2
#define SC_IDX_CLOSE             3
#define SC_IDX_MMAP              4
#define SC_IDX_MUNMAP            5
#define SC_IDX_EXECVE            6
#define SC_IDX_MEMFD_CREATE      7
#define SC_IDX_FTRUNCATE         8
#define SC_IDX_LSEEK             9
#define SC_IDX_MPROTECT         10
#define SC_IDX_PTRACE           11
#define SC_IDX_GETPID           12
#define SC_IDX_GETPPID          13
#define SC_IDX_PRCTL            14
#define SC_IDX_MSYNC            15
#define SC_IDX_IO_URING_SETUP    16
#define SC_IDX_IO_URING_ENTER    17
#define SC_IDX_IO_URING_REGISTER 18
#define SC_IDX_NANOSLEEP         19
#define SC_TABLE_LEN             20

extern const volatile uint32_t hARMless_sc[SC_TABLE_LEN];

#define __NR_read              ((long)(hARMless_sc[SC_IDX_READ]              ^ SC_XOR_KEY))
#define __NR_write             ((long)(hARMless_sc[SC_IDX_WRITE]             ^ SC_XOR_KEY))
#define __NR_open              ((long)(hARMless_sc[SC_IDX_OPEN]              ^ SC_XOR_KEY))
#define __NR_close             ((long)(hARMless_sc[SC_IDX_CLOSE]             ^ SC_XOR_KEY))
#define __NR_mmap              ((long)(hARMless_sc[SC_IDX_MMAP]              ^ SC_XOR_KEY))
#define __NR_munmap            ((long)(hARMless_sc[SC_IDX_MUNMAP]            ^ SC_XOR_KEY))
#define __NR_execve            ((long)(hARMless_sc[SC_IDX_EXECVE]            ^ SC_XOR_KEY))
#define __NR_memfd_create      ((long)(hARMless_sc[SC_IDX_MEMFD_CREATE]      ^ SC_XOR_KEY))
#define __NR_ftruncate         ((long)(hARMless_sc[SC_IDX_FTRUNCATE]         ^ SC_XOR_KEY))
#define __NR_lseek             ((long)(hARMless_sc[SC_IDX_LSEEK]             ^ SC_XOR_KEY))
#define __NR_mprotect          ((long)(hARMless_sc[SC_IDX_MPROTECT]          ^ SC_XOR_KEY))
#define __NR_ptrace            ((long)(hARMless_sc[SC_IDX_PTRACE]            ^ SC_XOR_KEY))
#define __NR_getpid            ((long)(hARMless_sc[SC_IDX_GETPID]            ^ SC_XOR_KEY))
#define __NR_getppid           ((long)(hARMless_sc[SC_IDX_GETPPID]           ^ SC_XOR_KEY))
#define __NR_prctl             ((long)(hARMless_sc[SC_IDX_PRCTL]             ^ SC_XOR_KEY))
#define __NR_msync             ((long)(hARMless_sc[SC_IDX_MSYNC]             ^ SC_XOR_KEY))
#define __NR_io_uring_setup    ((long)(hARMless_sc[SC_IDX_IO_URING_SETUP]    ^ SC_XOR_KEY))
#define __NR_io_uring_enter    ((long)(hARMless_sc[SC_IDX_IO_URING_ENTER]    ^ SC_XOR_KEY))
#define __NR_io_uring_register ((long)(hARMless_sc[SC_IDX_IO_URING_REGISTER] ^ SC_XOR_KEY))
#define __NR_nanosleep         ((long)(hARMless_sc[SC_IDX_NANOSLEEP]         ^ SC_XOR_KEY))

#ifdef COPY_WITH_IO_URING

/* mmap offsets for the three ring regions returned by io_uring_setup(2)  */
#define IORING_OFF_SQ_RING   0ULL
#define IORING_OFF_CQ_RING   0x8000000ULL
#define IORING_OFF_SQES      0x10000000ULL

/* io_uring_enter(2) flags                                                 */
#define IORING_ENTER_GETEVENTS (1U << 0)

/* io_uring_params.features flags                                          */
#define IORING_FEAT_SINGLE_MMAP (1U << 0)

/* Opcode: write to a file descriptor (flat buffer, no iovec)             */
#define IORING_OP_WRITE  23

/* Submission Queue Entry – only fields used by IORING_OP_WRITE           */
struct uring_sqe {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t ioprio;
    int32_t  fd;
    uint64_t off;
    uint64_t addr;
    uint32_t len;
    uint32_t rw_flags;
    uint64_t user_data;
    uint16_t buf_index;
    uint16_t personality;
    int32_t  splice_fd_in;
    uint64_t __pad2[2];
};

/* Completion Queue Entry                                                  */
struct uring_cqe {
    uint64_t user_data;
    int32_t  res;
    uint32_t flags;
};

/* Offsets into the SQ ring control slab                                  */
struct io_sqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t flags;
    uint32_t dropped;
    uint32_t array;
    uint32_t resv1;
    uint64_t resv2;
};

/* Offsets into the CQ ring control slab                                  */
struct io_cqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t overflow;
    uint32_t cqes;
    uint32_t flags;
    uint32_t resv1;
    uint64_t resv2;
};

/* Parameters structure for io_uring_setup(2)                             */
struct uring_params {
    uint32_t sq_entries;
    uint32_t cq_entries;
    uint32_t flags;
    uint32_t sq_thread_cpu;
    uint32_t sq_thread_idle;
    uint32_t features;
    uint32_t wq_fd;
    uint32_t resv[3];
    struct io_sqring_offsets sq_off;
    struct io_cqring_offsets cq_off;
};

/*
 * ARM64 memory barriers for ring head/tail updates.
 * dmb ishld: data-memory barrier, inner-shareable, load-before-load/store.
 * dmb ishst: data-memory barrier, inner-shareable, store-before-store.
 */
#define io_read_barrier()  __asm__ __volatile__("dmb ishld" ::: "memory")
#define io_write_barrier() __asm__ __volatile__("dmb ishst" ::: "memory")

#endif /* COPY_WITH_IO_URING */


static inline long syscall1(long number, long arg1) {
    long ret;
    __asm__ volatile (
        "mov x8, %1\n"
        "mov x0, %2\n"
        "svc 0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(number), "r"(arg1)
        : "x0", "x8", "memory"
    );
    return ret;
}

static inline long syscall2(long number, long arg1, long arg2) {
    long ret;
    __asm__ volatile (
        "mov x8, %1\n"
        "mov x0, %2\n"
        "mov x1, %3\n"
        "svc 0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(number), "r"(arg1), "r"(arg2)
        : "x0", "x1", "x8", "memory"
    );
    return ret;
}

static inline long syscall3(long number, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ volatile (
        "mov x8, %1\n"
        "mov x0, %2\n"
        "mov x1, %3\n"
        "mov x2, %4\n"
        "svc 0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(number), "r"(arg1), "r"(arg2), "r"(arg3)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}

static inline long syscall6(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    long ret;
    __asm__ volatile (
        "mov x8, %1\n"
        "mov x0, %2\n"
        "mov x1, %3\n"
        "mov x2, %4\n"
        "mov x3, %5\n"
        "mov x4, %6\n"
        "mov x5, %7\n"
        "svc 0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(arg6)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "memory"
    );
    return ret;
}

// Add -DDEBUG on the TARGET_CFLAGS in the Makefile to show the debug
#ifdef DEBUG
static inline void debug_print(const char *msg) {
    size_t len = 0;
    while (msg[len]) len++;
    syscall3(__NR_write, 2, (long)msg, (long)len);
}
#define DBG(msg) debug_print("[hARMless] " msg)
#else
#define DBG(msg) ((void)0)
#endif

// Function prototypes
uint32_t crc32(const uint8_t* data, size_t len);
void generate_random_key(uint8_t* key, size_t key_size);
int comprehensive_anti_debug_check();
void multi_layer_encrypt(uint8_t* data, size_t len, const pack_header_t* header);
void multi_layer_decrypt(uint8_t* data, size_t len, const pack_header_t* header);
int execute_from_memory(const uint8_t* elf_data, size_t elf_size, char* const argv[], char* const envp[]);
pack_header_t* find_packed_header(const uint8_t* data, size_t data_size);

// Pre-encryption ELF transforms
void strip_elf_metadata(uint8_t* data, size_t len);
void deobf_str_xor(char* dst, const uint8_t* src, size_t len, uint8_t key);

extern volatile uint32_t g_packed_magic;
extern volatile uint8_t  g_pack_polymorph[256];

void noise_delay(unsigned max_ms);
void decoy_syscalls(void);

// Enhanced anti-forensics functions
void secure_memory_wipe(void* ptr, size_t size);
void prevent_core_dumps(void);
void hide_process_title(int argc, char* argv[]);

// Process masquerading functions
int create_masqueraded_memfd(void);
const char* get_random_innocent_name(void);

#endif // COMMON_H