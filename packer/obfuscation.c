#include "common.h"
#include "elf64.h"
#include <unistd.h>

void strip_elf_metadata(uint8_t* data, size_t len) {
    if (!data || len < sizeof(Elf64_Ehdr)) return;
    if (!is_elf64(data)) return;

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)data;
    ehdr->e_shoff     = 0;
    ehdr->e_shnum     = 0;
    ehdr->e_shentsize = 0;
    ehdr->e_shstrndx  = 0;

    for (int i = 7; i < EI_NIDENT; i++) {
        ehdr->e_ident[i] = 0;
    }
}

void deobf_str_xor(char* dst, const uint8_t* src, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = (char)(src[i] ^ key);
    }
}

void noise_delay(unsigned max_ms) {
    if (max_ms == 0) return;

    static int seeded = 0;
    if (!seeded) {
        srand((unsigned)(time(NULL) ^ getpid()));
        seeded = 1;
    }

    unsigned ms = (unsigned)(rand() % (max_ms / 2 + 1)) + max_ms / 4;

    struct nl_timespec req;
    req.tv_sec  = (long)(ms / 1000);
    req.tv_nsec = (long)((ms % 1000) * 1000000L);

    syscall2(__NR_nanosleep, (long)&req, 0);
}

/*
 * Probe current process identity between sensitive operations.
 * Mixes getpid/getppid with a prctl(PR_GET_NAME) buffer read, uses
 * results in a condition, and varies the syscall type mix so the
 * sequence does not reduce to a pair of identical info-query calls.
 */
void check_exec_context(void) {
    volatile long pid  = syscall1(__NR_getpid,  0);
    volatile long ppid = syscall1(__NR_getppid, 0);
    char pname[16];
    (void)syscall3(__NR_prctl, PR_GET_NAME, (long)pname, 0);
    /* pid <= 0 only if something is very wrong; pname empty only if
     * hide_process_title was never called or prctl failed. */
    if (pid <= 0 || ppid <= 0 || pname[0] == '\0')
        noise_delay(15);
}

void secure_memory_wipe(void* ptr, size_t size) {
    if (!ptr || size == 0) return;

    volatile uint8_t* mem = (volatile uint8_t*)ptr;

    static int rand_initialized = 0;
    if (!rand_initialized) {
        srand(time(NULL) ^ getpid());
        rand_initialized = 1;
    }

    for (int pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i < size; i++) {
            switch (pass) {
                case 0: mem[i] = 0x00; break;
                case 1: mem[i] = 0xFF; break;
                case 2: mem[i] = (uint8_t)rand(); break;
            }
        }
    }

    __asm__ __volatile__("" : : "r"(mem) : "memory");
}

void prevent_core_dumps(void) {
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);
}
<<<<<<< HEAD
=======

<<<<<<< HEAD
>>>>>>> 28bcb1a (removing NOPS and adding dynamic XOR key)
=======
>>>>>>> 28bcb1a (removing NOPS and adding dynamic XOR key)
