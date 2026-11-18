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

void secure_memory_wipe(void* ptr, size_t size) {
    if (!ptr || size == 0) return;

    volatile uint8_t* mem = (volatile uint8_t*)ptr;

    static int rand_initialized = 0;
    if (!rand_initialized) {
        srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)ptr);
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
