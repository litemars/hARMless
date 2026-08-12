#include "elf64.h"
#include <stdio.h>
#include <string.h>

int is_elf64(const void* data) {
    const unsigned char* ident = (const unsigned char*)data;
    return ident[0] == 0x7f &&
           ident[1] == 'E' &&
           ident[2] == 'L' &&
           ident[3] == 'F' &&
           ident[4] == ELFCLASS64;
}

int is_elf32(const void* data) {
    const unsigned char* ident = (const unsigned char*)data;
    return ident[0] == 0x7f &&
           ident[1] == 'E' &&
           ident[2] == 'L' &&
           ident[3] == 'F' &&
           ident[4] == ELFCLASS32;
}

int is_elf32_arm(const void* data) {
    const Elf32_Ehdr* ehdr = (const Elf32_Ehdr*)data;
    return is_elf32(data) && ehdr->e_machine == EM_ARM;
}

int is_elf64_arm64(const void* data) {
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)data;
    return is_elf64(data) && ehdr->e_machine == EM_AARCH64;
}

int is_elf64_x86_64(const void* data) {
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)data;
    return is_elf64(data) && ehdr->e_machine == EM_X86_64;
}

int is_target_elf(const void* data) {
#if defined(TARGET_ARM32)
    return is_elf32_arm(data);
#elif defined(TARGET_X86_64)
    return is_elf64_x86_64(data);
#else
    return is_elf64_arm64(data);
#endif
}

const char* target_elf_name(void) {
#if defined(TARGET_ARM32)
    return "ARM32/EABI5";
#elif defined(TARGET_X86_64)
    return "x86-64";
#else
    return "ARM64";
#endif
}

void print_elf64_header(const Elf64_Ehdr* ehdr) {
    printf("ELF Header:\n");
    printf("  Entry point: 0x%lx\n", (unsigned long)ehdr->e_entry);
    printf("  Program header offset: 0x%lx\n", (unsigned long)ehdr->e_phoff);
    printf("  Section header offset: 0x%lx\n", (unsigned long)ehdr->e_shoff);
    printf("  Machine: %u\n", ehdr->e_machine);
    printf("  Type: %u\n", ehdr->e_type);
    printf("  Number of program headers: %u\n", ehdr->e_phnum);
    printf("  Number of section headers: %u\n", ehdr->e_shnum);
}
