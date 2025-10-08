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

int is_elf64_arm64(const void* data) {
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)data;
    return is_elf64(data) && ehdr->e_machine == EM_AARCH64;
}

int validate_elf64_executable(const Elf64_Ehdr* ehdr, size_t file_size) {
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        return 0;
    }

    if (ehdr->e_phnum == 0) {
        return 0;
    }

    size_t phdr_end = ehdr->e_phoff + (size_t)ehdr->e_phnum * ehdr->e_phentsize;
    if (phdr_end > file_size || ehdr->e_phoff >= file_size) {
        return 0;
    }

    if (ehdr->e_entry == 0) {
        return 0;
    }

    return 1;
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