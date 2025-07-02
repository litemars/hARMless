#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <elf.h>
#include <stdint.h>
#include <stddef.h>

// ELF manipulation functions
int read_elf_file(const char *filename, char **buffer, size_t *size);
int write_elf_file(const char *filename, const char *buffer, size_t size);
int validate_elf_header(const Elf64_Ehdr *ehdr);
Elf64_Phdr *find_load_segment(const Elf64_Ehdr *ehdr);
int patch_entry_point(Elf64_Ehdr *ehdr, uint64_t new_entry);
int find_injection_point(const char *buffer, size_t size, size_t required_size);
int inject_loader(char *buffer, size_t buffer_size, int injection_offset, 
                  const char *loader_code, size_t loader_size);

#endif // ELF_UTILS_H
