#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <elf.h>
#include <stdint.h>
#include <stddef.h>
#include "common.h"

// ELF manipulation functions
int read_elf_file(const char *filename, char **buffer, size_t *size);
int write_elf_file(const char *filename, const char *buffer, size_t size);
int validate_elf_header(const Elf64_Ehdr *ehdr);

// ELF analysis functions
Elf64_Phdr *find_load_segment(const Elf64_Ehdr *ehdr);
Elf64_Phdr *find_note_segment(const Elf64_Ehdr *ehdr);
Elf64_Phdr *find_executable_segment(const Elf64_Ehdr *ehdr);
int count_load_segments(const Elf64_Ehdr *ehdr);

// ELF injection functions (PT_NOTE to PT_LOAD conversion)
int inject_loader_code(char *elf_buffer, size_t elf_size, 
                       const char *loader_code, size_t loader_size,
                       const char *encrypted_payload, size_t payload_size,
                       injection_info_t *injection_info);

int convert_note_to_load(Elf64_Ehdr *ehdr, Elf64_Phdr *note_phdr,
                         uint64_t injection_vaddr, uint32_t injection_size);

int patch_entry_point(Elf64_Ehdr *ehdr, uint64_t new_entry, uint64_t *original_entry);

// Segment manipulation
int extend_segment(Elf64_Phdr *phdr, uint32_t additional_size);
int adjust_subsequent_segments(Elf64_Ehdr *ehdr, int start_index, 
                               uint64_t offset_adjustment);

// ELF validation and analysis
int check_injection_space(const Elf64_Ehdr *ehdr, size_t required_size);
uint64_t find_injection_address(const Elf64_Ehdr *ehdr);
int is_already_packed(const Elf64_Ehdr *ehdr);

// Segment analysis utilities
int find_gap_after_segment(const Elf64_Ehdr *ehdr, int segment_index, 
                           uint64_t *gap_offset, size_t *gap_size);
int has_sufficient_padding(const Elf64_Ehdr *ehdr, size_t required_size);

// ELF header utilities
void print_elf_info(const Elf64_Ehdr *ehdr);
void print_segment_info(const Elf64_Ehdr *ehdr);
int verify_elf_integrity(const Elf64_Ehdr *ehdr, size_t file_size);

// Advanced injection techniques
int inject_using_padding(char *elf_buffer, size_t elf_size,
                         const char *loader_code, size_t loader_size,
                         injection_info_t *injection_info);

int inject_using_note_conversion(char *elf_buffer, size_t elf_size,
                                 const char *loader_code, size_t loader_size,
                                 const char *encrypted_payload, size_t payload_size,
                                 injection_info_t *injection_info);

// Section header manipulation
int adjust_section_headers(Elf64_Ehdr *ehdr, uint64_t offset_adjustment);

// Memory mapping helpers
void *map_elf_file(const char *filename, size_t *size);
int unmap_elf_file(void *mapped_file, size_t size);

// ELF architecture validation
int is_aarch64_elf(const Elf64_Ehdr *ehdr);
int is_executable_elf(const Elf64_Ehdr *ehdr);

#endif // ELF_UTILS_H