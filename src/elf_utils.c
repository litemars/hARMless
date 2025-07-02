#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

#include "includes/elf_utils.h"
#include "includes/common.h"

int read_elf_file(const char *filename, char **buffer, size_t *size) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        ERROR_PRINT("Cannot open file: %s", filename);
        return -1;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        ERROR_PRINT("Cannot stat file: %s", filename);
        close(fd);
        return -1;
    }
    
    *size = st.st_size;
    *buffer = malloc(*size);
    if (!*buffer) {
        ERROR_PRINT("Memory allocation failed");
        close(fd);
        return -1;
    }
    
    if (read(fd, *buffer, *size) != (ssize_t)*size) {
        ERROR_PRINT("Failed to read file contents");
        free(*buffer);
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

int write_elf_file(const char *filename, const char *buffer, size_t size) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        ERROR_PRINT("Cannot create file: %s", filename);
        return -1;
    }
    
    if (write(fd, buffer, size) != (ssize_t)size) {
        ERROR_PRINT("Failed to write file contents");
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

int validate_elf_header(const Elf64_Ehdr *ehdr) {
    // Check ELF magic
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        ERROR_PRINT("Invalid ELF magic");
        return -1;
    }
    
    // Check for 64-bit ELF
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        ERROR_PRINT("Not a 64-bit ELF");
        return -1;
    }
    
    // Check for little-endian
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        ERROR_PRINT("Not little-endian");
        return -1;
    }
    
    // Check for AArch64 architecture
    if (ehdr->e_machine != EM_AARCH64) {
        ERROR_PRINT("Not AArch64 architecture");
        return -1;
    }
    
    // Check for executable or shared object
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        ERROR_PRINT("Not an executable or shared object");
        return -1;
    }
    
    return 0;
}

Elf64_Phdr *find_note_segment(const Elf64_Ehdr *ehdr) {
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_NOTE) {
            return &phdr[i];
        }
    }
    
    return NULL;
}

Elf64_Phdr *find_executable_segment(const Elf64_Ehdr *ehdr) {
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            return &phdr[i];
        }
    }
    
    return NULL;
}

int convert_note_to_load(Elf64_Ehdr *ehdr, Elf64_Phdr *note_phdr,
                         uint64_t injection_vaddr, uint32_t injection_size) {
    if (!note_phdr) {
        ERROR_PRINT("No PT_NOTE segment found");
        return -1;
    }
    
    DEBUG_PRINT("Converting PT_NOTE to PT_LOAD");
    DEBUG_PRINT("Original: vaddr=0x%lx, offset=0x%lx, size=0x%lx", 
                note_phdr->p_vaddr, note_phdr->p_offset, note_phdr->p_filesz);
    
    // Convert PT_NOTE to PT_LOAD
    note_phdr->p_type = PT_LOAD;
    note_phdr->p_flags = PF_R | PF_X; // Readable and executable
    note_phdr->p_vaddr = injection_vaddr;
    note_phdr->p_paddr = injection_vaddr;
    note_phdr->p_filesz = injection_size;
    note_phdr->p_memsz = injection_size;
    note_phdr->p_align = PAGE_SIZE;
    
    DEBUG_PRINT("Converted: vaddr=0x%lx, offset=0x%lx, size=0x%x", 
                note_phdr->p_vaddr, note_phdr->p_offset, injection_size);
    
    return 0;
}

int patch_entry_point(Elf64_Ehdr *ehdr, uint64_t new_entry, uint64_t *original_entry) {
    *original_entry = ehdr->e_entry;
    ehdr->e_entry = new_entry;
    
    DEBUG_PRINT("Entry point patched: 0x%lx -> 0x%lx", *original_entry, new_entry);
    return 0;
}

uint64_t find_injection_address(const Elf64_Ehdr *ehdr) {
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
    uint64_t max_vaddr = 0;
    
    // Find the highest virtual address used by LOAD segments
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            uint64_t end_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
            if (end_vaddr > max_vaddr) {
                max_vaddr = end_vaddr;
            }
        }
    }
    
    // Align to page boundary and add some space
    return ALIGN_UP(max_vaddr, PAGE_SIZE);
}

int check_injection_space(const Elf64_Ehdr *ehdr, size_t required_size) {
    // For PT_NOTE conversion, we need a PT_NOTE segment
    Elf64_Phdr *note_phdr = find_note_segment(ehdr);
    if (note_phdr) {
        DEBUG_PRINT("Found PT_NOTE segment for injection");
        return 0; // PT_NOTE conversion is always possible
    }
    
    // For padding injection, check available space
    Elf64_Phdr *exec_phdr = find_executable_segment(ehdr);
    if (!exec_phdr) {
        ERROR_PRINT("No executable segment found");
        return -1;
    }
    
    // Check if there's enough padding space
    uint64_t segment_end = exec_phdr->p_offset + exec_phdr->p_filesz;
    uint64_t next_segment_start = segment_end;
    
    // Find the next segment to determine available space
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_offset > segment_end && phdr[i].p_offset < next_segment_start) {
            next_segment_start = phdr[i].p_offset;
        }
    }
    
    size_t available_space = next_segment_start - segment_end;
    if (available_space < required_size) {
        ERROR_PRINT("Insufficient padding space: %zu < %zu", available_space, required_size);
        return -1;
    }
    
    return 0;
}

int inject_using_note_conversion(char *elf_buffer, size_t elf_size,
                                 const char *loader_code, size_t loader_size,
                                 const char *encrypted_payload, size_t payload_size,
                                 injection_info_t *injection_info) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_buffer;
    
    // Find PT_NOTE segment
    Elf64_Phdr *note_phdr = find_note_segment(ehdr);
    if (!note_phdr) {
        ERROR_PRINT("No PT_NOTE segment found for conversion");
        return -1;
    }
    
    // Calculate injection address and size
    uint64_t injection_vaddr = find_injection_address(ehdr);
    uint32_t total_injection_size = loader_size + payload_size;
    
    // Store injection info
    injection_info->injection_vaddr = injection_vaddr;
    injection_info->injection_offset = elf_size; // Append at end
    injection_info->injection_size = total_injection_size;
    injection_info->original_entry = ehdr->e_entry;
    
    // Convert PT_NOTE to PT_LOAD
    if (convert_note_to_load(ehdr, note_phdr, injection_vaddr, total_injection_size) != 0) {
        ERROR_PRINT("Failed to convert PT_NOTE to PT_LOAD");
        return -1;
    }
    
    // Update the converted segment's file offset to point to appended data
    note_phdr->p_offset = elf_size;
    
    // Append loader code at the end of file
    memcpy(elf_buffer + elf_size, loader_code, loader_size);
    
    // Append encrypted payload after loader
    memcpy(elf_buffer + elf_size + loader_size, encrypted_payload, payload_size);
    
    DEBUG_PRINT("Injection completed using PT_NOTE conversion");
    DEBUG_PRINT("Loader at file offset: 0x%lx, vaddr: 0x%lx", 
                (uint64_t)elf_size, injection_vaddr);
    
    return 0;
}

int inject_using_padding(char *elf_buffer, size_t elf_size,
                         const char *loader_code, size_t loader_size,
                         injection_info_t *injection_info) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_buffer;
    
    // Find executable segment for padding injection
    Elf64_Phdr *exec_phdr = find_executable_segment(ehdr);
    if (!exec_phdr) {
        ERROR_PRINT("No executable segment found");
        return -1;
    }
    
    // Find injection point in padding
    uint64_t injection_offset = exec_phdr->p_offset + exec_phdr->p_filesz;
    uint64_t injection_vaddr = exec_phdr->p_vaddr + exec_phdr->p_filesz;
    
    // Check alignment
    injection_offset = ALIGN_UP(injection_offset, 16);
    injection_vaddr = ALIGN_UP(injection_vaddr, 16);
    
    // Store injection info
    injection_info->injection_vaddr = injection_vaddr;
    injection_info->injection_offset = injection_offset;
    injection_info->injection_size = loader_size;
    injection_info->original_entry = ehdr->e_entry;
    
    // Inject loader code in padding
    memcpy(elf_buffer + injection_offset, loader_code, loader_size);
    
    // Extend the executable segment to include injected code
    uint32_t size_increase = injection_offset + loader_size - (exec_phdr->p_offset + exec_phdr->p_filesz);
    exec_phdr->p_filesz += size_increase;
    exec_phdr->p_memsz += size_increase;
    
    DEBUG_PRINT("Injection completed using padding");
    DEBUG_PRINT("Loader at file offset: 0x%lx, vaddr: 0x%lx", 
                injection_offset, injection_vaddr);
    
    return 0;
}

int is_already_packed(const Elf64_Ehdr *ehdr) {
    // Check for our magic signature in various places
    // This is a simple check - in practice, you might want more sophisticated detection
    
    // Check if entry point is suspicious (too high or in unusual location)
    if (ehdr->e_entry > 0x7f0000000000ULL) {
        return 1; // Suspicious entry point
    }
    
    // Check program header count - packed binaries often have modified counts
    if (ehdr->e_phnum > 20) {
        return 1; // Too many program headers
    }
    
    return 0;
}

void print_elf_info(const Elf64_Ehdr *ehdr) {
    printf("ELF Information:\n");
    printf("  Type: %s\n", (ehdr->e_type == ET_EXEC) ? "Executable" : "Shared Object");
    printf("  Machine: %s\n", (ehdr->e_machine == EM_AARCH64) ? "AArch64" : "Unknown");
    printf("  Entry Point: 0x%lx\n", ehdr->e_entry);
    printf("  Program Headers: %d\n", ehdr->e_phnum);
    printf("  Section Headers: %d\n", ehdr->e_shnum);
}

void print_segment_info(const Elf64_Ehdr *ehdr) {
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
    
    printf("Program Segments:\n");
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const char *type_name;
        switch (phdr[i].p_type) {
            case PT_LOAD: type_name = "LOAD"; break;
            case PT_NOTE: type_name = "NOTE"; break;
            case PT_DYNAMIC: type_name = "DYNAMIC"; break;
            case PT_INTERP: type_name = "INTERP"; break;
            default: type_name = "OTHER"; break;
        }
        
        printf("  [%d] %s: vaddr=0x%lx, offset=0x%lx, size=0x%lx, flags=%c%c%c\n",
               i, type_name, phdr[i].p_vaddr, phdr[i].p_offset, phdr[i].p_filesz,
               (phdr[i].p_flags & PF_R) ? 'R' : '-',
               (phdr[i].p_flags & PF_W) ? 'W' : '-',
               (phdr[i].p_flags & PF_X) ? 'X' : '-');
    }
}

int verify_elf_integrity(const Elf64_Ehdr *ehdr, size_t file_size) {
    // Basic integrity checks
    if (ehdr->e_phoff >= file_size) {
        ERROR_PRINT("Program header offset beyond file size");
        return -1;
    }
    
    if (ehdr->e_shoff >= file_size) {
        ERROR_PRINT("Section header offset beyond file size");
        return -1;
    }
    
    // Check program headers
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_offset + phdr[i].p_filesz > file_size) {
            ERROR_PRINT("Segment %d extends beyond file size", i);
            return -1;
        }
    }
    
    return 0;
}

int is_aarch64_elf(const Elf64_Ehdr *ehdr) {
    return (ehdr->e_machine == EM_AARCH64);
}

int is_executable_elf(const Elf64_Ehdr *ehdr) {
    return (ehdr->e_type == ET_EXEC || ehdr->e_type == ET_DYN);
}