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
        return -1;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    
    *size = st.st_size;
    *buffer = malloc(*size);
    if (!*buffer) {
        close(fd);
        return -1;
    }
    
    if (read(fd, *buffer, *size) != (ssize_t)*size) {
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
        return -1;
    }
    
    if (write(fd, buffer, size) != (ssize_t)size) {
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

int validate_elf_header(const Elf64_Ehdr *ehdr) {
    // Check ELF magic
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        return -1;
    }
    
    // Check for 64-bit ELF
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        return -1;
    }
    
    // Check for little-endian
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        return -1;
    }
    
    // Check for AArch64 architecture
    if (ehdr->e_machine != EM_AARCH64) {
        return -1;
    }
    
    // Check for executable
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        return -1;
    }
    
    return 0;
}

Elf64_Phdr *find_load_segment(const Elf64_Ehdr *ehdr) {
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            return &phdr[i];
        }
    }
    
    return NULL;
}

int patch_entry_point(Elf64_Ehdr *ehdr, uint64_t new_entry) {
    ehdr->e_entry = new_entry;
    return 0;
}

int find_injection_point(const char *buffer, size_t size, size_t required_size) {
    // Look for a sequence of NULL bytes large enough for injection
    size_t null_count = 0;
    
    for (size_t i = 0; i < size; i++) {
        if (buffer[i] == 0) {
            null_count++;
            if (null_count >= required_size) {
                return i - null_count + 1;
            }
        } else {
            null_count = 0;
        }
    }
    
    return -1; // No suitable injection point found
}

int inject_loader(char *buffer, size_t buffer_size, int injection_offset, 
                  const char *loader_code, size_t loader_size) {
    if (injection_offset < 0 || 
        (size_t)injection_offset + loader_size > buffer_size) {
        return -1;
    }
    
    memcpy(buffer + injection_offset, loader_code, loader_size);
    return 0;
}
