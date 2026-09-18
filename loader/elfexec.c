#include "common.h"
#include "elf64.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Old-kernel fallback: map a conventional ELF image and its native
 * interpreter, repair the core auxiliary-vector entries, and transfer control
 * on the process's original stack.
 */

#define EI_DATA       5
#define EI_VERSION    6
#define EV_CURRENT    1

#define AT_NULL       0
#define AT_PHDR       3
#define AT_PHENT      4
#define AT_PHNUM      5
#define AT_BASE       7
#define AT_ENTRY      9

typedef struct {
    uintptr_t type;
    uintptr_t value;
} harmless_auxv_t;

typedef struct {
    void *mapping;
    size_t mapping_size;
    uintptr_t load_bias;
    uintptr_t entry;
    uintptr_t phdr;
    Elf64_Half elf_type;
    Elf64_Half phent;
    Elf64_Half phnum;
} mapped_elf_t;

static uintptr_t page_down(uintptr_t value, size_t page_size) {
    return value & ~((uintptr_t)page_size - 1U);
}

static int page_up(uintptr_t value, size_t page_size, uintptr_t *result) {
    uintptr_t mask = (uintptr_t)page_size - 1U;
    if (value > UINTPTR_MAX - mask)
        return -1;
    *result = (value + mask) & ~mask;
    return 0;
}

static int range_in_file(uint64_t offset, uint64_t length, size_t file_size) {
    return offset <= (uint64_t)file_size &&
           length <= (uint64_t)file_size - offset;
}

static int expected_machine(void) {
#if defined(__x86_64__)
    return EM_X86_64;
#elif defined(__aarch64__)
    return EM_AARCH64;
#endif
}

static int validate_elf(const uint8_t *data, size_t size,
                        const Elf64_Ehdr **ehdr_out,
                        const Elf64_Phdr **phdr_out) {
    const Elf64_Ehdr *ehdr;
    uint64_t phdr_size;
    unsigned i;
    int found_stack = 0;

    if (!data || size < sizeof(Elf64_Ehdr))
        return -1;

    ehdr = (const Elf64_Ehdr *)data;
    if (!is_elf64(data) ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
        ehdr->e_version != EV_CURRENT ||
        ehdr->e_machine != expected_machine() ||
        (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) ||
        ehdr->e_ehsize != sizeof(Elf64_Ehdr) ||
        ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
        ehdr->e_phnum == 0)
        return -1;

    phdr_size = (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr);
    if (!range_in_file(ehdr->e_phoff, phdr_size, size))
        return -1;

    *ehdr_out = ehdr;
    *phdr_out = (const Elf64_Phdr *)(data + ehdr->e_phoff);
    for (i = 0; i < ehdr->e_phnum; ++i) {
        if ((*phdr_out)[i].p_type == PT_GNU_STACK) {
            if (found_stack || ((*phdr_out)[i].p_flags & PF_X))
                return -1;
            found_stack = 1;
        }
    }
    return found_stack ? 0 : -1;
}

static int segment_protection(uint32_t flags) {
    int protection = 0;
    if (flags & PF_R)
        protection |= PROT_READ;
    if (flags & PF_W)
        protection |= PROT_WRITE;
    if (flags & PF_X)
        protection |= PROT_EXEC;
    return protection;
}

static int map_elf(const uint8_t *data, size_t size, mapped_elf_t *image) {
    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdr;
    uintptr_t min_address = UINTPTR_MAX;
    uintptr_t max_address = 0;
    uintptr_t mapping_start;
    uintptr_t mapping_end;
    uintptr_t load_bias;
    uintptr_t maximum_alignment;
    unsigned char *page_protections = NULL;
    size_t page_size;
    size_t mapping_size;
    size_t reservation_size;
    size_t page_count;
    size_t protection_page;
    void *mapping = MAP_FAILED;
    unsigned i;
    int found_load = 0;

    memset(image, 0, sizeof(*image));
    if (validate_elf(data, size, &ehdr, &phdr) < 0)
        return -1;

    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0 || (page_size & (page_size - 1U)) != 0)
        return -1;
    maximum_alignment = page_size;

    for (i = 0; i < ehdr->e_phnum; ++i) {
        uintptr_t segment_end;
        uintptr_t aligned_end;

        if (phdr[i].p_type != PT_LOAD)
            continue;
        if (phdr[i].p_filesz > phdr[i].p_memsz ||
            !range_in_file(phdr[i].p_offset, phdr[i].p_filesz, size) ||
            phdr[i].p_vaddr > UINTPTR_MAX - phdr[i].p_memsz)
            return -1;
        if (phdr[i].p_memsz == 0)
            continue;
        if (((uintptr_t)phdr[i].p_vaddr & (page_size - 1U)) !=
            ((uintptr_t)phdr[i].p_offset & (page_size - 1U)))
            return -1;
        if (phdr[i].p_align > 1) {
            uintptr_t alignment = (uintptr_t)phdr[i].p_align;
            if ((uint64_t)alignment != phdr[i].p_align ||
                (alignment & (alignment - 1U)) != 0 ||
                ((uintptr_t)phdr[i].p_vaddr & (alignment - 1U)) !=
                    ((uintptr_t)phdr[i].p_offset & (alignment - 1U)))
                return -1;
            if (alignment > maximum_alignment)
                maximum_alignment = alignment;
        }

        segment_end = (uintptr_t)(phdr[i].p_vaddr + phdr[i].p_memsz);
        if (page_up(segment_end, page_size, &aligned_end) < 0)
            return -1;
        if (page_down((uintptr_t)phdr[i].p_vaddr, page_size) < min_address)
            min_address = page_down((uintptr_t)phdr[i].p_vaddr, page_size);
        if (aligned_end > max_address)
            max_address = aligned_end;
        found_load = 1;
    }

    if (!found_load || max_address <= min_address ||
        max_address - min_address > SIZE_MAX)
        return -1;

    mapping_size = (size_t)(max_address - min_address);
    reservation_size = mapping_size;
    if (ehdr->e_type == ET_DYN) {
        uintptr_t reservation_start;
        uintptr_t reservation_end;
        uintptr_t aligned_start;
        uintptr_t alignment_delta;
        size_t prefix_size;
        size_t suffix_size;

        if (maximum_alignment > SIZE_MAX - mapping_size)
            return -1;
        reservation_size = mapping_size + (size_t)maximum_alignment;
        mapping = mmap(NULL, reservation_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON, -1, 0);
        if (mapping == MAP_FAILED)
            return -1;

        reservation_start = (uintptr_t)mapping;
        if (reservation_start > UINTPTR_MAX - reservation_size) {
            munmap(mapping, reservation_size);
            return -1;
        }
        reservation_end = reservation_start + reservation_size;
        alignment_delta = (min_address - reservation_start) &
                          (maximum_alignment - 1U);
        if (reservation_start > UINTPTR_MAX - alignment_delta) {
            munmap(mapping, reservation_size);
            return -1;
        }
        aligned_start = reservation_start + alignment_delta;
        if (aligned_start < min_address ||
            aligned_start > reservation_end - mapping_size) {
            munmap(mapping, reservation_size);
            return -1;
        }

        prefix_size = (size_t)(aligned_start - reservation_start);
        suffix_size = (size_t)(reservation_end -
                               (aligned_start + mapping_size));
        if ((prefix_size && munmap(mapping, prefix_size) < 0) ||
            (suffix_size &&
             munmap((void *)(aligned_start + mapping_size), suffix_size) < 0)) {
            munmap((void *)aligned_start, mapping_size + suffix_size);
            return -1;
        }
        mapping = (void *)aligned_start;
    } else {
        mapping = mmap((void *)min_address, mapping_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON, -1, 0);
    }
    if (mapping == MAP_FAILED)
        return -1;

    mapping_start = (uintptr_t)mapping;
    if (ehdr->e_type == ET_EXEC && mapping_start != min_address) {
        munmap(mapping, mapping_size);
        return -1;
    }
    load_bias = mapping_start - min_address;
    if (mapping_start > UINTPTR_MAX - mapping_size) {
        munmap(mapping, mapping_size);
        return -1;
    }
    mapping_end = mapping_start + mapping_size;

    page_count = mapping_size / page_size;
    page_protections = (unsigned char *)calloc(page_count, 1);
    if (!page_protections) {
        munmap(mapping, mapping_size);
        return -1;
    }

    for (i = 0; i < ehdr->e_phnum; ++i) {
        uintptr_t destination;
        uintptr_t first_page;
        uintptr_t last_page;
        size_t first_index;
        size_t last_index;
        size_t page;

        if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
            continue;

        if ((uintptr_t)phdr[i].p_vaddr > UINTPTR_MAX - load_bias) {
            free(page_protections);
            munmap(mapping, mapping_size);
            return -1;
        }
        destination = load_bias + (uintptr_t)phdr[i].p_vaddr;
        if (destination < mapping_start ||
            destination > mapping_end - (size_t)phdr[i].p_memsz) {
            free(page_protections);
            munmap(mapping, mapping_size);
            return -1;
        }

        memcpy((void *)destination, data + phdr[i].p_offset,
               (size_t)phdr[i].p_filesz);
        memset((void *)(destination + (uintptr_t)phdr[i].p_filesz), 0,
               (size_t)(phdr[i].p_memsz - phdr[i].p_filesz));

        first_page = page_down(destination, page_size);
        if (page_up(destination + (uintptr_t)phdr[i].p_memsz,
                    page_size, &last_page) < 0) {
            free(page_protections);
            munmap(mapping, mapping_size);
            return -1;
        }
        first_index = (size_t)((first_page - mapping_start) / page_size);
        last_index = (size_t)((last_page - mapping_start) / page_size);
        if (last_index > page_count) {
            free(page_protections);
            munmap(mapping, mapping_size);
            return -1;
        }
        /* Linux maps PT_LOAD entries in program-header order.  A later
         * segment therefore owns the permissions on a shared boundary page. */
        for (page = first_index; page < last_index; ++page)
            page_protections[page] =
                (unsigned char)segment_protection(phdr[i].p_flags);
    }

    for (protection_page = 0; protection_page < page_count;) {
        size_t first = protection_page;
        int protection = page_protections[protection_page];
        while (++protection_page < page_count &&
               page_protections[protection_page] == protection)
            ;
        if (mprotect((void *)(mapping_start + first * page_size),
                     (protection_page - first) * page_size, protection) < 0) {
            free(page_protections);
            munmap(mapping, mapping_size);
            return -1;
        }
    }
    image->mapping = mapping;
    image->mapping_size = mapping_size;
    image->elf_type = ehdr->e_type;
    image->load_bias = load_bias;
    image->entry = load_bias + (uintptr_t)ehdr->e_entry;
    image->phent = ehdr->e_phentsize;
    image->phnum = ehdr->e_phnum;

    for (i = 0; i < ehdr->e_phnum; ++i) {
        uint64_t phdr_bytes = (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr);
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_R) &&
            ehdr->e_phoff >= phdr[i].p_offset &&
            (uint64_t)ehdr->e_phoff - phdr[i].p_offset <=
                phdr[i].p_filesz &&
            phdr_bytes <=
                phdr[i].p_filesz - ((uint64_t)ehdr->e_phoff - phdr[i].p_offset)) {
            image->phdr = load_bias + (uintptr_t)phdr[i].p_vaddr +
                          (uintptr_t)((uint64_t)ehdr->e_phoff - phdr[i].p_offset);
            break;
        }
    }

    found_load = 0;
    for (i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X) &&
            ehdr->e_entry >= phdr[i].p_vaddr &&
            ehdr->e_entry - phdr[i].p_vaddr < phdr[i].p_memsz) {
            found_load = 1;
            break;
        }
    }

    if (!image->phdr || !found_load || image->entry < mapping_start ||
        image->entry >= mapping_end || image->phdr < mapping_start ||
        image->phdr > mapping_end -
            (size_t)((uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr))) {
        free(page_protections);
        munmap(mapping, mapping_size);
        memset(image, 0, sizeof(*image));
        return -1;
    }

    if (!(page_protections[(page_down(image->entry, page_size) -
                            mapping_start) / page_size] & PROT_EXEC)) {
        free(page_protections);
        munmap(mapping, mapping_size);
        memset(image, 0, sizeof(*image));
        return -1;
    }
    {
        uintptr_t phdr_end = image->phdr +
            (uintptr_t)((uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr));
        uintptr_t page = page_down(image->phdr, page_size);
        uintptr_t final_page;

        if (page_up(phdr_end, page_size, &final_page) < 0) {
            free(page_protections);
            munmap(mapping, mapping_size);
            memset(image, 0, sizeof(*image));
            return -1;
        }
        for (; page < final_page; page += page_size) {
            if (!(page_protections[(page - mapping_start) / page_size] &
                  PROT_READ)) {
                free(page_protections);
                munmap(mapping, mapping_size);
                memset(image, 0, sizeof(*image));
                return -1;
            }
        }
    }
    free(page_protections);
    return 0;
}

static const char *find_interpreter(const uint8_t *data, size_t size) {
    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdr;
    const char *interpreter = "";
    unsigned i;

    if (validate_elf(data, size, &ehdr, &phdr) < 0)
        return NULL;

    for (i = 0; i < ehdr->e_phnum; ++i) {
        const char *path;
        if (phdr[i].p_type != PT_INTERP)
            continue;
        if (*interpreter)
            return NULL;
        if (phdr[i].p_filesz < 2 ||
            !range_in_file(phdr[i].p_offset, phdr[i].p_filesz, size))
            return NULL;
        path = (const char *)(data + phdr[i].p_offset);
        if (path[0] != '/' || path[phdr[i].p_filesz - 1] != '\0' ||
            memchr(path, '\0', (size_t)phdr[i].p_filesz - 1))
            return NULL;
        interpreter = path;
    }
    return interpreter;
}

static int map_interpreter(const char *path, mapped_elf_t *interpreter) {
    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdr;
    struct stat file_stat;
    void *file_mapping;
    int fd;
    int result;

    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    if (fstat(fd, &file_stat) < 0 || !S_ISREG(file_stat.st_mode) ||
        file_stat.st_size <= 0 ||
        (uint64_t)file_stat.st_size > SIZE_MAX) {
        close(fd);
        return -1;
    }

    file_mapping = mmap(NULL, (size_t)file_stat.st_size, PROT_READ,
                        MAP_PRIVATE, fd, 0);
    close(fd);
    if (file_mapping == MAP_FAILED)
        return -1;

    if (validate_elf((const uint8_t *)file_mapping,
                     (size_t)file_stat.st_size, &ehdr, &phdr) < 0 ||
        ehdr->e_type != ET_DYN) {
        munmap(file_mapping, (size_t)file_stat.st_size);
        return -1;
    }
    {
        unsigned i;
        for (i = 0; i < ehdr->e_phnum; ++i) {
            if (phdr[i].p_type == PT_INTERP) {
                munmap(file_mapping, (size_t)file_stat.st_size);
                return -1;
            }
        }
    }

    result = map_elf((const uint8_t *)file_mapping,
                     (size_t)file_stat.st_size, interpreter);
    munmap(file_mapping, (size_t)file_stat.st_size);
    return result;
}

static int update_auxv(char *const envp[], const mapped_elf_t *program,
                       const mapped_elf_t *interpreter) {
    harmless_auxv_t *auxv;
    harmless_auxv_t *required[5] = { NULL, NULL, NULL, NULL, NULL };
    char *const *environment = envp;
    unsigned found = 0;

    if (!environment)
        return -1;
    while (*environment)
        ++environment;
    auxv = (harmless_auxv_t *)(environment + 1);

    for (; auxv->type != AT_NULL; ++auxv) {
        switch (auxv->type) {
        case AT_PHDR:
            required[0] = auxv;
            break;
        case AT_PHENT:
            required[1] = auxv;
            break;
        case AT_PHNUM:
            required[2] = auxv;
            break;
        case AT_BASE:
            required[3] = auxv;
            break;
        case AT_ENTRY:
            required[4] = auxv;
            break;
        default:
            break;
        }
    }

    for (found = 0; found < 5; ++found) {
        if (!required[found])
            return -1;
    }

    required[0]->value = program->phdr;
    required[1]->value = program->phent;
    required[2]->value = program->phnum;
    required[3]->value = interpreter ? interpreter->load_bias : 0;
    required[4]->value = program->entry;
    return 0;
}

__attribute__((noreturn))
static void enter_elf(uintptr_t entry, void *initial_stack) {
#if defined(__x86_64__)
    __asm__ volatile (
        "mov %0, %%r8\n"
        "mov %1, %%r9\n"
        "mov $158, %%eax\n"       /* arch_prctl */
        "mov $0x1001, %%edi\n"    /* ARCH_SET_GS */
        "xor %%esi, %%esi\n"
        "syscall\n"
        "mov $158, %%eax\n"       /* arch_prctl */
        "mov $0x1002, %%edi\n"    /* ARCH_SET_FS */
        "xor %%esi, %%esi\n"
        "syscall\n"
        "mov %%r9, %%rsp\n"
        "xor %%ebp, %%ebp\n"
        "xor %%edx, %%edx\n"
        "cld\n"
        "jmp *%%r8\n"
        :
        : "r"(entry), "r"(initial_stack)
        : "rax", "rdi", "rsi", "rdx", "r8", "r9", "rcx", "r11", "memory"
    );
#elif defined(__aarch64__)
    __asm__ volatile (
        "mov x9, %0\n"
        "mov x10, %1\n"
        "msr tpidr_el0, xzr\n"
        "mov sp, x10\n"
        "mov x29, xzr\n"
        "mov x30, xzr\n"
        "mov x0, xzr\n"
        "br x9\n"
        :
        : "r"(entry), "r"(initial_stack)
        : "x0", "x9", "x10", "x29", "x30", "memory"
    );
#endif
    for (;;) {
    }
}

int execute_elf_image(uint8_t* elf_data, size_t elf_size,
                      char* const argv[], char* const envp[]) {
    mapped_elf_t program;
    mapped_elf_t interpreter;
    mapped_elf_t *interpreter_ptr = NULL;
    const char *interpreter_path;
    uintptr_t entry;
    void *initial_stack;

    memset(&program, 0, sizeof(program));
    memset(&interpreter, 0, sizeof(interpreter));
    if (!argv || !argv[0] || map_elf(elf_data, elf_size, &program) < 0)
        return -1;

    interpreter_path = find_interpreter(elf_data, elf_size);
    if (!interpreter_path) {
        munmap(program.mapping, program.mapping_size);
        return -1;
    }
    if (program.elf_type == ET_DYN && !*interpreter_path) {
        munmap(program.mapping, program.mapping_size);
        return -1;
    }
    if (*interpreter_path) {
        if (map_interpreter(interpreter_path, &interpreter) < 0) {
            munmap(program.mapping, program.mapping_size);
            return -1;
        }
        interpreter_ptr = &interpreter;
    }

    if (update_auxv(envp, &program, interpreter_ptr) < 0) {
        if (interpreter_ptr)
            munmap(interpreter.mapping, interpreter.mapping_size);
        munmap(program.mapping, program.mapping_size);
        return -1;
    }

    entry = interpreter_ptr ? interpreter.entry : program.entry;
    initial_stack = (void *)((uintptr_t *)argv - 1);

    /* Mapping is committed; success consumes the caller's heap buffer. */
    secure_memory_wipe(elf_data, elf_size);
    free(elf_data);
    enter_elf(entry, initial_stack);
}
