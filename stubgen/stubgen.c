#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include "common.h"
#include "elf64.h"

#define POLYMORPH_PADDING_MAX 256
#define POLYMORPH_FILLER_LEN  256

static int slurp_file(const char* path, uint8_t** out_buf, size_t* out_size) {
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Error: cannot open '%s': %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: fseek failed on '%s': %s\n", path, strerror(errno));
        fclose(fp);
        return -1;
    }
    long sz = ftell(fp);
    if (sz <= 0 || (size_t)sz > SIZE_MAX / 2) {
        fprintf(stderr, "Error: '%s' has invalid size %ld\n", path, sz);
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error: rewind failed on '%s': %s\n", path, strerror(errno));
        fclose(fp);
        return -1;
    }
    uint8_t* buf = malloc((size_t)sz);
    if (!buf) {
        fprintf(stderr, "Error: cannot allocate %ld bytes for '%s'\n", sz, path);
        fclose(fp);
        return -1;
    }
    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (n != (size_t)sz) {
        fprintf(stderr, "Error: short read on '%s' (%zu of %ld)\n", path, n, sz);
        free(buf);
        return -1;
    }
    *out_buf = buf;
    *out_size = (size_t)sz;
    return 0;
}

/*
 * get_random_bytes: fill buf with `len` cryptographically random bytes
 * from /dev/urandom. Falls back to time/pid-seeded rand() only if the
 * device cannot be opened (very unusual on Linux).
 */
static int get_random_bytes(uint8_t* buf, size_t len) {
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        size_t n = fread(buf, 1, len, urandom);
        fclose(urandom);
        if (n == len) return 0;
    }
    /* Fallback: explicitly inferior, but better than failing the build. */
    static int seeded = 0;
    if (!seeded) { srand((unsigned)(time(NULL) ^ getpid())); seeded = 1; }
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
    return 0;
}

static int strtab_streq(const char* strtab, size_t strtab_size,
                        size_t offset, const char* needle) {
    if (offset >= strtab_size) return 0;
    size_t i = 0;
    while (offset + i < strtab_size) {
        char c = strtab[offset + i];
        char n = needle[i];
        if (c != n) return 0;
        if (c == '\0') return 1;  /* both NUL means exact match */
        i++;
    }
    return 0;
}

static int find_loader_symbol(const uint8_t* loader, size_t loader_size,
                              const char* sym_name,
                              size_t* out_offset, size_t* out_size) {
    if (loader_size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "Error: loader smaller than ELF header\n");
        return -1;
    }
    if (!is_elf64(loader)) {
        fprintf(stderr, "Error: loader is not ELF64\n");
        return -1;
    }
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)loader;
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
        fprintf(stderr, "Error: loader has no section header table — "
                        "build/loader must be unstripped for stubgen\n");
        return -1;
    }
    if (ehdr->e_shentsize != sizeof(Elf64_Shdr)) {
        fprintf(stderr, "Error: unexpected section header size %u\n",
                ehdr->e_shentsize);
        return -1;
    }
    size_t sht_size = (size_t)ehdr->e_shnum * ehdr->e_shentsize;
    if (ehdr->e_shoff > loader_size || sht_size > loader_size - ehdr->e_shoff) {
        fprintf(stderr, "Error: section header table out of file bounds\n");
        return -1;
    }
    const Elf64_Shdr* sections = (const Elf64_Shdr*)(loader + ehdr->e_shoff);

    /* Find .symtab by section type — more robust than name lookup. */
    const Elf64_Shdr* symtab = NULL;
    for (size_t i = 0; i < ehdr->e_shnum; i++) {
        if (sections[i].sh_type == SHT_SYMTAB) {
            symtab = &sections[i];
            break;
        }
    }
    if (!symtab) {
        fprintf(stderr, "Error: loader has no .symtab — build/loader must "
                        "be unstripped for stubgen\n");
        return -1;
    }
    if (symtab->sh_entsize != sizeof(Elf64_Sym)) {
        fprintf(stderr, "Error: unexpected symbol entry size %llu\n",
                (unsigned long long)symtab->sh_entsize);
        return -1;
    }
    if (symtab->sh_offset > loader_size ||
        symtab->sh_size > loader_size - symtab->sh_offset) {
        fprintf(stderr, "Error: .symtab out of file bounds\n");
        return -1;
    }
    if (symtab->sh_link == 0 || symtab->sh_link >= ehdr->e_shnum) {
        fprintf(stderr, "Error: .symtab.sh_link invalid\n");
        return -1;
    }
    const Elf64_Shdr* strtab = &sections[symtab->sh_link];
    if (strtab->sh_type != SHT_STRTAB) {
        fprintf(stderr, "Error: .symtab.sh_link does not point to a strtab\n");
        return -1;
    }
    if (strtab->sh_offset > loader_size ||
        strtab->sh_size > loader_size - strtab->sh_offset) {
        fprintf(stderr, "Error: .strtab out of file bounds\n");
        return -1;
    }

    const char* names = (const char*)(loader + strtab->sh_offset);
    const Elf64_Sym* syms = (const Elf64_Sym*)(loader + symtab->sh_offset);
    size_t nsyms = (size_t)(symtab->sh_size / sizeof(Elf64_Sym));

    for (size_t i = 0; i < nsyms; i++) {
        const Elf64_Sym* s = &syms[i];
        if (s->st_name == 0) continue;
        if (s->st_shndx == 0 || s->st_shndx >= ehdr->e_shnum) continue;

        if (!strtab_streq(names, (size_t)strtab->sh_size,
                          (size_t)s->st_name, sym_name)) continue;

        /* Match — translate virtual address to file offset via the
         * containing section's sh_addr / sh_offset pair. */
        const Elf64_Shdr* sec = &sections[s->st_shndx];
        if (sec->sh_type == SHT_NOBITS) {
            fprintf(stderr, "Error: symbol '%s' is in .bss (no file image) — "
                            "ensure it is initialized to a non-zero value\n",
                    sym_name);
            return -1;
        }
        if (s->st_value < sec->sh_addr) {
            fprintf(stderr, "Error: symbol '%s' value below section base\n",
                    sym_name);
            return -1;
        }
        size_t in_section = (size_t)(s->st_value - sec->sh_addr);
        if (in_section >= sec->sh_size) {
            fprintf(stderr, "Error: symbol '%s' beyond section end\n", sym_name);
            return -1;
        }
        size_t file_off = (size_t)sec->sh_offset + in_section;
        if (file_off > loader_size || s->st_size > loader_size - file_off) {
            fprintf(stderr, "Error: symbol '%s' file range out of bounds\n",
                    sym_name);
            return -1;
        }
        *out_offset = file_off;
        *out_size = (size_t)s->st_size;
        return 0;
    }

    fprintf(stderr, "Error: symbol '%s' not found in loader .symtab\n", sym_name);
    return -1;
}

void print_usage(const char* program_name) {
    printf("Usage: %s <loader_binary> <packed_data> <output_stub>\n", program_name);
    printf("\nCombines an unstripped loader with packed data and applies\n");
    printf("per-pack polymorphic patches: random magic, random 256-byte\n");
    printf("filler, random padding length, and section-header strip.\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }
    const char* loader_file = argv[1];
    const char* packed_file = argv[2];
    const char* output_file = argv[3];

    uint8_t* loader_data = NULL;
    uint8_t* packed_data = NULL;
    size_t loader_size = 0, packed_size = 0;
    int ret = 1;

    if (slurp_file(loader_file, &loader_data, &loader_size) != 0) goto cleanup;
    if (slurp_file(packed_file, &packed_data, &packed_size) != 0) goto cleanup;

    if (packed_size < sizeof(pack_header_t)) {
        fprintf(stderr, "Error: packed file is smaller than pack_header_t\n");
        goto cleanup;
    }

    /* Locate patch points in the loader. */
    size_t magic_off = 0, magic_sz = 0;
    size_t poly_off  = 0, poly_sz  = 0;
    if (find_loader_symbol(loader_data, loader_size, "g_packed_magic",
                           &magic_off, &magic_sz) != 0) goto cleanup;
    if (find_loader_symbol(loader_data, loader_size, "g_pack_polymorph",
                           &poly_off, &poly_sz) != 0) goto cleanup;

    if (magic_sz != sizeof(uint32_t)) {
        fprintf(stderr, "Error: g_packed_magic has unexpected size %zu\n", magic_sz);
        goto cleanup;
    }
    if (poly_sz != POLYMORPH_FILLER_LEN) {
        fprintf(stderr, "Error: g_pack_polymorph has unexpected size %zu (want %d)\n",
                poly_sz, POLYMORPH_FILLER_LEN);
        goto cleanup;
    }

    /* Generate per-pack random material. */
    uint32_t new_magic = 0;
    uint8_t  new_filler[POLYMORPH_FILLER_LEN];
    uint8_t  pad_byte = 0;
    uint8_t  padding[POLYMORPH_PADDING_MAX];

    if (get_random_bytes((uint8_t*)&new_magic, sizeof(new_magic)) != 0) goto cleanup;
    if (get_random_bytes(new_filler, sizeof(new_filler)) != 0) goto cleanup;
    if (get_random_bytes(&pad_byte, 1) != 0) goto cleanup;
    if (get_random_bytes(padding, sizeof(padding)) != 0) goto cleanup;
    size_t pad_len = (size_t)pad_byte;  /* 0..255 */

    /* Patch loader bytes in our local buffer (we own it; safe to mutate). */
    memcpy(loader_data + magic_off, &new_magic, sizeof(new_magic));
    memcpy(loader_data + poly_off, new_filler, sizeof(new_filler));

    /* Patch the packed header's magic field. pack_header_t.magic is the
     * very first field (offset 0), 4 bytes. */
    memcpy(packed_data + 0, &new_magic, sizeof(new_magic));


    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)loader_data;
    {
        Elf64_Shdr* sections = (Elf64_Shdr*)(loader_data + ehdr->e_shoff);
        for (size_t i = 0; i < ehdr->e_shnum; i++) {
            if (sections[i].sh_type != SHT_SYMTAB &&
                sections[i].sh_type != SHT_STRTAB) continue;
            if (sections[i].sh_offset > loader_size) continue;
            if (sections[i].sh_size > loader_size - sections[i].sh_offset) continue;
            if (sections[i].sh_size == 0) continue;
            (void)get_random_bytes(loader_data + sections[i].sh_offset,
                                   (size_t)sections[i].sh_size);
        }
    }

    ehdr->e_shoff     = 0;
    ehdr->e_shnum     = 0;
    ehdr->e_shentsize = 0;
    ehdr->e_shstrndx  = 0;

    /* Write output. */
    FILE* out = fopen(output_file, "wb");
    if (!out) {
        fprintf(stderr, "Error: cannot create '%s': %s\n", output_file, strerror(errno));
        goto cleanup;
    }
    if (fwrite(loader_data, 1, loader_size, out) != loader_size) goto fail_write;
    if (pad_len > 0 && fwrite(padding, 1, pad_len, out) != pad_len) goto fail_write;
    if (fwrite(packed_data, 1, packed_size, out) != packed_size) goto fail_write;
    fclose(out);

    if (chmod(output_file, 0755) < 0) {
        fprintf(stderr, "Warning: chmod +x failed: %s\n", strerror(errno));
    }

    printf("Polymorphic stub generated: %s\n", output_file);
    printf("  Loader        : %zu bytes\n", loader_size);
    printf("  Padding       : %zu bytes\n", pad_len);
    printf("  Packed payload: %zu bytes\n", packed_size);
    printf("  Total         : %zu bytes\n", loader_size + pad_len + packed_size);
    printf("  New magic     : 0x%08X\n", new_magic);
    printf("  Polymorph     : %d bytes randomized in .data\n", POLYMORPH_FILLER_LEN);

    ret = 0;
    goto cleanup;

fail_write:
    fprintf(stderr, "Error: write failed on '%s': %s\n", output_file, strerror(errno));
    fclose(out);
    unlink(output_file);

cleanup:
    if (loader_data) free(loader_data);
    if (packed_data) free(packed_data);
    return ret;
}
