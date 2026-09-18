#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include "common.h"
#include "elf64.h"
#include "crypto.h"

static int generate_random_key(uint8_t* key, size_t key_size) {
    if (!key || key_size == 0 || key_size > INT_MAX) return 0;
    return RAND_bytes(key, (int)key_size) == 1;
}

int is_elf64(const void* data) {
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)data;
    return (ehdr->e_ident[0] == ELFMAG0 &&
            ehdr->e_ident[1] == ELFMAG1 &&
            ehdr->e_ident[2] == ELFMAG2 &&
            ehdr->e_ident[3] == ELFMAG3 &&
            ehdr->e_ident[4] == ELFCLASS64);
}

int is_elf64_arm64(const void* data) {
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)data;
    return is_elf64(data) && ehdr->e_machine == EM_AARCH64;
}

int is_elf64_x86_64(const void* data) {
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)data;
    return is_elf64(data) && ehdr->e_machine == EM_X86_64;
}

static int is_elf64_target(const void* data) {
#if defined(TARGET_X86_64)
    return is_elf64_x86_64(data);
#else
    return is_elf64_arm64(data);
#endif
}

static const char* target_arch_name(void) {
#if defined(TARGET_X86_64)
    return "x86-64";
#else
    return "ARM64";
#endif
}

void print_usage(const char* program_name) {
    printf("Advanced %s ELF Packer v2 - Integrated Obfuscation\n",
           target_arch_name());
    printf("Usage: %s <input_elf> <output_packed>\n", program_name);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char* input_file = argv[1];
    const char* output_file = argv[2];


    printf("Advanced %s ELF Packer\n", target_arch_name());

    // Open and read input file
    FILE* input_fp = fopen(input_file, "rb");
    if (!input_fp) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return 1;
    }

    if (fseek(input_fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: Cannot determine input file size\n");
        fclose(input_fp);
        return 1;
    }
    long file_length = ftell(input_fp);
    if (file_length <= 0 || file_length > INT_MAX ||
        fseek(input_fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error: Input file is empty, unreadable, or too large\n");
        fclose(input_fp);
        return 1;
    }
    size_t file_size = (size_t)file_length;

    uint8_t* file_data = malloc(file_size);
    if (!file_data) {
        fprintf(stderr, "Error: Cannot allocate memory for file data\n");
        fclose(input_fp);
        return 1;
    }

    size_t bytes_read = fread(file_data, 1, file_size, input_fp);
    if (bytes_read != file_size) {
        fprintf(stderr, "Error: Cannot read input file (read %zu of %zu bytes)\n", bytes_read, file_size);
        free(file_data);
        fclose(input_fp);
        return 1;
    }
    fclose(input_fp);

    if (file_size < sizeof(Elf64_Ehdr) || !is_elf64_target(file_data)) {
        fprintf(stderr, "Error: Input file is not a %s ELF binary\n",
                target_arch_name());
        free(file_data);
        return 1;
    }

    printf("Packing %s ELF binary: %s\n", target_arch_name(), input_file);
    printf("Original size: %zu bytes\n", file_size);

    strip_elf_metadata(file_data, file_size);

    uint32_t original_crc = crc32(file_data, file_size);
    pack_header_t header;
    FILE* output_fp = NULL;
    int result = 1;

    memset(&header, 0, sizeof(header));

    header.magic = PACKED_MAGIC;
    header.original_size = (uint32_t)file_size;
    header.packed_size = (uint32_t)file_size;
    header.crc32 = original_crc;

    if (!generate_random_key(header.key, sizeof(header.key)) ||
        !generate_random_key(header.iv, sizeof(header.iv))) {
        fprintf(stderr, "Error: Cannot read cryptographic randomness\n");
        goto cleanup;
    }
    memcpy(header.format_tag, PACK_FORMAT_TAG, sizeof(header.format_tag));

    if (!aes256_ctr_crypt(file_data, file_size, header.key, header.iv)) {
        fprintf(stderr, "Error: Encryption failed\n");
        goto cleanup;
    }

    output_fp = fopen(output_file, "wb");
    if (!output_fp) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", output_file);
        goto cleanup;
    }

    size_t header_written = fwrite(&header, sizeof(header), 1, output_fp);
    if (header_written != 1) {
        fprintf(stderr, "Error: Cannot write header to output file\n");
        goto cleanup;
    }

    size_t data_written = fwrite(file_data, 1, file_size, output_fp);
    if (data_written != file_size) {
        fprintf(stderr, "Error: Cannot write encrypted data to output file (wrote %zu of %zu bytes)\n", data_written, file_size);
        goto cleanup;
    }
    fclose(output_fp);
    output_fp = NULL;

    chmod(output_file, 0755);

    printf("\nPacking completed successfully!\n");
    printf("==========================================\n");
    printf("Output file: %s\n", output_file);
    printf("Packed size: %zu bytes\n", sizeof(header) + file_size);
    printf("CRC32: 0x%08X\n", original_crc);
    printf("Cipher: AES-256-CTR\n");

    result = 0;

cleanup:
    if (output_fp) fclose(output_fp);
    secure_memory_wipe(file_data, file_size);
    secure_memory_wipe(&header, sizeof(header));
    free(file_data);

    return result;
}
