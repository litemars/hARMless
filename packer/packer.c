#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "common.h"
#include "elf64.h"
#include "crypto.h"

void generate_random_key(uint8_t* key, size_t key_size) {
    size_t i;
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        if (fread(key, 1, key_size, urandom) != key_size) {
            // Fallback if read fails
            srand(time(NULL));
            for (i = 0; i < key_size; i++) {
                key[i] = rand() & 0xFF;
            }
        }
        fclose(urandom);
    } else {
        srand(time(NULL));
        for (i = 0; i < key_size; i++) {
            key[i] = rand() & 0xFF;
        }
    }
}

void multi_layer_encrypt(uint8_t* data, size_t len, const pack_header_t* header) {
    // Layer 1: AES-256
    
    aes256_encrypt(data, len, header->primary_key);
    

    // Layer 2: ChaCha20
    
    chacha20_encrypt(data, len, header->secondary_key, header->nonce);
    

    // Layer 3: RC4
    
    rc4_encrypt_decrypt(header->tertiary_key, 32, data, data, len);
    
}

int is_elf64(const void* data) {
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)data;
    return (ehdr->e_ident[0] == ELFMAG0 &&
            ehdr->e_ident[1] == ELFMAG1 &&
            ehdr->e_ident[2] == ELFMAG2 &&
            ehdr->e_ident[3] == ELFMAG3 &&
            ehdr->e_ident[4] == ELFCLASS64);
}

int is_elf32(const void* data) {
    const Elf32_Ehdr* ehdr = (const Elf32_Ehdr*)data;
    return (ehdr->e_ident[0] == ELFMAG0 &&
            ehdr->e_ident[1] == ELFMAG1 &&
            ehdr->e_ident[2] == ELFMAG2 &&
            ehdr->e_ident[3] == ELFMAG3 &&
            ehdr->e_ident[4] == ELFCLASS32);
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

static int is_elf64_target(const void* data) {
#if defined(TARGET_ARM32)
    return is_elf32_arm(data);
#elif defined(TARGET_X86_64)
    return is_elf64_x86_64(data);
#else
    return is_elf64_arm64(data);
#endif
}

static const char* target_arch_name(void) {
#if defined(TARGET_ARM32)
    return "ARM32/EABI5";
#elif defined(TARGET_X86_64)
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

    fseek(input_fp, 0, SEEK_END);
    size_t file_size = ftell(input_fp);
    fseek(input_fp, 0, SEEK_SET);

    if (file_size == 0 || file_size > SIZE_MAX / 2) {
        fprintf(stderr, "Error: Input file is empty or too large\n");
        fclose(input_fp);
        return 1;
    }

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

    if (!is_elf64_target(file_data)) {
        fprintf(stderr, "Error: Input file is not a %s ELF binary\n",
                target_arch_name());
        free(file_data);
        return 1;
    }

    printf("Packing %s ELF binary: %s\n", target_arch_name(), input_file);
    printf("Original size: %zu bytes\n", file_size);

    strip_elf_metadata(file_data, file_size);

    uint32_t original_crc = crc32(file_data, file_size);
    uint8_t* encrypted_data = malloc(file_size);
    if (!encrypted_data) {
        fprintf(stderr, "Error: Cannot allocate memory for encrypted data\n");
        free(file_data);
        return 1;
    }

    memcpy(encrypted_data, file_data, file_size);

    pack_header_t header;
    memset(&header, 0, sizeof(header));

    header.magic = PACKED_MAGIC;
    header.original_size = file_size;
    header.packed_size = file_size;
    header.crc32 = original_crc;

    generate_random_key(header.primary_key, 32);
    generate_random_key(header.secondary_key, 32);
    generate_random_key(header.tertiary_key, 32);
    generate_random_key(header.nonce, 16);
    generate_random_key(header.salt, 16);

    multi_layer_encrypt(encrypted_data, file_size, &header);

    FILE* output_fp = fopen(output_file, "wb");
    if (!output_fp) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", output_file);
        free(file_data);
        free(encrypted_data);
        return 1;
    }

    size_t header_written = fwrite(&header, sizeof(header), 1, output_fp);
    if (header_written != 1) {
        fprintf(stderr, "Error: Cannot write header to output file\n");
        fclose(output_fp);
        free(file_data);
        free(encrypted_data);
        return 1;
    }

    size_t data_written = fwrite(encrypted_data, 1, file_size, output_fp);
    if (data_written != file_size) {
        fprintf(stderr, "Error: Cannot write encrypted data to output file (wrote %zu of %zu bytes)\n", data_written, file_size);
        fclose(output_fp);
        free(file_data);
        free(encrypted_data);
        return 1;
    }
    fclose(output_fp);

    chmod(output_file, 0755);

    printf("\nPacking completed successfully!\n");
    printf("==========================================\n");
    printf("Output file: %s\n", output_file);
    printf("Packed size: %zu bytes\n", sizeof(header) + file_size);
    printf("CRC32: 0x%08X\n", original_crc);

    secure_memory_wipe(file_data, file_size);
    secure_memory_wipe(encrypted_data, file_size);
    free(file_data);
    free(encrypted_data);

    return 0;
}
