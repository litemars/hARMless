#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>

#include "includes/common.h"
#include "includes/elf_utils.h"
#include "includes/crypto.h"
#include "loader_stub.h"

static void usage(const char *prog) {
    printf("AArch64 ELF Packer - Runtime Crypter for ARM64 binaries\n\n");
    printf("Usage: %s [options] <input_file> <output_file>\n\n", prog);
    printf("Options:\n");
    printf("  -v, --verbose    Enable verbose output\n");
    printf("  -h, --help       Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s binary packed_binary\n", prog);
    printf("  %s -v /bin/ls packed_ls\n", prog);
}

int main(int argc, char *argv[]) {
    char *input_file = NULL;
    char *output_file = NULL;
    int verbose = 0;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (!input_file) {
            input_file = argv[i];
        } else if (!output_file) {
            output_file = argv[i];
        } else {
            fprintf(stderr, "Error: Too many arguments\n");
            usage(argv[0]);
            return 1;
        }
    }
    
    if (!input_file || !output_file) {
        fprintf(stderr, "Error: Missing input or output file\n");
        usage(argv[0]);
        return 1;
    }
    
    if (verbose) {
        printf("[+] AArch64 Packer starting...\n");
        printf("[+] Input file: %s\n", input_file);
        printf("[+] Output file: %s\n", output_file);
    }
    
    // Read input ELF file
    char *elf_buffer = NULL;
    size_t elf_size = 0;
    
    if (read_elf_file(input_file, &elf_buffer, &elf_size) != 0) {
        fprintf(stderr, "Error: Failed to read input file\n");
        return 1;
    }
    
    if (verbose) {
        printf("[+] Read %zu bytes from input file\n", elf_size);
    }
    
    // Validate ELF header
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_buffer;
    if (validate_elf_header(ehdr) != 0) {
        fprintf(stderr, "Error: Invalid ELF file or not AArch64\n");
        free(elf_buffer);
        return 1;
    }
    
    if (verbose) {
        printf("[+] ELF validation passed\n");
        printf("[+] Original entry point: 0x%lx\n", ehdr->e_entry);
    }
    
    // Generate encryption key and IV
    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[AES_IV_SIZE];
    generate_random_key(key, sizeof(key));
    generate_random_iv(iv, sizeof(iv));
    
    if (verbose) {
        printf("[+] Generated encryption key and IV\n");
    }
    
    // Encrypt the ELF payload
    uint8_t *encrypted_payload = malloc(elf_size + 16); // Extra space for padding
    size_t encrypted_size = 0;
    
    if (aes_encrypt((uint8_t *)elf_buffer, elf_size, key, iv, 
                    encrypted_payload, &encrypted_size) != 0) {
        fprintf(stderr, "Error: Failed to encrypt payload\n");
        free(elf_buffer);
        free(encrypted_payload);
        return 1;
    }
    
    if (verbose) {
        printf("[+] Encrypted payload (%zu bytes -> %zu bytes)\n", elf_size, encrypted_size);
    }
    
    // Create packed binary header
    packed_header_t header = {
        .magic = MAGIC_SIGNATURE,
        .payload_size = encrypted_size,
        .original_entry = ehdr->e_entry
    };
    memcpy(header.key, key, AES_KEY_SIZE);
    memcpy(header.iv, iv, AES_IV_SIZE);
    
    // Calculate total size needed
    size_t total_size = sizeof(header) + encrypted_size + obj_loader_stub_bin_len;
    char *output_buffer = malloc(total_size);
    
    // Assemble final binary: loader + header + encrypted payload
    memcpy(output_buffer, obj_loader_stub_bin, obj_loader_stub_bin_len);
    memcpy(output_buffer + obj_loader_stub_bin_len, &header, sizeof(header));
    memcpy(output_buffer + obj_loader_stub_bin_len + sizeof(header), 
           encrypted_payload, encrypted_size);
    
    // Write output file
    if (write_elf_file(output_file, output_buffer, total_size) != 0) {
        fprintf(stderr, "Error: Failed to write output file\n");
        free(elf_buffer);
        free(encrypted_payload);
        free(output_buffer);
        return 1;
    }
    
    // Make output file executable
    chmod(output_file, 0755);
    
    if (verbose) {
        printf("[+] Packed binary created successfully\n");
        printf("[+] Original size: %zu bytes\n", elf_size);
        printf("[+] Packed size: %zu bytes\n", total_size);
        printf("[+] Compression ratio: %.1f%%\n", 
               (float)total_size / elf_size * 100.0);
    }
    
    printf("Successfully packed %s -> %s\n", input_file, output_file);
    
    free(elf_buffer);
    free(encrypted_payload);
    free(output_buffer);
    
    return 0;
}
