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
    printf("AArch64 ELF Packer - Advanced Runtime Crypter for ARM64 binaries\n\n");
    printf("Usage: %s [options] <input_file> <output_file>\n\n", prog);
    printf("Options:\n");
    printf("  -v, --verbose    Enable verbose output\n");
    printf("  -m, --method     Injection method (note|padding) [default: note]\n");
    printf("  -h, --help       Show this help message\n");
    printf("\nSupported injection methods:\n");
    printf("  note      - PT_NOTE to PT_LOAD conversion (recommended)\n");
    printf("  padding   - Text segment padding injection\n");
    printf("\nExamples:\n");
    printf("  %s binary packed_binary\n", prog);
    printf("  %s -v -m note /bin/ls packed_ls\n", prog);
    printf("  %s --verbose --method padding program packed_program\n", prog);
}

int main(int argc, char *argv[]) {
    char *input_file = NULL;
    char *output_file = NULL;
    char *injection_method = "note";
    int verbose = 0;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--method") == 0) {
            if (i + 1 < argc) {
                injection_method = argv[++i];
            } else {
                fprintf(stderr, "Error: --method requires an argument\n");
                usage(argv[0]);
                return 1;
            }
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
    
    // Validate injection method
    if (strcmp(injection_method, "note") != 0 && strcmp(injection_method, "padding") != 0) {
        fprintf(stderr, "Error: Invalid injection method '%s'\n", injection_method);
        usage(argv[0]);
        return 1;
    }
    
    if (verbose) {
        INFO_PRINT("AArch64 Packer starting...");
        INFO_PRINT("Input file: %s", input_file);
        INFO_PRINT("Output file: %s", output_file);
        INFO_PRINT("Injection method: %s", injection_method);
    }
    
    // Read input ELF file
    char *elf_buffer = NULL;
    size_t elf_size = 0;
    
    if (read_elf_file(input_file, &elf_buffer, &elf_size) != 0) {
        ERROR_PRINT("Failed to read input file");
        return 1;
    }
    
    if (verbose) {
        INFO_PRINT("Read %zu bytes from input file", elf_size);
    }
    
    // Validate ELF header
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_buffer;
    if (validate_elf_header(ehdr) != 0) {
        ERROR_PRINT("Invalid ELF file or not AArch64");
        free(elf_buffer);
        return 1;
    }
    
    // Check if already packed
    if (is_already_packed(ehdr)) {
        ERROR_PRINT("File appears to already be packed");
        free(elf_buffer);
        return 1;
    }
    
    if (verbose) {
        INFO_PRINT("ELF validation passed");
        INFO_PRINT("Original entry point: 0x%lx", ehdr->e_entry);
        print_elf_info(ehdr);
    }
    
    // Check injection space availability
    size_t required_space = obj_loader_stub_bin_len + sizeof(packed_header_t) + elf_size + 1024;
    if (check_injection_space(ehdr, required_space) != 0) {
        ERROR_PRINT("Insufficient space for injection");
        free(elf_buffer);
        return 1;
    }
    
    // Generate encryption key and IV
    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[AES_IV_SIZE];
    generate_random_key(key, sizeof(key));
    generate_random_iv(iv, sizeof(iv));
    
    if (verbose) {
        INFO_PRINT("Generated encryption key and IV");
    }
    
    // Encrypt the ELF payload using AES
    uint8_t *encrypted_payload = malloc(elf_size + 32); // Extra space for padding
    size_t encrypted_size = 0;
    
    if (aes_encrypt((uint8_t *)elf_buffer, elf_size, key, iv, 
                    encrypted_payload, &encrypted_size) != 0) {
        ERROR_PRINT("Failed to encrypt payload");
        free(elf_buffer);
        free(encrypted_payload);
        return 1;
    }
    
    if (verbose) {
        INFO_PRINT("Encrypted payload (%zu bytes -> %zu bytes)", elf_size, encrypted_size);
    }
    
    // Create packed binary header
    packed_header_t header = {
        .magic = MAGIC_SIGNATURE,
        .payload_size = encrypted_size,
        .original_entry = ehdr->e_entry,
        .original_phnum = ehdr->e_phnum
    };
    memcpy(header.key, key, AES_KEY_SIZE);
    memcpy(header.iv, iv, AES_IV_SIZE);
    
    // Prepare injection data (header + encrypted payload)
    size_t injection_data_size = sizeof(header) + encrypted_size;
    char *injection_data = malloc(injection_data_size);
    memcpy(injection_data, &header, sizeof(header));
    memcpy(injection_data + sizeof(header), encrypted_payload, encrypted_size);
    
    // Calculate required buffer size for the packed binary
    size_t packed_size = elf_size + obj_loader_stub_bin_len + injection_data_size + PAGE_SIZE;
    char *packed_buffer = malloc(packed_size);
    memcpy(packed_buffer, elf_buffer, elf_size);
    
    // Perform injection using the specified method
    injection_info_t injection_info;
    int result = -1;
    
    if (strcmp(injection_method, "note") == 0) {
        result = inject_using_note_conversion(packed_buffer, elf_size,
                                              (char*)obj_loader_stub_bin, obj_loader_stub_bin_len,
                                              injection_data, injection_data_size,
                                              &injection_info);
    } else if (strcmp(injection_method, "padding") == 0) {
        result = inject_using_padding(packed_buffer, elf_size,
                                      (char*)obj_loader_stub_bin, obj_loader_stub_bin_len,
                                      &injection_info);
        
        // For padding method, append injection data at the end
        memcpy(packed_buffer + elf_size + obj_loader_stub_bin_len, 
               injection_data, injection_data_size);
    }
    
    if (result != 0) {
        ERROR_PRINT("Failed to inject loader using %s method", injection_method);
        free(elf_buffer);
        free(encrypted_payload);
        free(injection_data);
        free(packed_buffer);
        return 1;
    }
    
    // Update ELF header in packed buffer
    Elf64_Ehdr *packed_ehdr = (Elf64_Ehdr *)packed_buffer;
    uint64_t original_entry;
    if (patch_entry_point(packed_ehdr, injection_info.injection_vaddr, &original_entry) != 0) {
        ERROR_PRINT("Failed to patch entry point");
        free(elf_buffer);
        free(encrypted_payload);
        free(injection_data);
        free(packed_buffer);
        return 1;
    }
    
    // Calculate final packed size
    size_t final_packed_size = elf_size + obj_loader_stub_bin_len + injection_data_size;
    
    // Write packed binary
    if (write_elf_file(output_file, packed_buffer, final_packed_size) != 0) {
        ERROR_PRINT("Failed to write output file");
        free(elf_buffer);
        free(encrypted_payload);
        free(injection_data);
        free(packed_buffer);
        return 1;
    }
    
    // Set executable permissions
    chmod(output_file, 0755);
    
    if (verbose) {
        INFO_PRINT("Injection successful using %s method", injection_method);
        INFO_PRINT("Injected loader at vaddr: 0x%lx", injection_info.injection_vaddr);
        INFO_PRINT("New entry point: 0x%lx", injection_info.injection_vaddr);
        INFO_PRINT("Original entry preserved: 0x%lx", original_entry);
        INFO_PRINT("Packed binary created successfully");
        INFO_PRINT("Original size: %zu bytes", elf_size);
        INFO_PRINT("Packed size: %zu bytes", final_packed_size);
        INFO_PRINT("Size increase: %.1f%%", (float)(final_packed_size - elf_size) / elf_size * 100.0);
    }
    
    printf("Successfully packed %s -> %s (method: %s)\n", input_file, output_file, injection_method);
    
    // Verify the packed ELF is valid
    if (verbose) {
        INFO_PRINT("Verifying packed ELF integrity...");
        if (verify_elf_integrity((Elf64_Ehdr *)packed_buffer, final_packed_size) == 0) {
            INFO_PRINT("Packed ELF integrity check passed");
        } else {
            ERROR_PRINT("Packed ELF integrity check failed");
        }
    }
    
    free(elf_buffer);
    free(encrypted_payload);
    free(injection_data);
    free(packed_buffer);
    
    return 0;
}