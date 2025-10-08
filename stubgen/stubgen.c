#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include "common.h"

void print_usage(const char* program_name) {
    printf("Usage: %s <loader_binary> <packed_data> <output_stub>\n", program_name);
    printf("\nCombines loader with packed data to create self-contained executable\n");
    printf("\nOptions:\n");
    printf("  loader_binary  - The loader executable\n");
    printf("  packed_data    - The packed data file\n");
    printf("  output_stub    - Output self-contained executable\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }

    const char* loader_file = argv[1];
    const char* packed_file = argv[2];
    const char* output_file = argv[3];

    FILE* loader_fp = NULL;
    FILE* packed_fp = NULL;
    FILE* output_fp = NULL;
    uint8_t* loader_data = NULL;
    uint8_t* packed_data = NULL;
    size_t loader_size = 0;
    size_t packed_size = 0;
    int ret = 1;

    loader_fp = fopen(loader_file, "rb");
    if (!loader_fp) {
        fprintf(stderr, "Error: Cannot open loader file '%s': %s\n", loader_file, strerror(errno));
        goto cleanup;
    }

    fseek(loader_fp, 0, SEEK_END);
    loader_size = ftell(loader_fp);
    fseek(loader_fp, 0, SEEK_SET);

    if (loader_size == 0) {
        fprintf(stderr, "Error: Loader file is empty\n");
        goto cleanup;
    }

    packed_fp = fopen(packed_file, "rb");
    if (!packed_fp) {
        fprintf(stderr, "Error: Cannot open packed file '%s': %s\n", packed_file, strerror(errno));
        goto cleanup;
    }

    fseek(packed_fp, 0, SEEK_END);
    packed_size = ftell(packed_fp);
    fseek(packed_fp, 0, SEEK_SET);

    if (packed_size == 0) {
        fprintf(stderr, "Error: Packed file is empty\n");
        goto cleanup;
    }

    loader_data = calloc(loader_size, 1);
    if (!loader_data) {
        fprintf(stderr, "Error: Cannot allocate memory for loader data\n");
        goto cleanup;
    }

    if (fread(loader_data, 1, loader_size, loader_fp) != loader_size) {
        fprintf(stderr, "Error: Cannot read loader file\n");
        goto cleanup;
    }

    packed_data = calloc(packed_size, 1);
    if (!packed_data) {
        fprintf(stderr, "Error: Cannot allocate memory for packed data\n");
        goto cleanup;
    }

    if (fread(packed_data, 1, packed_size, packed_fp) != packed_size) {
        fprintf(stderr, "Error: Cannot read packed file\n");
        goto cleanup;
    }

    output_fp = fopen(output_file, "wb");
    if (!output_fp) {
        fprintf(stderr, "Error: Cannot create output file '%s': %s\n", output_file, strerror(errno));
        goto cleanup;
    }

    if (fwrite(loader_data, 1, loader_size, output_fp) != loader_size) {
        fprintf(stderr, "Error: Cannot write loader data to output file\n");
        goto cleanup;
    }

    if (fwrite(packed_data, 1, packed_size, output_fp) != packed_size) {
        fprintf(stderr, "Error: Cannot write packed data to output file\n");
        goto cleanup;
    }

    printf("Stub generation completed successfully!\n");
    printf("Loader size: %zu bytes\n", loader_size);
    printf("Packed size: %zu bytes\n", packed_size);
    printf("Total size: %zu bytes\n", loader_size + packed_size);
    printf("Output file: %s\n", output_file);

    if (chmod(output_file, 0755) < 0) {
        fprintf(stderr, "Warning: Cannot make output file executable: %s\n", strerror(errno));
    }

    ret = 0;

cleanup:
    if (loader_fp) fclose(loader_fp);
    if (packed_fp) fclose(packed_fp);
    if (output_fp) fclose(output_fp);
    if (loader_data) free(loader_data);
    if (packed_data) free(packed_data);

    return ret;
}
