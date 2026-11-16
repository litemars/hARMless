#include "common.h"

#ifndef EXEC_DIRECT_ONLY
int create_payload_memfd(const char* argv0) {
    const char fallback[] = "payload";
    const char* base = fallback;
    char name[64];

    if (argv0 && argv0[0]) {
        base = argv0;
        for (const char* p = argv0; *p; p++) {
            if (*p == '/') base = p + 1;
        }
        if (!base[0]) base = fallback;
    }

    size_t len = 0;
    while (base[len] && len < sizeof(name) - 1) {
        name[len] = base[len];
        len++;
    }
    name[len] = '\0';
    return syscall2(__NR_memfd_create, (long)name, MFD_CLOEXEC);
}
#endif
