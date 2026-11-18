#define TEXT_POLYMORPH_LEN 512

#if defined(__x86_64__)
    .text
    .globl harmless_text_polymorph
    .type harmless_text_polymorph,@function
harmless_text_polymorph:
    .globl g_text_polymorph
    .type g_text_polymorph,@object
g_text_polymorph:
    .rept TEXT_POLYMORPH_LEN
    .byte 0x90
    .endr
    .size g_text_polymorph, .-g_text_polymorph
    ret
    .size harmless_text_polymorph, .-harmless_text_polymorph
#elif defined(__aarch64__)
    .text
    .globl harmless_text_polymorph
    .type harmless_text_polymorph,%function
harmless_text_polymorph:
    .globl g_text_polymorph
    .type g_text_polymorph,%object
g_text_polymorph:
    .rept (TEXT_POLYMORPH_LEN / 4)
    .inst 0xd503201f
    .endr
    .size g_text_polymorph, .-g_text_polymorph
    ret
    .size harmless_text_polymorph, .-harmless_text_polymorph
#else
#error "Unsupported architecture"
#endif

    .section .note.GNU-stack,"",@progbits
