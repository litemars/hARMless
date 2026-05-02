#include "common.h"



volatile uint32_t g_packed_magic = PACKED_MAGIC;

__attribute__((used))
volatile uint8_t g_pack_polymorph[256] = { [0] = 0xFF };
