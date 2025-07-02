.section .text
.global _start
.type _start, @function

_start:
    // AArch64 loader entry point
    // This code is position-independent and gets injected into the target ELF
    
    // Save registers that might be used by the original program
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x10, x11, [sp, #-16]!
    stp x12, x13, [sp, #-16]!
    stp x14, x15, [sp, #-16]!
    stp x16, x17, [sp, #-16]!
    stp x18, x19, [sp, #-16]!
    stp x20, x21, [sp, #-16]!
    stp x22, x23, [sp, #-16]!
    stp x24, x25, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
    str x30, [sp, #-8]!
    
    // Align stack to 16-byte boundary
    mov x0, sp
    and x0, x0, #~15
    mov sp, x0
    
    // Call the main loader function
    bl loader_main
    
    // If loader_main returns (it shouldn't), restore and exit
    ldr x30, [sp], #8
    ldp x28, x29, [sp], #16
    ldp x26, x27, [sp], #16
    ldp x24, x25, [sp], #16
    ldp x22, x23, [sp], #16
    ldp x20, x21, [sp], #16
    ldp x18, x19, [sp], #16
    ldp x16, x17, [sp], #16
    ldp x14, x15, [sp], #16
    ldp x12, x13, [sp], #16
    ldp x10, x11, [sp], #16
    ldp x8, x9, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
    
    // Exit with error code if we reach here
    mov x8, #93        // __NR_exit
    mov x0, #1         // exit status
    svc #0
    
    // Should never reach here
    b .

// Alternative entry point for debugging
.global _start_debug
.type _start_debug, @function

_start_debug:
    // Minimal entry for debugging purposes
    bl loader_debug_info
    
    // Exit
    mov x8, #93        // __NR_exit
    mov x0, #0         // success
    svc #0
    b .

// Position-independent data access helper
.global get_data_base
.type get_data_base, @function

get_data_base:
    // Get current position
    adr x0, .
    ret

// Simple memory copy function in assembly
.global asm_memcpy
.type asm_memcpy, @function

asm_memcpy:
    // x0 = dest, x1 = src, x2 = count
    mov x3, x0          // Save original dest
    cbz x2, 2f          // If count is 0, done
    
1:  ldrb w4, [x1], #1  // Load byte from src, increment
    strb w4, [x0], #1   // Store byte to dest, increment
    subs x2, x2, #1     // Decrement count
    bne 1b              // Continue if not zero
    
2:  mov x0, x3          // Return original dest
    ret

// Simple memory set function in assembly
.global asm_memset
.type asm_memset, @function

asm_memset:
    // x0 = dest, x1 = value, x2 = count
    mov x3, x0          // Save original dest
    and w1, w1, #0xff   // Ensure value is byte-sized
    cbz x2, 2f          // If count is 0, done
    
1:  strb w1, [x0], #1  // Store byte, increment dest
    subs x2, x2, #1     // Decrement count
    bne 1b              // Continue if not zero
    
2:  mov x0, x3          // Return original dest
    ret

// End of loader stub
.global _loader_end
_loader_end:
    nop

.section .data
loader_signature:
    .ascii "AARCH64_LOADER_V1"
    .byte 0

.section .bss
.align 8
loader_buffer:
    .space 4096