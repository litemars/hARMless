.section .text
.global _start

_start:
    // AArch64 loader entry point
    // Set up minimal stack and call loader_main
    
    // Align stack pointer
    mov x0, sp
    and x0, x0, #~15
    mov sp, x0
    
    // Call the main loader function
    bl loader_main
    
    // If loader_main returns, exit with error
    mov x8, #93        // __NR_exit
    mov x0, #1         // exit status
    svc #0
    
    // Should never reach here
    b .
