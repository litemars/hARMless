ENTRY(_start)

PHDRS {
    text PT_LOAD FLAGS(0x5);
    data PT_LOAD FLAGS(0x6);
}

SECTIONS
{
    . = SIZEOF_HEADERS;
    
    .text : { 
        *(.text*)
        *(.rodata*)
    } :text
    
    .data : { 
        *(.data*)
        *(.sdata*)
    } :data
    
    .bss : { 
        *(.bss*)
        *(.sbss*)
    } :data
    
    .got : { *(.got) }
    .got.plt : { *(.got.plt) }

    _end = .;
    
    /DISCARD/ : {
        *(.note*)
        *(.comment)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.gnu.hash)
        *(.dynsym)
        *(.dynstr)
        *(.dynamic)
        *(.got*)
        *(.plt*)
    }
}