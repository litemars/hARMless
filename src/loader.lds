ENTRY(_start)

PHDRS {
  text PT_LOAD FLAGS(0x5); /* RX */
  data PT_LOAD FLAGS(0x6); /* RW */
}

SECTIONS
{
  . = SIZEOF_HEADERS;

  .text : { *(.text*) } :text
  .rodata : { *(.rodata*) } :text
  .data : { *(.data*) } :data
  .bss : { *(.bss*) } :data

  _end = .;
}
