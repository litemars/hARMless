# hARMless ARM32/EABI5 Packer Handoff

Date: 2026-07-15

## Purpose

This handoff is for integrating hARMless into a project whose build output is
ARM32/EABI5 ELF.

The supported workflow is:

- Build ARM32/EABI5 target artifacts.
- Run host-native x86_64 WSL tools to pack an ARM32/EABI5 ELF.
- Run the packed output on native ARM32 Linux or ARM64 Linux with 32-bit ARM
  compatibility enabled.

## Build Outputs

Run:

```bash
make all32
make verify-build32
```

Expected outputs:

```text
build/ARM32_EABI5/packer
build/ARM32_EABI5/loader
build/ARM32_EABI5/stubgen
build/X86_X64/packer-arm32
build/X86_X64/stubgen
```

On x86_64 WSL:

- `build/X86_X64/packer-arm32` validates and encrypts ARM32/EABI5 input ELF.
- `build/X86_X64/stubgen` patches the ARM32 loader and emits the final binary.
- `build/ARM32_EABI5/loader` is embedded into the final packed executable.

## Dependencies On x86_64 WSL

```bash
sudo dpkg --add-architecture armhf
sudo apt-get update
sudo apt-get install -y \
  gcc-arm-linux-gnueabihf \
  binutils-arm-linux-gnueabihf \
  qemu-user \
  libssl-dev:amd64 \
  libssl-dev:armhf \
  zlib1g-dev:armhf \
  libzstd-dev:armhf
```

Or:

```bash
make install-deps32
```

## Pack Command

Use this command from the hARMless repository root:

```bash
make pack32 INPUT=/path/to/input_arm32_eabi5_elf OUTPUT=/path/to/output_packed_arm32_eabi5_elf
```

Equivalent direct command sequence:

```bash
./build/X86_X64/packer-arm32 /path/to/input_arm32_eabi5_elf /tmp/payload.packed
./build/X86_X64/stubgen \
  ./build/ARM32_EABI5/loader \
  /tmp/payload.packed \
  /path/to/output_packed_arm32_eabi5_elf
rm -f /tmp/payload.packed
```

The final output should report as ARM32/EABI5:

```bash
file /path/to/output_packed_arm32_eabi5_elf
readelf -h /path/to/output_packed_arm32_eabi5_elf | grep "Version5 EABI"
```

## Consuming Project Wrapper

Minimal wrapper for another project:

```bash
#!/bin/bash
set -euo pipefail

HARMLESS_ROOT=/path/to/hARMless
INPUT_ARM32_ELF="$1"
OUTPUT_ARM32_PACKED="$2"
TMP_PACKED="${OUTPUT_ARM32_PACKED}.packed"

file "$INPUT_ARM32_ELF" | grep -q "ARM"
readelf -h "$INPUT_ARM32_ELF" | grep -q "Version5 EABI"

"$HARMLESS_ROOT/build/X86_X64/packer-arm32" "$INPUT_ARM32_ELF" "$TMP_PACKED"
"$HARMLESS_ROOT/build/X86_X64/stubgen" \
  "$HARMLESS_ROOT/build/ARM32_EABI5/loader" \
  "$TMP_PACKED" \
  "$OUTPUT_ARM32_PACKED"
rm -f "$TMP_PACKED"
```

## Validation Evidence

Local x86_64 WSL:

```bash
make all32
make verify-build32
make test32
```

Validated output types:

```text
build/ARM32_EABI5/packer:   ELF 32-bit LSB pie executable, ARM, EABI5
build/ARM32_EABI5/loader:   ELF 32-bit LSB executable, ARM, EABI5, statically linked
build/ARM32_EABI5/stubgen:  ELF 32-bit LSB executable, ARM, EABI5, statically linked
build/X86_X64/packer-arm32: ELF 64-bit LSB pie executable, x86-64
build/X86_X64/stubgen:      ELF 64-bit LSB executable, x86-64, statically linked
```

Runtime validation on ARM64 Linux with 32-bit ARM compatibility:

- Original ARM32/EABI5 static payload wrote `/tmp/hARMless_arm32_payload_marker`.
- Packed ARM32/EABI5 payload also wrote the same marker.
- Both returned status 0.

Observed packed output:

```text
ELF 32-bit LSB executable, ARM, EABI5 version 1, statically linked, no section header
```

## qemu-user Note

`qemu-arm` is useful for checking that an unprotected ARM32/EABI5 binary starts,
but it is not a reliable validator for this packed loader. The loader reads its
own executable image and includes anti-analysis checks; qemu-user can alter
`/proc/self/exe` behavior or trigger those checks. Use native ARM32 Linux or
ARM64 Linux with 32-bit ARM compatibility for runtime acceptance.

## Important Implementation Notes

- ARM32/EABI5 support uses ELF32 symbol/section parsing in `stubgen`.
- ARM32 loader uses ARM EABI direct syscalls.
- ARM32 target disables the io_uring write path and uses the plain write path.
- AES was changed to AES-256-CTR so encrypted payload size always matches the
  original ELF size across ARM32 and ARM64.

## Current Boundaries

- ARM32 target is `arm-linux-gnueabihf` / EABI5.
- Hard-float ARMHF is the validated ABI.
- The packed output is a Linux ARM32 executable, not Android APK/so packaging.
- Runtime validation still needs a native/compat ARM environment, not only qemu.
