# hARMless ARM64 Packer Handoff

Date: 2026-07-15

Note: if the consuming project outputs ARM32/EABI5 ELF, use
`ARM32_EABI5_HANDOFF.md` instead of this ARM64-specific handoff.

## Purpose

This handoff documents the current usable result from this checkout for reuse by
another project:

- Build succeeds on the current x86_64 WSL host.
- Build succeeds and runtime validation passes on an ARM64 Linux server.
- The supported mainline use case is packing ARM64 ELF files.
- On x86_64 WSL, host-native tools pack ARM64 ELF files by combining the ARM64
  loader stub with encrypted payload data.

No unrelated x86 target workflow is required for the current integration.

## Source State

- Repository: `litemars/hARMless`
- Synced upstream commit: `46b3630`
- Local branch: `main`
- Upstream status at handoff: local `HEAD` matches `origin/main`

Local changes on top of upstream provide:

- Platform-labeled build output directories.
- x86_64 WSL host tools for ARM64 ELF packing.
- ARM64 loader and ARM64-native tools.
- Smoke tests for platform layout and pack flow.
- ARM64 runtime test that runs only on ARM64 Linux.
- README usage updated for the ARM64 packing workflow.

## Output Layout

After running `make all`, the build outputs are:

```text
build/ARM64/packer
build/ARM64/loader
build/ARM64/stubgen
build/X86_X64/packer
build/X86_X64/stubgen
```

On x86_64 WSL:

- `build/X86_X64/packer` runs on the x86_64 WSL host.
- `build/X86_X64/stubgen` runs on the x86_64 WSL host.
- `build/ARM64/loader` is embedded into the final packed ARM64 executable.
- The final packed output is ARM64 ELF and must run on ARM64 Linux.

On ARM64 Linux:

- `build/ARM64/packer`, `build/ARM64/loader`, and `build/ARM64/stubgen` run
  natively.

## Dependencies

### x86_64 Ubuntu/WSL Host

```bash
sudo dpkg --add-architecture arm64
sudo apt-get update
sudo apt-get install -y \
  gcc-aarch64-linux-gnu \
  binutils-aarch64-linux-gnu \
  libssl-dev:amd64 \
  libssl-dev:arm64 \
  zlib1g-dev:arm64 \
  libzstd-dev:arm64
```

The local WSL apt source has been changed to Tsinghua mirrors and verified with:

```bash
sudo apt-get update -qq
```

### ARM64 Linux Host

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  make \
  gcc \
  file \
  binutils \
  pkg-config \
  libssl-dev \
  zlib1g-dev \
  libzstd-dev
```

## Build Commands

Run from the repository root.

```bash
make clean
make all
make verify-build
```

Expected x86_64 WSL result:

- `build/ARM64/packer`: ARM aarch64 ELF
- `build/ARM64/loader`: ARM aarch64 ELF, statically linked
- `build/ARM64/stubgen`: ARM aarch64 ELF, statically linked
- `build/X86_X64/packer`: x86-64 ELF
- `build/X86_X64/stubgen`: x86-64 ELF, statically linked

Expected ARM64 Linux result:

- `build/ARM64/packer`: ARM aarch64 ELF
- `build/ARM64/loader`: ARM aarch64 ELF, statically linked
- `build/ARM64/stubgen`: ARM aarch64 ELF, statically linked

## Packing Commands

### Pack ARM64 ELF on x86_64 WSL

Use this in the current local WSL environment:

```bash
make pack INPUT=/path/to/input_arm64_elf OUTPUT=/path/to/output_packed_arm64_elf
```

Equivalent direct commands:

```bash
./build/X86_X64/packer /path/to/input_arm64_elf /tmp/payload.packed
./build/X86_X64/stubgen ./build/ARM64/loader /tmp/payload.packed /path/to/output_packed_arm64_elf
```

Run the generated output on ARM64 Linux:

```bash
chmod +x /path/to/output_packed_arm64_elf
/path/to/output_packed_arm64_elf
```

### Pack ARM64 ELF on ARM64 Linux

```bash
make pack INPUT=/path/to/input_arm64_elf OUTPUT=/path/to/output_packed_arm64_elf
./output_packed_arm64_elf
```

Equivalent direct commands:

```bash
./build/ARM64/packer /path/to/input_arm64_elf /tmp/payload.packed
./build/ARM64/stubgen ./build/ARM64/loader /tmp/payload.packed /path/to/output_packed_arm64_elf
```

## Validation Evidence

### Local x86_64 WSL

Commands run successfully:

```bash
make clean
make all
make verify-build
make test
```

The smoke test packed `build/ARM64/loader` using the x86_64 host tools and
verified the generated output as ARM64 ELF.

Observed file types:

```text
build/ARM64/packer:    ELF 64-bit LSB pie executable, ARM aarch64
build/ARM64/loader:    ELF 64-bit LSB executable, ARM aarch64, statically linked
build/ARM64/stubgen:   ELF 64-bit LSB executable, ARM aarch64, statically linked
build/X86_X64/packer:  ELF 64-bit LSB pie executable, x86-64
build/X86_X64/stubgen: ELF 64-bit LSB executable, x86-64, statically linked
```

### ARM64 Linux Server

Test directory:

```text
/root/hARMless-codex-test
```

Commands run successfully:

```bash
make clean
make all
make verify-build
make test-runtime
```

Runtime test result:

- `/bin/ls` was packed on ARM64 Linux.
- The packed executable ran successfully.
- Version output matched the original `/bin/ls`.
- Basic `ls /` behavior matched the original command.

Observed ARM64 file types:

```text
build/ARM64/packer:  ELF 64-bit LSB pie executable, ARM aarch64
build/ARM64/loader:  ELF 64-bit LSB executable, ARM aarch64, statically linked
build/ARM64/stubgen: ELF 64-bit LSB executable, ARM aarch64, statically linked
```

## Integration Guidance for Another Project

Recommended integration mode:

1. Keep this repository as a tool submodule or external tool directory.
2. Build it once per target environment with `make all`.
3. From the consuming project, call `make pack` or call `packer` and `stubgen`
   directly.
4. Treat the packed output as an ARM64 Linux executable artifact.

Minimal wrapper command for x86_64 WSL:

```bash
HARMLESS_ROOT=/path/to/hARMless
"$HARMLESS_ROOT/build/X86_X64/packer" "$INPUT_ARM64_ELF" "$OUTPUT_ARM64_ELF.packed"
"$HARMLESS_ROOT/build/X86_X64/stubgen" \
  "$HARMLESS_ROOT/build/ARM64/loader" \
  "$OUTPUT_ARM64_ELF.packed" \
  "$OUTPUT_ARM64_ELF"
rm -f "$OUTPUT_ARM64_ELF.packed"
```

Minimal wrapper command for ARM64 Linux:

```bash
HARMLESS_ROOT=/path/to/hARMless
"$HARMLESS_ROOT/build/ARM64/packer" "$INPUT_ARM64_ELF" "$OUTPUT_ARM64_ELF.packed"
"$HARMLESS_ROOT/build/ARM64/stubgen" \
  "$HARMLESS_ROOT/build/ARM64/loader" \
  "$OUTPUT_ARM64_ELF.packed" \
  "$OUTPUT_ARM64_ELF"
rm -f "$OUTPUT_ARM64_ELF.packed"
```

The consuming project should validate input with `file` before calling the
packer:

```bash
file "$INPUT_ARM64_ELF" | grep -q "ARM aarch64"
```

## Runtime and Output Notes

- The packed output is a standalone ARM64 ELF executable.
- `stubgen` strips section headers from the generated output.
- Each generated output receives randomized polymorphic material, including:
  - random magic value
  - randomized loader filler
  - randomized padding
  - syscall-table re-keying
  - string-block re-keying
  - packed-header blinding
- The packed executable self-deletes when run, so tests regenerate it before
  each execution check.

## Boundaries

- Current supported payload target: ARM64 ELF.
- Current x86_64 support is for host-side packing tools, not for producing
  x86-64 packed payloads in this handoff.
- No credentials are required by the consuming project.
- Temporary files should be kept under the consuming project's own temp
  directory or under this repository's `.codex_tmp` if testing inside this repo.

## Quick Acceptance Checklist

For a consuming project, acceptance is complete when these pass:

```bash
make -C /path/to/hARMless all
make -C /path/to/hARMless verify-build
make -C /path/to/hARMless pack \
  INPUT=/path/to/input_arm64_elf \
  OUTPUT=/path/to/output_packed_arm64_elf
file /path/to/output_packed_arm64_elf | grep -q "ARM aarch64"
```

On ARM64 Linux, also run:

```bash
/path/to/output_packed_arm64_elf
```
