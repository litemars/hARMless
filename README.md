# hARMless

[Changes from upstream](CHANGES_FROM_UPSTREAM.md) | [相对原版的差异与升级点](CHANGES_FROM_UPSTREAM.zh-CN.md)

ELF packer/loader for Linux security research. This checkout supports the
current integration targets:

- ARM64 ELF packing.
- ARM32/EABI5 ELF packing.
- x86_64 WSL host-side packing tools for both targets.

## Build Outputs

Run from the repository root:

```bash
make all      # ARM64 target
make all32    # ARM32/EABI5 target
```

Output layout:

| Directory | Platform | Purpose |
| --- | --- | --- |
| `build/ARM64` | ARM64 Linux | ARM64 packer, loader, and stubgen |
| `build/ARM32_EABI5` | ARM32 Linux EABI5 | ARM32 packer, loader, and stubgen |
| `build/X86_X64` | x86_64 Linux/WSL | Host-native packers and stubgen |

On x86_64 WSL:

- `build/X86_X64/packer` packs ARM64 ELF payloads.
- `build/X86_X64/packer-arm32` packs ARM32/EABI5 ELF payloads.
- `build/X86_X64/stubgen` combines packed data with either target loader.

## Dependencies

### x86_64 Ubuntu/WSL

ARM64 target dependencies:

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

ARM32/EABI5 target dependencies:

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

Project targets are also available:

```bash
make install-deps
make install-deps32
```

## Build And Verify

ARM64:

```bash
make clean
make all
make verify-build
make test
```

ARM32/EABI5:

```bash
make all32
make verify-build32
make test32
```

`make test32` is a local build/pack/format smoke test. `qemu-user` is not a
reliable runtime validator for the packed loader because `/proc/self/exe` and
anti-analysis checks can differ from native execution. Use native ARM32 Linux or
ARM64 Linux with 32-bit ARM compat enabled for payload runtime validation.

## Pack Commands

### Pack ARM64 ELF On x86_64 WSL

```bash
make pack INPUT=/path/to/input_arm64_elf OUTPUT=/path/to/output_packed_arm64_elf
```

Equivalent direct commands:

```bash
./build/X86_X64/packer /path/to/input_arm64_elf /tmp/payload.packed
./build/X86_X64/stubgen ./build/ARM64/loader /tmp/payload.packed /path/to/output_packed_arm64_elf
```

### Pack ARM32/EABI5 ELF On x86_64 WSL

```bash
make pack32 INPUT=/path/to/input_arm32_eabi5_elf OUTPUT=/path/to/output_packed_arm32_eabi5_elf
```

Equivalent direct commands:

```bash
./build/X86_X64/packer-arm32 /path/to/input_arm32_eabi5_elf /tmp/payload.packed
./build/X86_X64/stubgen ./build/ARM32_EABI5/loader /tmp/payload.packed /path/to/output_packed_arm32_eabi5_elf
```

### Native Target Hosts

On ARM64 Linux:

```bash
make all
make pack INPUT=/path/to/input_arm64_elf OUTPUT=/path/to/output_packed_arm64_elf
```

On ARM32/EABI5 Linux:

```bash
make all32
make pack32 INPUT=/path/to/input_arm32_eabi5_elf OUTPUT=/path/to/output_packed_arm32_eabi5_elf
```

## Validation Status

Validated on x86_64 WSL:

- ARM64 cross-build and pack smoke test.
- ARM32/EABI5 cross-build and pack smoke test.
- Output format checks for `ARM aarch64` and `ARM, EABI5`.

Validated on an ARM64 Linux server:

- ARM64 packed `/bin/ls` runs successfully and matches original behavior.
- ARM32/EABI5 static payload runs directly through the server's 32-bit ARM
  compatibility layer.
- ARM32/EABI5 packed payload runs and writes the expected runtime marker.

## Technical Notes

- AES layer uses AES-256-CTR to preserve payload length for arbitrary ELF sizes.
- Additional encryption layers remain ChaCha20 and RC4.
- `stubgen` supports both ELF32 and ELF64 loaders.
- Packed outputs receive randomized magic, filler, padding, syscall-table
  re-keying, string-block re-keying, header blinding, and section-header strip.
- Temporary test artifacts are written under `.codex_tmp`.

## Legal Notice

This tool is intended for authorized security research, controlled red-team
testing, and education. Unauthorized use against systems or software you do not
own or have permission to test may be illegal.

## License

MIT. See `LICENSE`.
