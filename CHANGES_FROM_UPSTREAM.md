# Changes From Upstream

This document describes the maintained differences between this repository and
the upstream [`litemars/hARMless`](https://github.com/litemars/hARMless)
project. The current work is based on upstream commit `46b3630`.

## Upgrade Summary

This fork extends the upstream ARM64-oriented implementation into a repeatable
cross-platform build and packing workflow for both ARM64 and ARM32/EABI5 Linux
ELF executables.

| Area | Upstream baseline | This fork |
| --- | --- | --- |
| Payload targets | ARM64 and upstream x86 work | ARM64 and ARM32/EABI5 integration targets |
| Build host | Primarily target-native | x86_64 WSL cross-build plus target-native builds |
| Output layout | Shared build outputs | Platform-labelled `build/ARM64`, `build/ARM32_EABI5`, and `build/X86_X64` |
| ARM32 ELF | Not supported by the loader/stub pipeline | ELF32 ARM/EABI5 validation, packing, loader, and symbol handling |
| Encryption length | AES mode could change encrypted length | AES-256-CTR preserves the exact payload length |
| Runtime persistence | Loader self-deletes during startup | Packed executables persist by default; self-delete is opt-in |
| Payload argv | Loader can rewrite `argv[0]` during process masquerading | Original `argv[0]` is preserved by default for service compatibility |
| Runtime validation | Payload sizes and crypto/I/O failures were weakly checked | Bounded size validation, 2 GiB input limit, and fail-closed transform handling |
| Verification | Basic project tests | Build-layout, runtime-guard, ARM64, and ARM32/EABI5 smoke tests |
| Integration docs | General project README | Architecture-specific handoff and upgrade documents |

## Main Differences

### ARM32/EABI5 support

- Adds ELF32 structures, ARM machine detection, and target validation.
- Adds ARM EABI direct syscall wrappers and the ARM32 syscall table.
- Adds ELF32 symbol lookup and section scrubbing in `stubgen`.
- Builds a statically linked ARM32/EABI5 loader with
  `arm-linux-gnueabihf`.
- Adds host-native `build/X86_X64/packer-arm32` for packing ARM32 payloads
  from x86_64 Linux or WSL.
- Uses the plain write path for ARM32 instead of the optional `io_uring` path.

The validated ARM32 ABI is hard-float ARMHF, EABI5. Android APK and shared
library packaging are outside the current scope.

### Cross-platform build layout

The Makefile separates executables by runtime platform:

```text
build/ARM64/packer
build/ARM64/loader
build/ARM64/stubgen
build/ARM32_EABI5/packer
build/ARM32_EABI5/loader
build/ARM32_EABI5/stubgen
build/X86_X64/packer
build/X86_X64/packer-arm32
build/X86_X64/stubgen
```

New high-level targets include:

```bash
make all
make verify-build
make pack INPUT=/path/to/arm64.elf OUTPUT=/path/to/arm64.packed

make all32
make verify-build32
make pack32 INPUT=/path/to/arm32-eabi5.elf OUTPUT=/path/to/arm32-eabi5.packed
```

### Payload encryption correction

The AES layer now uses AES-256-CTR with a zero IV. CTR mode keeps ciphertext
length equal to plaintext length, which prevents the stored payload length and
CRC range from diverging for payload sizes that require block padding under
AES-ECB. ChaCha20 and RC4 remain as additional layers.

This changes the packed payload format. A loader and packer from the same
revision should always be used together; previously generated files should be
regenerated when adopting this fork.

### Polymorphic output handling

The existing output randomization flow is applied to both ELF32 and ELF64
loaders. Generated files receive randomized magic and filler data, syscall and
string-table re-keying, packed-header blinding, symbol scrubbing, and section
header removal.

### Audit boundary

The loader now rejects `original_size > packed_size`, checks the packed range
with bounded subtraction before copying, rejects inputs above the 32-bit header
limit, and propagates OpenSSL transform failures instead of continuing with a
possibly unencrypted or partially decrypted buffer.

The format is still an obfuscation layer rather than a strong confidentiality
boundary. Keys are stored in each packed header and the loader necessarily holds
the plaintext ELF in memory before `execve`; the CRC32 is an integrity check for
accidental corruption, not an authenticated-encryption tag. A future protected
asset format should use an external device-bound key and AEAD while preserving a
separate compatibility path for existing packed files.

### Test and integration coverage

The fork adds reusable checks for:

- Platform-labelled build artifacts and executable formats.
- Runtime-test architecture guards.
- ARM64 build and packing from x86_64 WSL.
- ARM32/EABI5 build, packing, and ELF format verification.

Runtime acceptance has also been performed on an ARM64 Linux host:

- A packed ARM64 `/bin/ls` executed and matched the original behavior.
- An ARM32/EABI5 static payload and its packed form both ran through the
  host's 32-bit ARM compatibility layer and produced the expected marker.

`qemu-arm` is useful for basic unprotected executable checks, but it is not the
runtime acceptance environment for the packed loader because self-image and
anti-analysis behavior can differ under user-mode emulation.

## Documentation Added

- `ARM64_PACKER_HANDOFF.md`: ARM64 build, packing, validation, and integration.
- `ARM32_EABI5_HANDOFF.md`: ARM32/EABI5 build, packing, validation, and
  integration.
- `CHANGES_FROM_UPSTREAM.md`: English fork upgrade notes.
- `CHANGES_FROM_UPSTREAM.zh-CN.md`: Chinese fork upgrade notes.

## Upstream Synchronization

Keep `origin` or another dedicated remote pointed at
`litemars/hARMless`. Merge or rebase upstream changes only after running both
architecture test paths, because changes to packed headers, crypto order,
loader markers, or symbol locations affect the packer-loader contract.
