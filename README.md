# 🛡️ hARMless

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-ARM64%20%7C%20x86--64%20Linux-green.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Stars](https://img.shields.io/github/stars/litemars/hARMless?style=social)

**An ELF Packer/Loader for ARM64 and x86-64 Linux Binaries**

A comprehensive security research tool that encrypts ARM64 or x86-64 ELF executables using AES-256-CTR and provides runtime in-memory execution without writing the original binary to disk.

---

## Features

- **Multi-Architecture ELF Support**: ARM64 (AArch64) and x86-64 Linux binaries; target selected automatically or with `ARCH=arm64` / `ARCH=x86_64`
- **AES-256-CTR Encryption**: Encrypts the complete payload with a fresh key and IV for every packed file
- **Fileless Execution**: Tries `memfd_create` first and automatically falls back to the anonymous ELF mapper when memfd execution is unavailable
- **Code Obfuscation**: Advanced obfuscation techniques for anti-analysis
- **CRC32 Corruption Check**: Verifies the decrypted payload bytes before execution
- **Embedded Payload**: Packed binaries contain the complete original executable; the loader dynamically links the target system's `libcrypto` by default
- **Core File Suppression**: Sets `RLIMIT_CORE` to zero to suppress ordinary core files
- **Secure Memory Wiping**: Multi-pass memory erasure for sensitive data
- **Selected Raw Syscalls**: Uses encoded Linux syscall numbers for memfd and io_uring operations
- **Optional Self-Deletion**: Deletes the packed launcher by default or keeps it with `SELF_DELETE=0`
- **Polymorphic Loader**: Every packed binary is bytewise unique — randomized magic, filler, padding, and symbol table scrubbing at stub-generation time

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/litemars/hARMless.git
cd hARMless

# Build for the host architecture (auto-detected)
make all

# Override the target architecture (clean before switching)
make clean && make all ARCH=arm64
make clean && make all ARCH=x86_64

# Pack a binary (ARCH must match what the loader was built for)
make pack INPUT=/bin/ls OUTPUT=packed_ls

# Run the packed binary on an x86-64 Linux machine
./packed_ls
```

---

## 📦 Installation

### Prerequisites

- **Linux system** (ARM64 or x86-64) or a cross-compilation toolchain
- **C compiler** — native `cc`/Clang/GCC or the appropriate cross-compiler (see table below)
- **Make**
- **OpenSSL 1.0.1 or later development files** (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on RHEL/CentOS/AlmaLinux, or `openssl` on Termux) — AES-256-CTR and random generation use EVP and `RAND_bytes()`
- **pkg-config** (`pkgconfig` on CentOS 6, `pkgconf-pkg-config` on newer RHEL-family systems; recommended for locating OpenSSL outside standard paths)
- **Standard development tools** (`git`, `build-essential`)

| Host → Target | Compiler needed |
|---------------|----------------|
| x86-64 → x86-64 | `gcc` (native) |
| ARM64 → ARM64 | `gcc` (native) |
| x86-64 → ARM64 | `aarch64-linux-gnu-gcc` |
| ARM64 → x86-64 | `x86_64-linux-gnu-gcc` |

### Build Steps

```bash
# 1. Clone the repository
git clone https://github.com/litemars/hARMless.git
cd hARMless

# 2a. Build for the host architecture
make all

# 2b. Build for x86-64 instead
make clean && make all ARCH=x86_64

# Optional: static memfd-only loader (requires Linux 3.17+ and static libcrypto/libc)
make clean && make all ARCH=x86_64 STATIC=1 EXEC_METHOD=memfd

# Optional: keep the packed launcher after it runs
make clean && make all ARCH=x86_64 SELF_DELETE=0

# This creates:
# - build/packer    : Binary packer  (validates ELF machine type for chosen ARCH)
# - build/loader    : Stub loader    (compiled for the chosen ARCH)
# - build/stubgen   : Stub generator (host-native, arch-agnostic)
```

### Cross-Compilation

```bash
# x86-64 host → ARM64 target
sudo apt-get install gcc-aarch64-linux-gnu libssl-dev
make all ARCH=arm64

# ARM64 host → x86-64 target
sudo apt-get install gcc-x86-64-linux-gnu libssl-dev
make all ARCH=x86_64

# Or let install-deps handle it:
make install-deps ARCH=x86_64
make all ARCH=x86_64
```

For a cross-build, `TARGET_PKG_CONFIG` must resolve the target architecture's
`libcrypto`, not the host library. Set it to a cross-aware wrapper or configure
its sysroot, for example `TARGET_PKG_CONFIG=aarch64-linux-gnu-pkg-config` when
that wrapper is available.

---

## 📖 Usage

### Basic Packing

```bash
# Pack an ARM64 binary
make pack INPUT=your_arm64_binary OUTPUT=packed_binary

# Alternative: Use tools directly
./build/packer your_arm64_binary packed_data
./build/stubgen ./build/loader packed_data packed_binary
```

### Running Packed Binaries

```bash
# Simply execute the packed binary
./packed_binary

# The packed binary will:
# 1. Run anti-debug and anti-sandbox checks
# 2. Read its own embedded encrypted data
# 3. Decrypt the original ELF in memory
# 4. Check the decrypted payload for corruption with CRC32
# 5. Try memfd, then use direct ELF mapping if memfd is unavailable
# 6. Delete itself from disk when self-deletion is enabled (the default)
```

## Technical Details

### Execution Backends

Choose the execution backend with `EXEC_METHOD=<method>`:

| Method | Behavior | Kernel requirement |
|--------|----------|--------------------|
| `auto` (default) | Try memfd, then direct mapping if it fails | Linux 2.6.32+ on x86-64 |
| `memfd` | Require `memfd_create` and `execve` `/proc/self/fd/<N>` | Linux 3.17+ |
| `direct` | Map the ELF and interpreter into anonymous memory | Linux 2.6.32+ on x86-64 |

ARM64 starts with Linux 3.7; Linux 2.6.32 compatibility is x86-64 only.

### In-Memory Write Paths

`COPY_METHOD` applies to the memfd backend:

| Method | Flag | Kernel requirement |
|--------|------|--------------------|
| `write(2)` | `COPY_METHOD=write` | Any kernel with memfd |
| `mmap` | `COPY_METHOD=mmap` | Any kernel with memfd |
| `io_uring` (default) | `COPY_METHOD=io_uring` | Linux 5.1+; falls back to `write(2)` |

Self-deletion and anti-analysis are enabled by default; use `SELF_DELETE=0` or `ANTI_ANALYSIS=0` to disable them. `STATIC=1` needs the target's static libraries and `EXEC_METHOD=memfd`. Run `make clean` before changing the architecture or any build mode.


### Polymorphic Engine

Every invocation of `stubgen` produces a bytewise-unique packed binary, even when packing the same input:

| Mutation | Mechanism |
|----------|-----------|
| Random magic | 32-bit `g_packed_magic` patched to a fresh value from `/dev/urandom`; packed header is synchronized |
| Random filler | 256-byte `g_pack_polymorph` array in `.data` overwritten with random bytes |
| Random padding | 0–4095 bytes of random junk inserted between loader stub and payload |
| SC table re-keying | `hARMless_sc[]` re-encoded with a fresh random `g_sc_xor_key` so syscall numbers differ in every binary |
| String block re-keying | All 231 obfuscated string bytes in `g_obf_str_block` re-encoded with a fresh random `g_str_xor_key` |
| Header OTP blinding | Pack header body (68 bytes) XOR'd with the first 68 bytes of `g_pack_polymorph` as a one-time pad |
| Symbol scrub | `.symtab`/`.strtab` sections overwritten with random data; ELF section header fields zeroed |

The result: no two packed outputs share the same byte pattern, defeating static hash-based signatures.

### XOR-Obfuscated Syscall Table

Syscall numbers are stored in a `volatile` array (`hARMless_sc[]`) XOR-encoded with the key `0xDEADBEEF` at compile time. At stub-generation time, `stubgen` re-encodes the entire table with a fresh random key written into `g_sc_xor_key`, so syscall numbers differ in every packed binary. They are decoded inline at each call site via `hARMless_sc[i] ^ g_sc_xor_key`, preventing static analysis tools from recovering syscall identifiers.

### XOR-Obfuscated String Block

All anti-debug and process-masquerade strings (tool names, hypervisor signatures, env var names, process titles) are stored in a single contiguous `g_obf_str_block[]` array, XOR-encoded with `g_str_xor_key`. At stub-generation time, `stubgen` re-encodes the entire block with a fresh random byte key, making every binary's string patterns unique and independent of one another.

### Memory Safety

- **Secure Wiping**: 3-pass overwrite (zeros, ones, random) with volatile access to prevent compiler optimization
- **No Disk Writes**: Original binary never touches filesystem
- **Self-Deletion**: Loader calls `unlink()` on itself before executing the payload
- **ASLR Compatible**: PIE payloads and their interpreters are placed in aligned anonymous mappings

---

## Security Features

### Core File Suppression

```c
setrlimit(RLIMIT_CORE, &(struct rlimit){0, 0});
```

This suppresses conventional file-based core dumps from the packed process.

### Integrity Verification

After decryption, the loader computes CRC32 over the payload and compares it with the value stored by the packer. This catches accidental corruption and incorrect decryption before execution. CRC32 is not authenticated tamper protection, and it does not cover the loader code.

### Anti-Analysis

- **No debug symbols**: Stripped binaries; section header table zeroed at stub-generation time
- **Obfuscated control flow**: Reduces reverse engineering surface
- **Obfuscated syscall numbers**: Stored XOR'd with `0xDEADBEEF`, decoded at each call site
- **Selected raw syscalls**: memfd and io_uring use the encoded syscall table; the direct mapper and EVP crypto use libc/libcrypto
- **Noise delays**: CPU-bound xorshift loops seeded from the ASLR stack address; cannot be skipped by sandbox time-acceleration and emit no recognizable timing syscall
- **Process context probes**: `getpid`, `getppid`, and `prctl(PR_GET_NAME)` woven between critical operations; results used in a runtime condition to avoid trivial dead-code elimination by an analyst
- **In-memory execution**: No `/tmp` artifacts

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Original Binary                      │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   Packer (packer.c)   │
         │  - Read ELF           │
         │  - Generate key + IV  │
         │  - Encrypt payload    │
         │  - Compute CRC32      │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Packed Data File     │
         │ [HARMCTR1 header +    │
         │  encrypted payload]   │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │ Stub Generator        │
         │ (stubgen.c)           │
         │  - Patch magic/filler │
         │  - Scrub symbols      │
         │  - Insert padding     │
         │  - Append payload     │
         └───────────┬───────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│              Packed Binary (Output)                    │
│  ┌──────────────────────────────────────────────┐      │
│  │ Loader Stub (loader.c)                       │      │
│  │  - Anti-debug / anti-sandbox checks          │      │
│  │  - Decrypt AES-256-CTR                       │      │
│  │  - Verify CRC32                              │      │
│  │  - Try masqueraded memfd                     │      │
│  │  - Unlink self                               │      │
│  │  - Execute through memfd or direct mapping   │      │
│  └──────────────────────────────────────────────┘      │
│  ┌──────────────────────────────────────────────┐      │
│  │ [random padding] Encrypted Payload + Header  │      │
│  └──────────────────────────────────────────────┘      │
└────────────────────────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   Runtime Execution   │
         │  (in-memory only)     │
         └───────────────────────┘
```

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

**⚠️ Legal Notice**: This tool is intended for:
- Authorized penetration testing
- Security research and education
- Red team operations
- Malware analysis

**Unauthorized use is prohibited and may be illegal.**

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
