# 🛡️ hARMless

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-ARM64%20%7C%20x86--64%20Linux-green.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Stars](https://img.shields.io/github/stars/litemars/hARMless?style=social)



**An ELF Packer/Loader for ARM64 and x86-64 Linux Binaries**

A comprehensive security research tool that encrypts ARM64 or x86-64 ELF executables using multi-layer encryption and provides runtime in-memory execution without writing the original binary to disk.

---

## Features

- **Multi-Architecture ELF Support**: ARM64 (AArch64) and x86-64 Linux binaries; target selected at build time with `ARCH=arm64` (default) or `ARCH=x86_64`
- **Multi-Layer Encryption**: Triple encryption using AES-256, ChaCha20, and RC4
- **Memory Execution**: Runtime decryption and execution entirely in memory using `memfd_create`
- **Code Obfuscation**: Advanced obfuscation techniques for anti-analysis
- **CRC32 Verification**: Integrity checking to detect tampering
- **Self-Contained**: Packed binaries are completely standalone
- **Core Dump Prevention**: Prevents memory dumps using `setrlimit`
- **Secure Memory Wiping**: Multi-pass memory erasure for sensitive data
- **Direct Syscalls**: Bypasses userland hooks for enhanced stealth
- **Polymorphic Loader**: Every packed binary is bytewise unique — randomized magic, filler, padding, and symbol table scrubbing at stub-generation time

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/litemars/hARMless.git
cd hARMless

# Build for the host architecture (auto-detected)
make all

# Override to cross-compile for a different target
make all ARCH=arm64
make all ARCH=x86_64

# Pack a binary (ARCH must match what the loader was built for)
make pack INPUT=/bin/ls OUTPUT=packed_ls

# Run the packed binary on an x86-64 Linux machine
./packed_ls
```

---

## 📦 Installation

### Prerequisites

- **Linux system** (ARM64 or x86-64) or a cross-compilation toolchain
- **GCC** — native or the appropriate cross-compiler (see table below)
- **Make**
- **OpenSSL** (`libssl-dev`) — required for AES-256 and ChaCha20 via the EVP API
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

# 2a. Build for ARM64 (default)
make all

# 2b. Build for x86-64
make all ARCH=x86_64

# This creates:
# - build/packer    : Binary packer  (validates ELF machine type for chosen ARCH)
# - build/loader    : Stub loader    (compiled for the chosen ARCH)
# - build/stubgen   : Stub generator (host-native, arch-agnostic)
```

### Cross-Compilation

```bash
# x86-64 host → ARM64 target (existing behaviour, ARCH=arm64 is the default)
sudo apt-get install gcc-aarch64-linux-gnu libssl-dev
make all ARCH=arm64

# ARM64 host → x86-64 target
sudo apt-get install gcc-x86-64-linux-gnu libssl-dev
make all ARCH=x86_64

# Or let install-deps handle it:
make install-deps ARCH=x86_64
make all ARCH=x86_64
```

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
# 4. Verify integrity with CRC32
# 5. Create a masqueraded memfd and write the ELF into it
# 6. Delete itself from disk (unlink)
# 7. Execute directly from memory via /proc/self/fd/<memfd>
```

### Test

```bash
# Testing using /bin/ls

make test
# Output: packed_binary: packed_ls

```

---

## Technical Details

### Encryption Pipeline

The packer uses a **triple-layer encryption** approach:

1. **AES-256-ECB**: First encryption pass (OpenSSL EVP)
2. **ChaCha20**: Modern stream cipher for additional security (OpenSSL EVP)
3. **RC4 Stream Cipher**: Final obfuscation layer

```
Original Binary → AES-256 → ChaCha20 → RC4 → Packed Data
```

**Key Generation**: Cryptographically secure random keys from `/dev/urandom` (256 bits per layer)


### In-Memory Write Paths

Three selectable methods for writing the decrypted ELF into the memfd (chosen at compile time):

| Method | Flag | Kernel Requirement |
|--------|------|--------------------|
| `io_uring` (default) | `-DCOPY_WITH_IO_URING` | ≥ 5.1 |
| `mmap` | `-DCOPY_WITH_MMAP` | Any |
| `write(2)` | (neither flag) | Any |

### Polymorphic Engine

Every invocation of `stubgen` produces a bytewise-unique packed binary, even when packing the same input:

| Mutation | Mechanism |
|----------|-----------|
| Random magic | 32-bit `g_packed_magic` patched to a fresh value from `/dev/urandom`; packed header is synchronized |
| Random filler | 256-byte `g_pack_polymorph` array in `.data` overwritten with random bytes |
| Random padding | 0–4095 bytes of random junk inserted between loader stub and payload |
| SC table re-keying | `hARMless_sc[]` re-encoded with a fresh random `g_sc_xor_key` so syscall numbers differ in every binary |
| String block re-keying | All 241 obfuscated string bytes in `g_obf_str_block` re-encoded with a fresh random `g_str_xor_key` |
| Header OTP blinding | Pack header body (140 bytes) XOR'd with the first 140 bytes of `g_pack_polymorph` as a one-time pad |
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
- **ASLR Compatible**: Position-independent code; random address slot reserved via `mmap(NULL)` before execution

---

## Security Features

### Core Dump Prevention

```c
setrlimit(RLIMIT_CORE, &(struct rlimit){0, 0});
```

Ensures sensitive memory is never written to disk, even during crashes.

### Integrity Verification

CRC32 checksums detect any tampering with:
- Encrypted payload
- Decryption keys
- Loader code

### Anti-Analysis

- **No debug symbols**: Stripped binaries; section header table zeroed at stub-generation time
- **Obfuscated control flow**: Reduces reverse engineering surface
- **Obfuscated syscall numbers**: Stored XOR'd with `0xDEADBEEF`, decoded at each call site
- **Direct syscalls**: Evades LD_PRELOAD and EDR hooks
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
         │  - Generate keys      │
         │  - Triple encrypt     │
         │  - Compute CRC32      │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Packed Data File     │
         │  [encrypted payload]  │
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
│  │  - Decrypt (RC4 → ChaCha20 → AES-256)        │      │
│  │  - Verify CRC32                              │      │
│  │  - Create masqueraded memfd                  │      │
│  │  - Unlink self                               │      │
│  │  - Execute via /proc/self/fd/<N>             │      │
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

