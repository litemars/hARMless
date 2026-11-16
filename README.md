# 🛡️ hARMless

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-ARM64%20%7C%20x86--64%20Linux-green.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Stars](https://img.shields.io/github/stars/litemars/hARMless?style=social)



**An ELF Packer/Loader for ARM64 and x86-64 Linux Binaries**

A security research ELF packer that uses authenticated AES-256-GCM encryption
and executes through direct anonymous mapping or an optional memfd backend.

---

## Features

- **Multi-Architecture ELF Support**: ARM64 and x86-64 Linux; target defaults to the host architecture
- **AES-256-GCM Encryption**: One authenticated, in-place pass with a fresh key and IV per output
- **Memory Execution**: Anonymous ELF mapping by default with a memfd fallback
- **Code Variation**: Per-output executable instruction block, magic, syscall table, filler and padding
- **Authenticated Payload**: Verifies the GCM tag before transferring control
- **Embedded Payload**: Packed binaries contain the complete original executable; the default loader uses the target system's `libcrypto` (use `STATIC=1 EXEC_METHOD=memfd` for a standalone loader)
- **Core File Suppression**: Sets `RLIMIT_CORE` to zero
- **Secure Memory Wiping**: Multi-pass memory erasure for sensitive data
- **Selected Raw Syscalls**: memfd and io_uring operations use encoded syscall numbers
- **Optional Self-Deletion**: Keeps the launcher by default; use `SELF_DELETE=1` for single-use output
- **Polymorphic Loader**: Every packed binary is bytewise unique — randomized magic, filler, padding, and symbol table scrubbing at stub-generation time

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/litemars/hARMless.git
cd hARMless

# Build for the host architecture (auto-detected)
make all

# Build another configuration; outputs coexist under build/
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
- **C compiler** — native `cc`/Clang/GCC or the appropriate cross-compiler (see table below)
- **Make**
- **OpenSSL 1.0.1 or later development files** (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on RHEL/CentOS/AlmaLinux, or `openssl` on Termux)
- **pkg-config** (`pkgconfig` on CentOS 6, `pkgconf-pkg-config` on newer RHEL-family systems)
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

# 2b. Build for x86-64
make all ARCH=x86_64

# Optional: build a fully static memfd-only loader
make all ARCH=x86_64 STATIC=1 EXEC_METHOD=memfd

# Optional: delete the packed launcher after it runs
make all ARCH=x86_64 SELF_DELETE=1

# Optional: omit memfd/io_uring and map the ELF in the current process
make all ARCH=x86_64 EXEC_METHOD=inplace

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

# Force in-process execution instead of memfd
make pack ARCH=x86_64 EXEC_METHOD=inplace INPUT=your_binary OUTPUT=packed_direct

# Alternative: Use tools directly
./build/packer your_arm64_binary packed_data
./build/stubgen ./build/loader packed_data packed_binary
```

### Running Packed Binaries

```bash
# Simply execute the packed binary
./packed_binary

# The packed binary will:
# 1. Open and read its embedded encrypted data
# 2. Optionally unlink the launcher when built with SELF_DELETE=1
# 3. Authenticate and decrypt the original ELF in memory
# 4. Map the ELF/interpreter directly, falling back to memfd when needed
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

The packer encrypts the payload with AES-256-GCM using a fresh 256-bit key and
96-bit IV from OpenSSL `RAND_bytes()` for every output. Decryption is performed
in place and the 128-bit authentication tag is verified before execution.
The key is embedded in the packed file, so this is payload authentication and
corruption detection rather than publisher identity or code signing.
The `HARMGCM1` wire format uses an 80-byte header; `.packed` intermediates
created by earlier versions must be regenerated.


### Execution Backends

Select the execution backend at build time:

| Method | Flag | Input support |
|--------|------|---------------|
| auto (default) | `EXEC_METHOD=auto` | Try in-process mapping, then memfd |
| memfd | `EXEC_METHOD=memfd` | Require memfd execution |
| in-process | `EXEC_METHOD=inplace` or `direct` | Map the ELF and its native interpreter anonymously |

The in-process backend maps `PT_LOAD` segments and the payload's native
interpreter, updates the required auxiliary-vector entries, clears the old TLS
base and transfers control using the existing Linux initial stack. It does not
invoke memfd, io_uring, `/proc/self/fd`, or a second `execve`. Unlike a real
`execve`, it does not reset process credentials, signal state, namespaces or
seccomp state.

### memfd Write Paths

When `EXEC_METHOD=auto` falls back to memfd, or `EXEC_METHOD=memfd` is selected,
three methods are available for copying the decrypted ELF:

| Method | Flag | Kernel Requirement |
|--------|------|--------------------|
| `write(2)` (default) | `COPY_METHOD=write` | Any kernel with memfd |
| `mmap` | `COPY_METHOD=mmap` | Any kernel with memfd |
| `io_uring` | `COPY_METHOD=io_uring` | ≥ 5.1; automatically falls back to `write(2)` |

For example:

```bash
# Use the conventional and most compatible memfd copy method
make all EXEC_METHOD=memfd COPY_METHOD=write

# Select either alternate memfd copy method
make all EXEC_METHOD=memfd COPY_METHOD=mmap
make all EXEC_METHOD=memfd COPY_METHOD=io_uring
```

The default build links the loader dynamically so it works with the ordinary
OpenSSL development packages shipped by RHEL, AlmaLinux, Debian, and Termux.
Use `STATIC=1` only when the target's static `libcrypto` and libc archives are
installed. `STATIC=1` requires `EXEC_METHOD=memfd`. Self-deletion is disabled
by default; build with `SELF_DELETE=1` for single-use output.

Each configuration is stored below
`build/<ARCH>-<EXEC_METHOD>-<COPY_METHOD>-static<0|1>-delete<0|1>/`. Stable
`build/packer`, `build/loader` and `build/stubgen` symlinks point at the most
recent `make all` or `make pack` configuration. `make pack` always uses the requested
configuration directly, so changing build options no longer requires cleaning.

### Polymorphic Engine

Every invocation of `stubgen` produces a bytewise-unique packed binary, even when packing the same input:

| Mutation | Mechanism |
|----------|-----------|
| Random magic | 32-bit `g_packed_magic` patched to a fresh value from `/dev/urandom`; packed header is synchronized |
| Random filler | 256-byte `g_pack_polymorph` array in `.data` overwritten with random bytes |
| Random padding | 0–4095 bytes of random junk inserted between loader stub and payload |
| SC table re-keying | `hARMless_sc[]` re-encoded with a fresh random `g_sc_xor_key` so syscall numbers differ in every binary |
| Header OTP blinding | 76-byte header body XOR'd with `g_pack_polymorph` bytes |
| Executable mutation | 512 executed bytes regenerated as architecture-safe instruction variants |
| Symbol scrub | `.symtab`/`.strtab` sections overwritten with random data; ELF section header fields zeroed |

The result defeats exact-file hash matching and changes executable bytes. Most
of the loader implementation remains structurally recognizable to deeper
static analysis.

### XOR-Obfuscated Syscall Table

Syscall numbers are stored in a `volatile` table XOR-encoded at compile time.
`stubgen` re-keys that table in every packed output, changing its stored bytes;
the values are still recoverable by a determined static analyst.

### Memory Safety

- **Secure Wiping**: 3-pass overwrite (zeros, ones, random) with volatile access to prevent compiler optimization
- **No Disk Writes**: Original binary never touches filesystem
- **Optional Self-Deletion**: Launcher is only unlinked with `SELF_DELETE=1`
- **ASLR Compatible**: PIE targets and interpreters use aligned anonymous mappings

---

## Security Properties

### Core File Suppression

```c
setrlimit(RLIMIT_CORE, &(struct rlimit){0, 0});
```

Suppresses ordinary file-based core dumps. Privileged collection and
endpoint memory telemetry remain outside this process-level control.

### Payload Authentication

AES-256-GCM detects corrupt or modified ciphertext before execution. It does
not authenticate the loader code and, because the payload key is embedded,
does not replace a publisher signature or platform allowlisting.

### Analysis Surface

- **No debug symbols**: Stripped binaries; section header table zeroed at stub-generation time
- **Obfuscated syscall numbers**: Stored XOR'd with `0xDEADBEEF`, decoded at each call site
- **Selected raw syscalls**: memfd and io_uring do not depend on libc wrappers
- **In-memory execution**: No `/tmp` artifacts
- **Stable identity**: Does not enumerate debuggers/VMs or masquerade as a kernel thread

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
         │  - Generate key/IV    │
         │  - AES-GCM encrypt    │
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
│  │  - Authenticate/decrypt AES-256-GCM          │      │
│  │  - Optional unlink                          │      │
│  │  - Direct mapping with memfd fallback        │      │
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
