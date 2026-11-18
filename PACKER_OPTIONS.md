# Packer and Loader Options

This reference describes the supported build, packing, execution, and
toolchain options. All `make` variables can be placed on the same command as
`make all` or `make pack`.

## Recommended starting point

Build and pack on the same Linux architecture as the input ELF:

```sh
make all
make pack INPUT=/path/to/program OUTPUT=packed_program
./packed_program arg1 arg2
```

The default is `EXEC_METHOD=auto COPY_METHOD=write STATIC=0 SELF_DELETE=0`.
It first tries the direct in-process mapper and uses the most compatible memfd
copy method if direct mapping is unavailable.

The input must be a nonempty ARM64 or x86-64 ELF64 file. `ARCH` must match its
ELF machine type. Packing does not bundle the payload's shared libraries: the
target still needs its native ELF interpreter and shared-library dependencies.

## Main build options

| Variable | Values | Default | Meaning |
|---|---|---|---|
| `ARCH` | `arm64`, `x86_64` | Host architecture | Target architecture of the input, loader, and final output. |
| `EXEC_METHOD` | `auto`, `memfd`, `inplace`, `direct` | `auto` | Selects how the decrypted ELF is executed. `inplace` and `direct` are aliases. |
| `COPY_METHOD` | `write`, `mmap`, `io_uring` | `write` | Selects the memfd copy implementation. Ignored by direct-only builds. |
| `STATIC` | `0`, `1` | `0` | Statically links the loader when set to `1`; requires `EXEC_METHOD=memfd`. |
| `SELF_DELETE` | `0`, `1` | `0` | With `1`, unlinks the packed launcher when it starts. |
| `INPUT` | Input path | None | Required by `make pack`; must be a matching ELF64 executable. |
| `OUTPUT` | Output path | None | Required by `make pack`; names the final executable. |

`SELF_DELETE=1` unlinks the launcher before payload authentication and
execution finish. Use the default `0` while testing a new payload or
configuration.

Kernel-style process identity is currently always enabled and has no build
toggle. At startup the loader selects an encoded name, applies it to
`argv[0]` and Linux `comm` using `PR_SET_NAME`, and uses it as the memfd name.

## Execution methods

### `EXEC_METHOD=auto`

Tries the in-process mapper first. If the input does not meet the direct
mapper's requirements, it falls back to memfd. `COPY_METHOD` controls that
fallback.

```sh
make pack ARCH=x86_64 EXEC_METHOD=auto COPY_METHOD=write \
  INPUT=program OUTPUT=program.packed
```

Use `auto` when payload compatibility is not yet known or when one build must
retain both execution paths. The dynamic loader binary is larger than a
single-backend build because it contains both implementations.

### `EXEC_METHOD=memfd`

Requires `memfd_create`, writes the decrypted ELF to the anonymous file, and
executes `/proc/self/fd/<fd>`. It is the only mode permitted with `STATIC=1`.

```sh
make pack ARCH=arm64 EXEC_METHOD=memfd COPY_METHOD=write \
  INPUT=program OUTPUT=program.memfd
```

### `EXEC_METHOD=inplace` or `EXEC_METHOD=direct`

Maps the payload's `PT_LOAD` segments and, when present, its ELF interpreter
into the current process. It then updates the required auxiliary-vector
entries and transfers control without a second `execve`.

```sh
make pack ARCH=x86_64 EXEC_METHOD=inplace \
  INPUT=program OUTPUT=program.inplace
```

This backend accepts conventional `ET_EXEC` and `ET_DYN` ELF64 files with a
non-executable `PT_GNU_STACK`. `STATIC=1` is rejected because the direct
mapper requires the launcher to be PIE. `COPY_METHOD` has no functional
effect in direct-only mode.

## memfd copy methods

These options affect `EXEC_METHOD=memfd` and the fallback inside
`EXEC_METHOD=auto`.

| `COPY_METHOD` | Operation | Compatibility and behavior |
|---|---|---|
| `write` | Repeated raw `write(2)` calls | Most compatible; handles short writes and `EINTR`. |
| `mmap` | Shared writable mapping plus byte copy | Requires ordinary writable memfd mappings; calls `msync` where `_POSIX_MAPPED_FILES` is available. |
| `io_uring` | One `IORING_OP_WRITE` submission | Requires io_uring, introduced in Linux 5.1; falls back to `write` if ring setup or submission fails. |

Examples:

```sh
make pack EXEC_METHOD=memfd COPY_METHOD=write INPUT=program OUTPUT=out.write
make pack EXEC_METHOD=memfd COPY_METHOD=mmap INPUT=program OUTPUT=out.mmap
make pack EXEC_METHOD=memfd COPY_METHOD=io_uring INPUT=program OUTPUT=out.uring
```

## Static and dynamic loaders

`STATIC=0` builds a PIE loader that dynamically links the target's
`libcrypto` and libc. This is the default and permits `auto`, `memfd`, and
direct execution modes. The destination system must provide compatible
loader libraries in addition to the payload's own dependencies.

`STATIC=1` produces a standalone loader and requires `EXEC_METHOD=memfd`:

```sh
make pack ARCH=x86_64 EXEC_METHOD=memfd STATIC=1 \
  INPUT=program OUTPUT=program.standalone
```

The target compiler, static libc, static `libcrypto`, and their static
dependencies must be installed. A static hARMless loader does not make a
dynamically linked input payload standalone.


To enable loader diagnostics, preserve the default target flags and add
`-DDEBUG`:

```sh
make all TARGET_CFLAGS='-Wall -Wextra -O2 -std=c99 -DDEBUG'
```

The loader then writes short `[hARMless]` messages to standard error. Debug
output changes the resulting loader and is intended for troubleshooting.

## Make targets

| Target | Purpose |
|---|---|
| `make all` | Builds packer, loader, and stubgen for one configuration. |
| `make activate` | Points `build/packer`, `build/loader`, and `build/stubgen` at one existing/built configuration. |
| `make pack INPUT=... OUTPUT=...` | Builds the selected configuration, encrypts the input, and creates the final executable. |
| `make test` | Runs `tests/unit_test.sh` using the active build tools. |
| `make install-deps ARCH=...` | Invokes the detected Linux/Termux package manager to install build dependencies. |
| `make clean` | Removes `build/` plus root-level `*.packed`, `test_*`, and `bench_*` files. |

`install-deps` may run privileged package-manager commands. Inspect the target
before using it on a managed system.


## Configuration recipes

| Goal | Command options |
|---|---|
| Compatibility-first | `EXEC_METHOD=auto COPY_METHOD=write STATIC=0 SELF_DELETE=0` |
| Require memfd | `EXEC_METHOD=memfd COPY_METHOD=write` |
| No second `execve` | `EXEC_METHOD=inplace STATIC=0` |
| Standalone loader | `EXEC_METHOD=memfd STATIC=1` |
| Single-use launcher | Add `SELF_DELETE=1` after validating the payload. |
| io_uring experiment | `EXEC_METHOD=memfd COPY_METHOD=io_uring` |
| Keep multiple builds | Invoke `make all` or `make pack` with each desired option set; configuration directories coexist. |

The direct mapper reduces the operations unique to the memfd path, while the
memfd backend follows Linux's conventional exec transition. The packer's
cryptography and polymorphism change bytes at rest; selection of a backend,
copy method, static linkage, or process name changes runtime behavior rather
than guaranteeing a particular endpoint-security result.
