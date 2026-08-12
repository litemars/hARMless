#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$ROOT_DIR/.codex_tmp"
LOG="$TMP_DIR/runtime-guard.log"
mkdir -p "$TMP_DIR"
trap 'rm -f "$LOG"' EXIT

if ! grep -q '\.codex_tmp' tests/unit_test.sh; then
    echo "ERROR: tests/unit_test.sh must place temporary runtime artifacts under .codex_tmp"
    exit 1
fi

if ! grep -q 'HARMLESS_SELF_DELETE' loader/loader.c; then
    echo "ERROR: loader self-delete must remain behind HARMLESS_SELF_DELETE"
    exit 1
fi

if grep -q '^[[:space:]]*unlink(argv\[0\]);' loader/loader.c; then
    echo "ERROR: loader must not unconditionally unlink argv[0]"
    exit 1
fi

if ! grep -q 'HARMLESS_MASQUERADE_ARGV0' loader/strings.c; then
    echo "ERROR: argv[0] mutation must remain behind HARMLESS_MASQUERADE_ARGV0"
    exit 1
fi

if ! grep -q 'original_size > header->packed_size' loader/loader.c; then
    echo "ERROR: loader must reject an original size larger than the packed payload"
    exit 1
fi

if ! grep -q 'self_size - payload_offset' loader/loader.c; then
    echo "ERROR: loader must validate payload size using bounded subtraction"
    exit 1
fi

if ! grep -q 'UINT32_MAX' packer/packer.c; then
    echo "ERROR: packer must reject inputs larger than the 32-bit header fields"
    exit 1
fi

if ! grep -q '^int aes256_encrypt' include/crypto.h || \
   ! grep -q '^int chacha20_encrypt' include/crypto.h; then
    echo "ERROR: crypto transform failures must be reported to callers"
    exit 1
fi

if ! grep -q 'PACKED_BIN' tests/unit_test.sh || ! grep -q '\[\[ ! -x "$PACKED_BIN" \]\]' tests/unit_test.sh; then
    echo "ERROR: ARM64 runtime test must assert packed executable persistence"
    exit 1
fi

if [[ "$(uname -m)" != "aarch64" ]]; then
    make test-runtime > "$LOG" 2>&1
    if ! grep -q "SKIP: ARM64 runtime tests require aarch64 Linux" "$LOG"; then
        cat "$LOG"
        exit 1
    fi
fi
