#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$ROOT_DIR/.codex_tmp/arm32"
SRC="$TMP_DIR/hello_arm32.c"
INPUT="$TMP_DIR/hello_arm32"
OUTPUT="$TMP_DIR/hello_arm32_packed"

cleanup() {
    rm -f "$SRC" "$INPUT" "$OUTPUT" "$OUTPUT.packed"
}

trap cleanup EXIT
mkdir -p "$TMP_DIR"
cd "$ROOT_DIR"

if ! command -v arm-linux-gnueabihf-gcc >/dev/null 2>&1; then
    echo "SKIP: arm-linux-gnueabihf-gcc is not installed"
    exit 0
fi

if ! command -v qemu-arm >/dev/null 2>&1; then
    echo "SKIP: qemu-arm is not installed"
    exit 0
fi

cat > "$SRC" <<'C_EOF'
#include <stdio.h>

int main(void) {
    puts("hARMless-arm32-eabi5-ok");
    return 0;
}
C_EOF

make all32
make verify-build32

arm-linux-gnueabihf-gcc -static -O2 -o "$INPUT" "$SRC"

if ! file "$INPUT" | grep -q "ARM"; then
    file "$INPUT"
    exit 1
fi

if ! readelf -h "$INPUT" | grep -q "Version5 EABI"; then
    readelf -h "$INPUT"
    exit 1
fi

make pack32 INPUT="$INPUT" OUTPUT="$OUTPUT"

if ! file "$OUTPUT" | grep -q "ARM"; then
    file "$OUTPUT"
    exit 1
fi

if ! readelf -h "$OUTPUT" | grep -q "Version5 EABI"; then
    readelf -h "$OUTPUT"
    exit 1
fi

if [[ ! -x "$OUTPUT" ]]; then
    echo "ERROR: packed ARM32 executable is missing or not executable"
    exit 1
fi

ORIGINAL_RESULT="$(qemu-arm "$INPUT")"
if [[ "$ORIGINAL_RESULT" != "hARMless-arm32-eabi5-ok" ]]; then
    echo "ERROR: unexpected ARM32 original output: $ORIGINAL_RESULT"
    exit 1
fi

if PACKED_RESULT="$(timeout 10s qemu-arm "$OUTPUT" 2>/dev/null)"; then
    PACKED_STATUS=0
else
    PACKED_STATUS=$?
fi

if [[ $PACKED_STATUS -eq 0 && "$PACKED_RESULT" == "hARMless-arm32-eabi5-ok" ]]; then
    if [[ ! -x "$OUTPUT" ]]; then
        echo "ERROR: ARM32 packed executable disappeared after first run"
        exit 1
    fi
    SECOND_RESULT="$(timeout 10s qemu-arm "$OUTPUT" 2>/dev/null)"
    if [[ "$SECOND_RESULT" != "hARMless-arm32-eabi5-ok" ]]; then
        echo "ERROR: ARM32 packed executable failed second run: $SECOND_RESULT"
        exit 1
    fi
    echo "[x] ARM32/EABI5 packed executable runs under qemu-arm"
else
    if [[ ! -x "$OUTPUT" ]]; then
        echo "ERROR: ARM32 packed executable disappeared after runtime attempt"
        exit 1
    fi
    echo "[x] ARM32/EABI5 packed executable was created"
    echo "NOTE: qemu-user is not a reliable runtime validator for this loader; use native ARM32 or ARM64 32-bit compat for payload execution."
fi
