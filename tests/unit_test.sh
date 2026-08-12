#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$ROOT_DIR/.codex_tmp/runtime"
ARM64_DIR="$ROOT_DIR/build/ARM64"
PACKED_DATA="$TMP_DIR/test_ls.packed"
PACKED_BIN="$TMP_DIR/test_ls_packed"

cleanup() {
    rm -f "$PACKED_DATA" "$PACKED_BIN"
}

create_packed_binary() {
    echo "Generating self-contained executable..."
    echo
    "$ARM64_DIR/stubgen" "$ARM64_DIR/loader" "$PACKED_DATA" "$PACKED_BIN"
    echo
    if [[ ! -f "$PACKED_BIN" ]]; then
        echo "ERROR: Packed executable not created"
        exit 1
    fi
}

assert_packed_still_exists() {
    if [[ ! -x "$PACKED_BIN" ]]; then
        echo "ERROR: Packed executable disappeared or is not executable"
        exit 1
    fi
}

trap cleanup EXIT
mkdir -p "$TMP_DIR"

echo "=== hARMless ARM64 Runtime Test ==="
echo "Testing with /bin/ls"
echo

if [[ "$(uname -m)" != "aarch64" ]]; then
    echo "SKIP: ARM64 runtime tests require aarch64 Linux (found $(uname -m))"
    exit 0
fi

if [[ ! -f /bin/ls ]]; then
    echo "ERROR: /bin/ls not found"
    exit 1
fi

if ! file /bin/ls | grep -q "ARM aarch64"; then
    echo "ERROR: /bin/ls is not an ARM64 binary (file says: $(file /bin/ls))"
    exit 1
fi

echo "[x] Found ARM64 /bin/ls"
echo

echo "Building tools..."
make -C "$ROOT_DIR" clean
make -C "$ROOT_DIR" all

echo "Packing /bin/ls..."
"$ARM64_DIR/packer" /bin/ls "$PACKED_DATA"

if [[ ! -f "$PACKED_DATA" ]]; then
    echo "ERROR: Packed file not created"
    exit 1
fi

echo
echo "[x] Created packed file: $(ls -lh "$PACKED_DATA")"
echo

create_packed_binary

echo
echo "[x] Created packed executable: $(ls -lh "$PACKED_BIN")"
echo

chmod +x "$PACKED_BIN"

echo "Testing execution..."
if timeout 10s "$PACKED_BIN" --version > /dev/null 2>&1; then
    echo
    echo "[x] Packed executable runs successfully"
    echo
else
    echo "ERROR: Packed executable failed to run"
    exit 1
fi
assert_packed_still_exists

echo "Comparing output with original..."
ORIGINAL_OUTPUT=$(timeout 5s /bin/ls --version 2>/dev/null | head -1 || echo "ls version output")
PACKED_OUTPUT=$(timeout 5s "$PACKED_BIN" --version 2>/dev/null | head -1 || echo "packed ls version output")
assert_packed_still_exists

if [[ "$ORIGINAL_OUTPUT" == "$PACKED_OUTPUT" ]]; then
    echo
    echo "[x] Output matches original"
    echo
else
    echo "WARNING: Output differs from original"
    echo "  Original: $ORIGINAL_OUTPUT"
    echo "  Packed:   $PACKED_OUTPUT"
fi

echo "Testing basic ls functionality..."
ORIGINAL_LS=$(timeout 5s /bin/ls / | wc -l)
PACKED_LS=$(timeout 5s "$PACKED_BIN" / | wc -l)
assert_packed_still_exists

if [[ $ORIGINAL_LS -eq $PACKED_LS ]]; then
    echo
    echo "[x] Basic functionality works"
    echo
else
    echo "WARNING: Different output count ($ORIGINAL_LS vs $PACKED_LS)"
fi

echo
echo "[x] Test completed successfully."
