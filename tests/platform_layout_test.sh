#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$ROOT_DIR/.codex_tmp"
OUTPUT="$TMP_DIR/platform_layout_packed_loader"
mkdir -p "$TMP_DIR"
trap 'rm -f "$OUTPUT" "$OUTPUT.packed"' EXIT

make clean
make all

for bin in build/ARM64/packer build/ARM64/loader build/ARM64/stubgen; do
    if ! file "$bin" | grep -q "ARM aarch64"; then
        file "$bin" 2>/dev/null || true
        exit 1
    fi
done

if [[ "$(uname -m)" == "x86_64" ]]; then
    for bin in build/X86_X64/packer build/X86_X64/stubgen; do
        if ! file "$bin" | grep -q "x86-64"; then
            file "$bin" 2>/dev/null || true
            exit 1
        fi
    done
fi

make pack INPUT=build/ARM64/loader OUTPUT="$OUTPUT"

if ! file "$OUTPUT" | grep -q "ARM aarch64"; then
    file "$OUTPUT"
    exit 1
fi
