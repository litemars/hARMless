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

if [[ "$(uname -m)" != "aarch64" ]]; then
    make test-runtime > "$LOG" 2>&1
    if ! grep -q "SKIP: ARM64 runtime tests require aarch64 Linux" "$LOG"; then
        cat "$LOG"
        exit 1
    fi
fi
