#!/bin/bash

# Simple unit test for hARMless
# Tests packing and execution of /bin/ls

create_packed_binary(){ 
    # The binary self delete every run, thus it needs to recreated for every test
    echo "Generating self-contained executable..."
    echo
    ../build/stubgen ../build/loader test_ls.packed test_ls_packed
    echo 
    if [[ ! -f test_ls_packed ]]; then
        echo "ERROR: Packed executable not created"
        exit 1
    fi
}

set -e

echo "=== hARMless Test ==="
echo "Testing with /bin/ls"
echo

# Detect architecture and set ARCH accordingly
UNAME_M=$(uname -m)
case "$UNAME_M" in
    aarch64)
        ARCH=arm64
        ELF_PATTERN="ARM aarch64"
        ;;
    x86_64)
        ARCH=x86_64
        ELF_PATTERN="x86-64"
        ;;
    *)
        echo "ERROR: Unsupported architecture: $UNAME_M"
        exit 1
        ;;
esac
echo "[x] Detected architecture: $ARCH"
echo

# Check if /bin/ls exists and matches the current architecture
if [[ ! -f /bin/ls ]]; then
    echo "ERROR: /bin/ls not found"
    exit 1
fi

if ! file /bin/ls | grep -q "$ELF_PATTERN"; then
    echo "ERROR: /bin/ls is not a $ARCH binary (file says: $(file /bin/ls))"
    exit 1
fi

echo "[x] Found $ARCH /bin/ls"
echo

# Build the tools
echo "Building tools..."
cd ..
make clean && make all ARCH=$ARCH
cd tests

# Test packing
echo "Packing /bin/ls..."
../build/packer /bin/ls test_ls.packed

if [[ ! -f test_ls.packed ]]; then
    echo "ERROR: Packed file not created"
    exit 1
fi

echo
echo "[x] Created packed file: $(ls -lh test_ls.packed)"
echo

# Test stub generation
create_packed_binary

echo
echo "[x] Created packed executable: $(ls -lh test_ls_packed)"
echo

chmod +x test_ls_packed

# Test execution
echo "Testing execution..."
timeout 10s ./test_ls_packed --version > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    echo
    echo "[x] Packed executable runs successfully"
    echo
else
    echo "ERROR: Packed executable failed to run"
    exit 1
fi

create_packed_binary

# Test that output is similar to original
echo "Comparing output with original..."
ORIGINAL_OUTPUT=$(timeout 5s /bin/ls --version 2>/dev/null | head -1 || echo "ls version output")
PACKED_OUTPUT=$(timeout 5s ./test_ls_packed --version 2>/dev/null | head -1 || echo "packed ls version output")

if [[ "$ORIGINAL_OUTPUT" == "$PACKED_OUTPUT" ]]; then
    echo
    echo "[x] Output matches original"
    echo
else
    echo "WARNING: Output differs from original"
    echo "  Original: $ORIGINAL_OUTPUT"
    echo "  Packed:   $PACKED_OUTPUT"
fi

create_packed_binary

# Test basic functionality
echo "Testing basic ls functionality..."
ORIGINAL_LS=$(timeout 5s /bin/ls / | wc -l)
PACKED_LS=$(timeout 5s ./test_ls_packed / | wc -l)

if [[ $ORIGINAL_LS -eq $PACKED_LS ]]; then
    echo
    echo "[x] Basic functionality works"
    echo
else
    echo "WARNING: Different output count ($ORIGINAL_LS vs $PACKED_LS)"
fi

# Uncomment the below to keep the packed binary
# create_packed_binary

# Cleanup
echo "Cleaning up..."
rm -f test_ls.packed

echo
echo "[x] Test completed successfully."
