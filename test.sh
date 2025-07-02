#!/bin/bash

# Test script for AArch64 packer

set -e

echo "Running AArch64 Packer Tests..."

# Check if we have an AArch64 environment
if [ "$(uname -m)" != "aarch64" ]; then
    echo "Warning: Not running on AArch64, some tests may fail"
fi

# Create test binary
echo "Creating test binary..."
cat > test_program.c << 'EOF'
#include <stdio.h>
#include <string.h>

int main() {
    printf("Hello from packed AArch64 binary!\n");
    printf("Test successful\n");
    return 42;
}
EOF

# Compile test program (statically linked)
if command -v aarch64-linux-gnu-gcc > /dev/null; then
    aarch64-linux-gnu-gcc -static test_program.c -o test_program
else
    gcc -static test_program.c -o test_program
fi

echo "Original binary size: $(stat -c%s test_program) bytes"

# Test packing
echo "Testing packing..."
./aarch64-packer test_program test_program_packed

echo "Packed binary size: $(stat -c%s test_program_packed) bytes"

# Test execution (only if on AArch64)
if [ "$(uname -m)" == "aarch64" ]; then
    echo "Testing packed binary execution..."
    chmod +x test_program_packed
    ./test_program_packed
    
    if [ $? -eq 42 ]; then
        echo "✓ Test passed - packed binary executed successfully"
    else
        echo "✗ Test failed - packed binary returned unexpected exit code"
        exit 1
    fi
else
    echo "Skipping execution test (not on AArch64)"
fi

# Cleanup
rm -f test_program test_program_packed test_program.c

echo "All tests completed successfully!"
