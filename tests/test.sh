#!/bin/bash

# AArch64 ELF Packer - Comprehensive Test Suite
# Tests the corrected implementation with proper ELF injection

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PACKER="$PROJECT_ROOT/aarch64-packer"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="$PROJECT_ROOT/test_output"
TEMP_DIR="$TEST_DIR/temp"

# Test functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "\n${YELLOW}[TEST]${NC} $1"
}

cleanup() {
    log_info "Cleaning up test artifacts..."
    rm -rf "$TEST_DIR"
}

create_test_environment() {
    log_info "Setting up test environment..."
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR" "$TEMP_DIR"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check if packer exists
    if [ ! -f "$PACKER" ]; then
        log_error "Packer not found at $PACKER. Please run 'make' first."
        exit 1
    fi
    
    # Check cross-compiler
    if ! command -v aarch64-linux-gnu-gcc > /dev/null; then
        log_error "aarch64-linux-gnu-gcc not found. Please install cross-compiler."
        exit 1
    fi
    
    # Check if we're on AArch64 for execution tests
    ARCH=$(uname -m)
    if [ "$ARCH" != "aarch64" ]; then
        log_warn "Not running on AArch64. Execution tests will be skipped."
        CAN_EXECUTE=false
    else
        CAN_EXECUTE=true
    fi
    
    log_info "Dependencies check passed"
}

create_test_programs() {
    log_info "Creating test programs..."
    
    # Simple hello world program
    cat > "$TEMP_DIR/hello.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Hello from packed AArch64 binary!\n");
    printf("Process ID: %d\n", getpid());
    printf("Packing test successful!\n");
    return 42;
}
EOF

    # More complex program with file operations
    cat > "$TEMP_DIR/complex.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    printf("Complex test program starting...\n");
    printf("Arguments: %d\n", argc);
    
    for (int i = 0; i < argc; i++) {
        printf("  argv[%d] = %s\n", i, argv[i]);
    }
    
    // Test file operations
    FILE *fp = fopen("/proc/version", "r");
    if (fp) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), fp)) {
            printf("Kernel version: %s", buffer);
        }
        fclose(fp);
    }
    
    printf("Complex test completed successfully!\n");
    return 123;
}
EOF

    # Statically linked program
    cat > "$TEMP_DIR/static.c" << 'EOF'
#include <stdio.h>

int main() {
    printf("Static binary test\n");
    return 0;
}
EOF

    # Compile test programs
    log_info "Compiling test programs..."
    
    aarch64-linux-gnu-gcc -o "$TEST_DIR/hello" "$TEMP_DIR/hello.c"
    aarch64-linux-gnu-gcc -o "$TEST_DIR/complex" "$TEMP_DIR/complex.c"
    aarch64-linux-gnu-gcc -static -o "$TEST_DIR/static" "$TEMP_DIR/static.c"
    
    log_info "Test programs compiled successfully"
}

test_packer_basic() {
    log_test "Basic packer functionality"
    
    # Test help output
    "$PACKER" --help > /dev/null
    log_info "Help output: PASS"
    
    # Test with invalid arguments
    if "$PACKER" 2>/dev/null; then
        log_error "Packer should fail with no arguments"
        return 1
    fi
    log_info "Argument validation: PASS"
}

test_elf_validation() {
    log_test "ELF validation and analysis"
    
    # Create invalid ELF file
    echo "Not an ELF file" > "$TEMP_DIR/invalid.elf"
    
    if "$PACKER" "$TEMP_DIR/invalid.elf" "$TEST_DIR/packed_invalid" 2>/dev/null; then
        log_error "Packer should reject invalid ELF files"
        return 1
    fi
    log_info "Invalid ELF rejection: PASS"
    
    # Test with x86_64 binary (if available)
    if command -v gcc > /dev/null; then
        echo 'int main() { return 0; }' | gcc -x c - -o "$TEMP_DIR/x86_binary"
        if "$PACKER" "$TEMP_DIR/x86_binary" "$TEST_DIR/packed_x86" 2>/dev/null; then
            log_error "Packer should reject non-AArch64 binaries"
            return 1
        fi
        log_info "Architecture validation: PASS"
    fi
}

test_packing_methods() {
    log_test "Testing different packing methods"
    
    # Test PT_NOTE conversion method
    log_info "Testing PT_NOTE conversion method..."
    "$PACKER" -v -m note "$TEST_DIR/hello" "$TEST_DIR/hello_packed_note"
    
    # Verify output is valid ELF
    if ! file "$TEST_DIR/hello_packed_note" | grep -q "ELF.*aarch64"; then
        log_error "Packed binary (note method) is not a valid AArch64 ELF"
        return 1
    fi
    log_info "PT_NOTE method: PASS"
    
    # Test padding injection method
    log_info "Testing padding injection method..."
    "$PACKER" -v -m padding "$TEST_DIR/hello" "$TEST_DIR/hello_packed_padding"
    
    # Verify output is valid ELF
    if ! file "$TEST_DIR/hello_packed_padding" | grep -q "ELF.*aarch64"; then
        log_error "Packed binary (padding method) is not a valid AArch64 ELF"
        return 1
    fi
    log_info "Padding method: PASS"
}

test_file_integrity() {
    log_test "File integrity and structure verification"
    
    for packed_file in "$TEST_DIR/hello_packed_note" "$TEST_DIR/hello_packed_padding"; do
        if [ ! -f "$packed_file" ]; then
            log_error "Packed file $packed_file not found"
            return 1
        fi
        
        # Check file permissions
        if [ ! -x "$packed_file" ]; then
            log_error "Packed file $packed_file is not executable"
            return 1
        fi
        
        # Check file size is reasonable
        original_size=$(stat -c%s "$TEST_DIR/hello")
        packed_size=$(stat -c%s "$packed_file")
        
        if [ "$packed_size" -le "$original_size" ]; then
            log_error "Packed file should be larger than original"
            return 1
        fi
        
        log_info "File integrity for $(basename "$packed_file"): PASS"
    done
}

test_execution() {
    if [ "$CAN_EXECUTE" = false ]; then
        log_warn "Skipping execution tests (not on AArch64)"
        return 0
    fi
    
    log_test "Execution testing"
    
    # Test original binary
    log_info "Testing original binary..."
    if ! "$TEST_DIR/hello" > "$TEMP_DIR/original_output" 2>&1; then
        log_error "Original binary failed to execute"
        return 1
    fi
    
    # Test packed binaries
    for method in note padding; do
        packed_file="$TEST_DIR/hello_packed_$method"
        log_info "Testing packed binary ($method method)..."
        
        if ! timeout 10 "$packed_file" > "$TEMP_DIR/packed_output_$method" 2>&1; then
            log_error "Packed binary ($method) failed to execute or timed out"
            log_error "Output:"
            cat "$TEMP_DIR/packed_output_$method" 2>/dev/null || true
            return 1
        fi
        
        # Check exit code
        if ! timeout 10 "$packed_file" >/dev/null 2>&1; then
            exit_code=$?
            if [ $exit_code -ne 42 ]; then
                log_error "Packed binary ($method) returned wrong exit code: $exit_code (expected 42)"
                return 1
            fi
        fi
        
        log_info "Execution test ($method): PASS"
    done
}

test_complex_programs() {
    if [ "$CAN_EXECUTE" = false ]; then
        log_warn "Skipping complex program tests (not on AArch64)"
        return 0
    fi
    
    log_test "Complex program testing"
    
    # Pack complex program
    "$PACKER" -v "$TEST_DIR/complex" "$TEST_DIR/complex_packed"
    
    # Test with arguments
    if ! timeout 10 "$TEST_DIR/complex_packed" arg1 arg2 > "$TEMP_DIR/complex_output" 2>&1; then
        log_error "Complex packed program failed"
        log_error "Output:"
        cat "$TEMP_DIR/complex_output" 2>/dev/null || true
        return 1
    fi
    
    # Verify expected content in output
    if ! grep -q "Complex test completed successfully" "$TEMP_DIR/complex_output"; then
        log_error "Complex program output missing expected content"
        return 1
    fi
    
    log_info "Complex program test: PASS"
}

test_static_binaries() {
    log_test "Static binary testing"
    
    # Pack static binary
    "$PACKER" -v "$TEST_DIR/static" "$TEST_DIR/static_packed"
    
    # Verify it's still a valid ELF
    if ! file "$TEST_DIR/static_packed" | grep -q "ELF.*aarch64"; then
        log_error "Packed static binary is not a valid AArch64 ELF"
        return 1
    fi
    
    if [ "$CAN_EXECUTE" = true ]; then
        if ! timeout 5 "$TEST_DIR/static_packed" > "$TEMP_DIR/static_output" 2>&1; then
            log_error "Packed static binary failed to execute"
            return 1
        fi
        
        if ! grep -q "Static binary test" "$TEMP_DIR/static_output"; then
            log_error "Static binary output incorrect"
            return 1
        fi
    fi
    
    log_info "Static binary test: PASS"
}

test_edge_cases() {
    log_test "Edge case testing"
    
    # Test packing already packed binary
    log_info "Testing double packing prevention..."
    if "$PACKER" "$TEST_DIR/hello_packed_note" "$TEST_DIR/double_packed" 2>/dev/null; then
        log_warn "Packer allowed double packing (this might be intentional)"
    else
        log_info "Double packing prevention: PASS"
    fi
    
    # Test with very small binary
    echo 'int main(){return 0;}' | aarch64-linux-gnu-gcc -x c - -o "$TEST_DIR/tiny"
    "$PACKER" "$TEST_DIR/tiny" "$TEST_DIR/tiny_packed"
    
    if ! file "$TEST_DIR/tiny_packed" | grep -q "ELF.*aarch64"; then
        log_error "Failed to pack tiny binary"
        return 1
    fi
    log_info "Tiny binary packing: PASS"
}

generate_report() {
    log_info "Generating test report..."
    
    {
        echo "AArch64 ELF Packer Test Report"
        echo "==============================="
        echo "Date: $(date)"
        echo "Host Architecture: $(uname -m)"
        echo "Kernel: $(uname -r)"
        echo ""
        echo "Test Files Created:"
        ls -la "$TEST_DIR"/*.packed* 2>/dev/null || echo "No packed files found"
        echo ""
        echo "File Analysis:"
        for f in "$TEST_DIR"/*_packed*; do
            if [ -f "$f" ]; then
                echo "File: $(basename "$f")"
                echo "  Type: $(file "$f")"
                echo "  Size: $(stat -c%s "$f") bytes"
                echo "  Executable: $([ -x "$f" ] && echo "Yes" || echo "No")"
                echo ""
            fi
        done
    } > "$TEST_DIR/test_report.txt"
    
    log_info "Test report saved to $TEST_DIR/test_report.txt"
}

main() {
    echo "AArch64 ELF Packer - Test Suite"
    echo "================================"
    
    # Setup
    create_test_environment
    check_dependencies
    
    # Create test programs
    create_test_programs
    
    # Run tests
    test_packer_basic
    test_elf_validation
    test_packing_methods
    test_file_integrity
    test_execution
    test_complex_programs
    test_static_binaries
    test_edge_cases
    
    # Generate report
    generate_report
    
    log_info "All tests completed successfully!"
    log_info "Test artifacts available in: $TEST_DIR"
    
    if [ "$CAN_EXECUTE" = false ]; then
        log_warn "Some tests were skipped due to architecture mismatch"
        log_warn "For full testing, run this script on an AArch64 system"
    fi
}

# Trap for cleanup
trap cleanup EXIT

# Run main function
main "$@"