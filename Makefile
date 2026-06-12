# Compiler detection
UNAME_M := $(shell uname -m)
CC      := gcc

# Target architecture: arm64 (default) or x86_64
# Override with: make ARCH=x86_64
ARCH ?= arm64

ifeq ($(ARCH), x86_64)
    ifeq ($(UNAME_M), x86_64)
        TARGET_CC := gcc                     # native x86-64 build
    else
        TARGET_CC := x86_64-linux-gnu-gcc    # cross-compile from ARM64
    endif
    TARGET_ARCH_FLAGS := -DTARGET_X86_64
else ifeq ($(ARCH), arm64)
    ifeq ($(UNAME_M), x86_64)
        TARGET_CC := aarch64-linux-gnu-gcc   # cross-compile from x86-64
    else
        TARGET_CC := gcc                     # native ARM64 build
    endif
    TARGET_ARCH_FLAGS := -DTARGET_ARM64
else
    $(error Unknown ARCH '$(ARCH)'. Use ARCH=arm64 or ARCH=x86_64)
endif

# Compiler flags
CFLAGS := -Wall -Wextra -O2 -std=c99
# Write method: choose one of -DCOPY_WITH_MMAP, -DCOPY_WITH_IO_URING, or neither (plain write syscall)
TARGET_CFLAGS := -Wall -Wextra -O2 -std=c99 -static -DCOPY_WITH_IO_URING
LDFLAGS := -static

# OpenSSL flags - prefer shared libraries to avoid static linking warnings
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null || echo "")
OPENSSL_LDFLAGS := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

# Security flags
SECURITY_FLAGS := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
STEALTH_FLAGS := -fomit-frame-pointer -fno-asynchronous-unwind-tables -fno-stack-protector

# Directories
INCLUDE_DIR := include
PACKER_DIR := packer
LOADER_DIR := loader
STUBGEN_DIR := stubgen
BUILD_DIR := build

# Output binaries
PACKER_BIN := $(BUILD_DIR)/packer
LOADER_BIN := $(BUILD_DIR)/loader
STUBGEN_BIN := $(BUILD_DIR)/stubgen

# Enhanced source files (including obfuscation)
PACKER_SOURCES := $(PACKER_DIR)/packer.c $(PACKER_DIR)/crypto.c $(PACKER_DIR)/obfuscation.c
LOADER_SOURCES := $(LOADER_DIR)/loader.c $(LOADER_DIR)/memexec.c $(LOADER_DIR)/polymorph.c $(LOADER_DIR)/strings.c $(PACKER_DIR)/elf64.c $(PACKER_DIR)/crypto.c $(PACKER_DIR)/obfuscation.c
# stubgen now parses the loader ELF to locate symbols and shares is_elf64
STUBGEN_SOURCES := $(STUBGEN_DIR)/stubgen.c $(PACKER_DIR)/elf64.c

# Include paths
INCLUDES := -I$(INCLUDE_DIR)

# Default target
all: $(BUILD_DIR) $(PACKER_BIN) $(LOADER_BIN) $(STUBGEN_BIN)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build packer
$(PACKER_BIN): $(PACKER_SOURCES)
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) $(TARGET_ARCH_FLAGS) $(OPENSSL_CFLAGS) $(INCLUDES) -o $@ $^ $(OPENSSL_LDFLAGS)

# Build loader
$(LOADER_BIN): $(LOADER_SOURCES)
	$(TARGET_CC) $(TARGET_CFLAGS) $(STEALTH_FLAGS) $(TARGET_ARCH_FLAGS) $(OPENSSL_CFLAGS) $(INCLUDES) -o $@ $^ $(OPENSSL_LDFLAGS) 2>/dev/null || $(TARGET_CC) $(TARGET_CFLAGS) $(STEALTH_FLAGS) $(TARGET_ARCH_FLAGS) $(OPENSSL_CFLAGS) $(INCLUDES) -o $@ $^ $(OPENSSL_LDFLAGS) -lzstd -lz

# Build stub generator
$(STUBGEN_BIN): $(STUBGEN_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# Advanced packing presets
pack: $(PACKER_BIN) $(LOADER_BIN) $(STUBGEN_BIN)
	@if [ -z "$(INPUT)" ] || [ -z "$(OUTPUT)" ]; then \
		echo "Usage: make pack INPUT=<binary> OUTPUT=<output>"; \
		exit 1; \
	fi
	$(PACKER_BIN) $(INPUT) $(OUTPUT).packed
	$(STUBGEN_BIN) $(LOADER_BIN) $(OUTPUT).packed $(OUTPUT)
	@echo "Output packed binary created: $(OUTPUT)"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f *.packed
	rm -f test_* bench_*

test:
	@echo "Running tests..."
	@if [ -x tests/unit_test.sh ]; then \
		cd tests && ./unit_test.sh; \
	else \
		echo "No tests found: tests/unit_test.sh"; \
		exit 1; \
	fi

# Install dependencies
install-deps:
	@echo "Installing cross-compilation and OpenSSL dependencies for ARCH=$(ARCH)..."
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update && \
		if [ "$(ARCH)" = "x86_64" ] && [ "$(UNAME_M)" != "x86_64" ]; then \
			sudo apt-get install -y gcc-x86-64-linux-gnu binutils-x86-64-linux-gnu libssl-dev; \
		elif [ "$(ARCH)" = "arm64" ] && [ "$(UNAME_M)" = "x86_64" ]; then \
			sudo apt-get install -y gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu libssl-dev; \
		else \
			sudo apt-get install -y gcc libssl-dev; \
		fi; \
	elif command -v yum >/dev/null 2>&1; then \
		sudo yum install -y gcc openssl-devel; \
	elif command -v pacman >/dev/null 2>&1; then \
		sudo pacman -S gcc openssl; \
	else \
		echo "Please install cross-compilation and OpenSSL tools manually"; \
	fi