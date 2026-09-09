# Compiler detection
UNAME_M := $(shell uname -m)
CC      ?= cc
PKG_CONFIG ?= pkg-config
TARGET_PKG_CONFIG ?= $(PKG_CONFIG)

# Target architecture: defaults to host arch, override with ARCH=arm64 or ARCH=x86_64
ifeq ($(UNAME_M), x86_64)
    ARCH ?= x86_64
else ifeq ($(UNAME_M), aarch64)
    ARCH ?= arm64
else
    $(error Cannot auto-detect ARCH from host '$(UNAME_M)'. Set ARCH=arm64 or ARCH=x86_64 explicitly)
endif

ifeq ($(ARCH), x86_64)
    ifeq ($(UNAME_M), x86_64)
        TARGET_CC ?= $(CC)                   # native x86-64 build
    else
        TARGET_CC ?= x86_64-linux-gnu-gcc    # cross-compile from ARM64
    endif
    TARGET_ARCH_FLAGS := -DTARGET_X86_64
else ifeq ($(ARCH), arm64)
    ifeq ($(UNAME_M), x86_64)
        TARGET_CC ?= aarch64-linux-gnu-gcc   # cross-compile from x86-64
    else
        TARGET_CC ?= $(CC)                   # native ARM64 build
    endif
    TARGET_ARCH_FLAGS := -DTARGET_ARM64
else
    $(error Unknown ARCH '$(ARCH)'. Use ARCH=arm64 or ARCH=x86_64)
endif

# Compiler and linker flags
CFLAGS ?= -Wall -Wextra -O2 -std=c99
TARGET_CFLAGS ?= -Wall -Wextra -O2 -std=c99
LDFLAGS ?=
LDLIBS ?=

COPY_METHOD ?= write
ifeq ($(COPY_METHOD),write)
    COPY_FLAGS :=
else ifeq ($(COPY_METHOD),mmap)
    COPY_FLAGS := -DCOPY_WITH_MMAP
else ifeq ($(COPY_METHOD),io_uring)
    COPY_FLAGS := -DCOPY_WITH_IO_URING
else
    $(error Unknown COPY_METHOD '$(COPY_METHOD)'. Use write, mmap, or io_uring)
endif

SELF_DELETE ?= 1
ifeq ($(SELF_DELETE),1)
    SELF_DELETE_FLAGS :=
else ifeq ($(SELF_DELETE),0)
    SELF_DELETE_FLAGS := -DKEEP_PACKED_FILE
else
    $(error Unknown SELF_DELETE value '$(SELF_DELETE)'. Use 0 or 1)
endif
LOADER_FEATURE_FLAGS := $(COPY_FLAGS) $(SELF_DELETE_FLAGS)

STATIC ?= 0
OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcrypto 2>/dev/null || echo "")
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs libcrypto 2>/dev/null || echo "-lcrypto")
LOADER_OPENSSL_CFLAGS := $(shell $(TARGET_PKG_CONFIG) --cflags libcrypto 2>/dev/null || echo "")
LOADER_LDFLAGS := $(LDFLAGS)
LOADER_OPENSSL_LIBS := $(shell $(TARGET_PKG_CONFIG) --libs libcrypto 2>/dev/null || echo "-lcrypto")
ifeq ($(STATIC),1)
    LOADER_LDFLAGS += -static
    LOADER_OPENSSL_LIBS := $(shell $(TARGET_PKG_CONFIG) --static --libs libcrypto 2>/dev/null || echo "-lcrypto")
else ifneq ($(STATIC),0)
    $(error Unknown STATIC value '$(STATIC)'. Use 0 or 1)
endif

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
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) $(TARGET_ARCH_FLAGS) $(OPENSSL_CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $^ $(OPENSSL_LIBS) $(LDLIBS)

# Build loader
$(LOADER_BIN): $(LOADER_SOURCES)
	$(TARGET_CC) $(TARGET_CFLAGS) $(LOADER_FEATURE_FLAGS) $(STEALTH_FLAGS) $(TARGET_ARCH_FLAGS) $(LOADER_OPENSSL_CFLAGS) $(INCLUDES) $(LOADER_LDFLAGS) -o $@ $^ $(LOADER_OPENSSL_LIBS) $(LDLIBS)

# Build stub generator
$(STUBGEN_BIN): $(STUBGEN_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $^ $(LDLIBS)

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
	@if [ -f tests/unit_test.sh ]; then \
		cd tests && SELF_DELETE=$(SELF_DELETE) bash ./unit_test.sh; \
	else \
		echo "No tests found: tests/unit_test.sh"; \
		exit 1; \
	fi

# Install dependencies
install-deps:
	@echo "Installing cross-compilation and OpenSSL dependencies for ARCH=$(ARCH)..."
	@if [ -n "$$TERMUX_VERSION" ] && command -v pkg >/dev/null 2>&1; then \
		pkg install -y clang make pkg-config openssl file; \
	elif command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update && \
		if [ "$(ARCH)" = "x86_64" ] && [ "$(UNAME_M)" != "x86_64" ]; then \
			sudo apt-get install -y gcc-x86-64-linux-gnu binutils-x86-64-linux-gnu libssl-dev pkg-config file; \
		elif [ "$(ARCH)" = "arm64" ] && [ "$(UNAME_M)" = "x86_64" ]; then \
			sudo apt-get install -y gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu libssl-dev pkg-config file; \
		else \
			sudo apt-get install -y gcc libssl-dev pkg-config file; \
		fi; \
	elif command -v yum >/dev/null 2>&1; then \
		sudo yum install -y gcc openssl-devel pkgconf-pkg-config file; \
	elif command -v pacman >/dev/null 2>&1; then \
		sudo pacman -S gcc openssl pkgconf file; \
	else \
		echo "Please install cross-compilation and OpenSSL tools manually"; \
	fi
