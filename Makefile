# Compiler detection
UNAME_M := $(shell uname -m)
CC      ?= cc
PKG_CONFIG ?= pkg-config
TARGET_PKG_CONFIG ?= $(PKG_CONFIG)

# Target architecture: defaults to host arch, override with ARCH=arm64 or ARCH=x86_64
ifeq ($(origin ARCH), undefined)
    ifeq ($(UNAME_M),x86_64)
        ARCH := x86_64
    else ifneq ($(filter $(UNAME_M),aarch64 arm64),)
        ARCH := arm64
    else
        $(error Cannot auto-detect ARCH from host '$(UNAME_M)'. Set ARCH=arm64 or ARCH=x86_64 explicitly)
    endif
endif

ifeq ($(ARCH), x86_64)
    ifeq ($(UNAME_M), x86_64)
        TARGET_CC ?= $(CC)                   # native x86-64 build
    else
        TARGET_CC ?= x86_64-linux-gnu-gcc    # cross-compile from ARM64
    endif
    TARGET_ARCH_FLAGS := -DTARGET_X86_64
else ifeq ($(ARCH), arm64)
    ifneq ($(filter $(UNAME_M),aarch64 arm64),)
        TARGET_CC ?= $(CC)                   # native ARM64 build
    else
        TARGET_CC ?= aarch64-linux-gnu-gcc   # cross-compile to ARM64
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

EXEC_METHOD ?= auto
ifeq ($(EXEC_METHOD),auto)
    EXEC_FLAGS :=
else ifeq ($(EXEC_METHOD),memfd)
    EXEC_FLAGS := -DEXEC_MEMFD_ONLY
else ifeq ($(EXEC_METHOD),inplace)
    EXEC_FLAGS := -DEXEC_DIRECT_ONLY
else ifeq ($(EXEC_METHOD),direct)
    EXEC_FLAGS := -DEXEC_DIRECT_ONLY
else
    $(error Unknown EXEC_METHOD '$(EXEC_METHOD)'. Use auto, memfd, inplace, or direct)
endif

COPY_METHOD ?= write
ifneq ($(EXEC_METHOD),inplace)
ifneq ($(EXEC_METHOD),direct)
    ifeq ($(COPY_METHOD),write)
        COPY_FLAGS :=
    else ifeq ($(COPY_METHOD),mmap)
        COPY_FLAGS := -DCOPY_WITH_MMAP
    else ifeq ($(COPY_METHOD),io_uring)
        COPY_FLAGS := -DCOPY_WITH_IO_URING
    else
        $(error Unknown COPY_METHOD '$(COPY_METHOD)'. Use write, mmap, or io_uring)
    endif
else
    # The in-process loader does not build a memfd copy backend.
    COPY_FLAGS :=
endif
else
    COPY_FLAGS :=
endif

SELF_DELETE ?= 0
ifeq ($(SELF_DELETE),1)
    SELF_DELETE_FLAGS :=
else ifeq ($(SELF_DELETE),0)
    SELF_DELETE_FLAGS := -DKEEP_PACKED_FILE
else
    $(error Unknown SELF_DELETE value '$(SELF_DELETE)'. Use 0 or 1)
endif
LOADER_FEATURE_FLAGS := $(EXEC_FLAGS) $(COPY_FLAGS) $(SELF_DELETE_FLAGS)

STATIC ?= 0
OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcrypto 2>/dev/null || echo "")
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs libcrypto 2>/dev/null || echo "-lcrypto")
LOADER_OPENSSL_CFLAGS := $(shell $(TARGET_PKG_CONFIG) --cflags libcrypto 2>/dev/null || echo "")
LOADER_LDFLAGS := $(LDFLAGS)
LOADER_OPENSSL_LIBS := $(shell $(TARGET_PKG_CONFIG) --libs libcrypto 2>/dev/null || echo "-lcrypto")
ifeq ($(STATIC),1)
    ifneq ($(EXEC_METHOD),memfd)
        $(error STATIC=1 requires EXEC_METHOD=memfd because direct mapping needs a PIE loader)
    endif
    LOADER_LDFLAGS += -static
    LOADER_OPENSSL_LIBS := $(shell $(TARGET_PKG_CONFIG) --static --libs libcrypto 2>/dev/null || echo "-lcrypto")
else ifneq ($(STATIC),0)
    $(error Unknown STATIC value '$(STATIC)'. Use 0 or 1)
else
    LOADER_LDFLAGS += -pie
endif

# Security flags
STACK_PROTECTOR_FLAG ?= $(shell printf 'int main(void) { return 0; }\n' | $(CC) -Werror -fstack-protector-strong -x c - -c -o /dev/null >/dev/null 2>&1 && echo -fstack-protector-strong || echo -fstack-protector)
SECURITY_FLAGS := $(STACK_PROTECTOR_FLAG) -D_FORTIFY_SOURCE=2 -fPIE
STEALTH_FLAGS := -fomit-frame-pointer -fno-asynchronous-unwind-tables -fno-stack-protector -fPIE

# Directories
INCLUDE_DIR := include
PACKER_DIR := packer
LOADER_DIR := loader
STUBGEN_DIR := stubgen
BUILD_ROOT := build
BUILD_ID := $(ARCH)-$(EXEC_METHOD)-$(COPY_METHOD)-static$(STATIC)-delete$(SELF_DELETE)
BUILD_DIR := $(BUILD_ROOT)/$(BUILD_ID)

# Output binaries
PACKER_BIN := $(BUILD_DIR)/packer
LOADER_BIN := $(BUILD_DIR)/loader
STUBGEN_BIN := $(BUILD_DIR)/stubgen
PROJECT_HEADERS := $(wildcard $(INCLUDE_DIR)/*.h)

# Enhanced source files (including obfuscation)
PACKER_SOURCES := $(PACKER_DIR)/packer.c $(PACKER_DIR)/crypto.c $(PACKER_DIR)/obfuscation.c
LOADER_SOURCES := $(LOADER_DIR)/loader.c $(LOADER_DIR)/memexec.c $(LOADER_DIR)/polymorph.c $(LOADER_DIR)/strings.c $(LOADER_DIR)/textpoly.S $(PACKER_DIR)/elf64.c $(PACKER_DIR)/crypto.c $(PACKER_DIR)/obfuscation.c
ifneq ($(EXEC_METHOD),memfd)
    LOADER_SOURCES += $(LOADER_DIR)/elfexec.c
endif
# stubgen now parses the loader ELF to locate symbols and shares is_elf64
STUBGEN_SOURCES := $(STUBGEN_DIR)/stubgen.c $(PACKER_DIR)/elf64.c

# Include paths
INCLUDES := -I$(INCLUDE_DIR)

.PHONY: all activate clean pack test

# Default target
all: $(PACKER_BIN) $(LOADER_BIN) $(STUBGEN_BIN) activate

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

activate: $(PACKER_BIN) $(LOADER_BIN) $(STUBGEN_BIN)
	ln -sfn $(BUILD_ID)/packer $(BUILD_ROOT)/packer
	ln -sfn $(BUILD_ID)/loader $(BUILD_ROOT)/loader
	ln -sfn $(BUILD_ID)/stubgen $(BUILD_ROOT)/stubgen

# Build packer
$(PACKER_BIN): $(PACKER_SOURCES) $(PROJECT_HEADERS) Makefile | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) $(TARGET_ARCH_FLAGS) $(OPENSSL_CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $(PACKER_SOURCES) $(OPENSSL_LIBS) $(LDLIBS)

# Build loader
$(LOADER_BIN): $(LOADER_SOURCES) $(PROJECT_HEADERS) Makefile | $(BUILD_DIR)
	$(TARGET_CC) $(TARGET_CFLAGS) $(LOADER_FEATURE_FLAGS) $(STEALTH_FLAGS) $(TARGET_ARCH_FLAGS) $(LOADER_OPENSSL_CFLAGS) $(INCLUDES) $(LOADER_LDFLAGS) -o $@ $(LOADER_SOURCES) $(LOADER_OPENSSL_LIBS) $(LDLIBS)

# Build stub generator
$(STUBGEN_BIN): $(STUBGEN_SOURCES) $(PROJECT_HEADERS) Makefile | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $(STUBGEN_SOURCES) $(LDLIBS)

# Advanced packing presets
pack: $(PACKER_BIN) $(LOADER_BIN) $(STUBGEN_BIN) activate
	@if [ -z "$(INPUT)" ] || [ -z "$(OUTPUT)" ]; then \
		echo "Usage: make pack INPUT=<binary> OUTPUT=<output>"; \
		exit 1; \
	fi
	$(PACKER_BIN) $(INPUT) $(OUTPUT).packed
	$(STUBGEN_BIN) $(LOADER_BIN) $(OUTPUT).packed $(OUTPUT)
	@echo "Output packed binary created: $(OUTPUT)"

# Clean build artifacts
clean:
	rm -rf $(BUILD_ROOT)
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
		sudo yum install -y gcc openssl-devel pkgconfig file; \
	elif command -v pacman >/dev/null 2>&1; then \
		sudo pacman -S gcc openssl pkgconf file; \
	else \
		echo "Please install cross-compilation and OpenSSL tools manually"; \
	fi
