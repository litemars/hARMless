UNAME_M := $(shell uname -m)
TARGET_TRIPLET ?= aarch64-linux-gnu
ARM32_TRIPLET ?= arm-linux-gnueabihf
PKG_CONFIG ?= pkg-config
HOST_CC ?= gcc
TARGET_ARCH_FLAGS := -DTARGET_ARM64
HOST_TARGET_FLAGS := -DTARGET_ARM64
ARM32_TARGET_ARCH_FLAGS := -DTARGET_ARM32

ifeq ($(UNAME_M), x86_64)
    HOST_BUILD_NAME := X86_X64
    TARGET_CC ?= $(TARGET_TRIPLET)-gcc
    TARGET_READELF := $(TARGET_TRIPLET)-readelf
    TARGET_PKG_CONFIG_LIBDIR ?= /usr/lib/$(TARGET_TRIPLET)/pkgconfig
    ARM32_CC ?= $(ARM32_TRIPLET)-gcc
    ARM32_READELF := $(ARM32_TRIPLET)-readelf
    ARM32_PKG_CONFIG_LIBDIR ?= /usr/lib/$(ARM32_TRIPLET)/pkgconfig
else ifeq ($(UNAME_M), aarch64)
    HOST_BUILD_NAME := ARM64
    TARGET_CC ?= $(HOST_CC)
    TARGET_READELF := readelf
    ARM32_CC ?= $(ARM32_TRIPLET)-gcc
    ARM32_READELF := $(ARM32_TRIPLET)-readelf
    ARM32_PKG_CONFIG_LIBDIR ?= /usr/lib/$(ARM32_TRIPLET)/pkgconfig
else
    $(error Cannot auto-detect host '$(UNAME_M)'. Build on x86_64 WSL or ARM64 Linux)
endif

TARGET_PKG_CONFIG_ENV :=
ifneq ($(TARGET_PKG_CONFIG_LIBDIR),)
TARGET_PKG_CONFIG_ENV := PKG_CONFIG_LIBDIR=$(TARGET_PKG_CONFIG_LIBDIR)
endif
ARM32_PKG_CONFIG_ENV :=
ifneq ($(ARM32_PKG_CONFIG_LIBDIR),)
ARM32_PKG_CONFIG_ENV := PKG_CONFIG_LIBDIR=$(ARM32_PKG_CONFIG_LIBDIR)
endif

CFLAGS := -Wall -Wextra -O2 -std=c99
TARGET_CFLAGS := -Wall -Wextra -O2 -std=c99 -static -DCOPY_WITH_IO_URING
ARM32_TARGET_CFLAGS := -Wall -Wextra -O2 -std=c99 -static -marm
LDFLAGS := -static

HOST_OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null || echo "")
HOST_OPENSSL_LDFLAGS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || echo "-lssl -lcrypto")
TARGET_OPENSSL_CFLAGS := $(shell $(TARGET_PKG_CONFIG_ENV) $(PKG_CONFIG) --cflags openssl 2>/dev/null || echo "")
TARGET_OPENSSL_LDFLAGS := $(shell $(TARGET_PKG_CONFIG_ENV) $(PKG_CONFIG) --libs openssl 2>/dev/null || echo "-lssl -lcrypto")
ARM32_OPENSSL_CFLAGS := $(shell $(ARM32_PKG_CONFIG_ENV) $(PKG_CONFIG) --cflags openssl 2>/dev/null || echo "")
ARM32_OPENSSL_LDFLAGS := $(shell $(ARM32_PKG_CONFIG_ENV) $(PKG_CONFIG) --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

SECURITY_FLAGS := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
STEALTH_FLAGS := -fomit-frame-pointer -fno-asynchronous-unwind-tables -fno-stack-protector

INCLUDE_DIR := include
PACKER_DIR := packer
LOADER_DIR := loader
STUBGEN_DIR := stubgen
BUILD_DIR := build
ARM64_BUILD_DIR := $(BUILD_DIR)/ARM64
ARM32_BUILD_DIR := $(BUILD_DIR)/ARM32_EABI5
HOST_BUILD_DIR := $(BUILD_DIR)/$(HOST_BUILD_NAME)
BUILD_DIRS := $(ARM64_BUILD_DIR)
ifneq ($(HOST_BUILD_DIR),$(ARM64_BUILD_DIR))
BUILD_DIRS += $(HOST_BUILD_DIR)
endif

ARM64_PACKER_BIN := $(ARM64_BUILD_DIR)/packer
ARM64_LOADER_BIN := $(ARM64_BUILD_DIR)/loader
ARM64_STUBGEN_BIN := $(ARM64_BUILD_DIR)/stubgen
ARM32_PACKER_BIN := $(ARM32_BUILD_DIR)/packer
ARM32_LOADER_BIN := $(ARM32_BUILD_DIR)/loader
ARM32_STUBGEN_BIN := $(ARM32_BUILD_DIR)/stubgen

ifeq ($(HOST_BUILD_NAME), ARM64)
HOST_PACKER_BIN := $(ARM64_PACKER_BIN)
HOST_ARM32_PACKER_BIN := $(ARM64_BUILD_DIR)/packer-arm32
HOST_STUBGEN_BIN := $(ARM64_STUBGEN_BIN)
HOST_TOOL_BINS :=
HOST_ARM32_TOOL_BINS := $(HOST_ARM32_PACKER_BIN)
else
HOST_PACKER_BIN := $(HOST_BUILD_DIR)/packer
HOST_ARM32_PACKER_BIN := $(HOST_BUILD_DIR)/packer-arm32
HOST_STUBGEN_BIN := $(HOST_BUILD_DIR)/stubgen
HOST_TOOL_BINS := $(HOST_PACKER_BIN) $(HOST_STUBGEN_BIN)
HOST_ARM32_TOOL_BINS := $(HOST_ARM32_PACKER_BIN) $(HOST_STUBGEN_BIN)
endif

PACKER_BIN := $(HOST_PACKER_BIN)
LOADER_BIN := $(ARM64_LOADER_BIN)
STUBGEN_BIN := $(HOST_STUBGEN_BIN)
ALL_BINS := $(ARM64_PACKER_BIN) $(ARM64_LOADER_BIN) $(ARM64_STUBGEN_BIN) $(HOST_TOOL_BINS)
ALL32_BINS := $(ARM32_PACKER_BIN) $(ARM32_LOADER_BIN) $(ARM32_STUBGEN_BIN) $(HOST_ARM32_TOOL_BINS)

PACKER_SOURCES := $(PACKER_DIR)/packer.c $(PACKER_DIR)/crypto.c $(PACKER_DIR)/obfuscation.c
LOADER_SOURCES := $(LOADER_DIR)/loader.c $(LOADER_DIR)/memexec.c $(LOADER_DIR)/polymorph.c $(LOADER_DIR)/strings.c $(PACKER_DIR)/elf64.c $(PACKER_DIR)/crypto.c $(PACKER_DIR)/obfuscation.c
STUBGEN_SOURCES := $(STUBGEN_DIR)/stubgen.c $(PACKER_DIR)/elf64.c

INCLUDES := -I$(INCLUDE_DIR)

.PHONY: all all32 clean test test-smoke test-runtime test32 install-deps install-deps32 verify-build verify-build32 verify-pack-tools verify-pack-tools32 pack pack32

all: $(BUILD_DIRS) $(ALL_BINS)

all32: $(ARM32_BUILD_DIR) $(HOST_BUILD_DIR) $(ALL32_BINS)

verify-build: all
	@echo "Verifying ARM64 build artifacts..."
	@for bin in $(ARM64_PACKER_BIN) $(ARM64_LOADER_BIN) $(ARM64_STUBGEN_BIN); do \
		if [ ! -x "$$bin" ]; then \
			echo "ERROR: missing executable artifact: $$bin"; \
			exit 1; \
		fi; \
		if ! file "$$bin" | grep -q "ARM aarch64"; then \
			file "$$bin"; \
			exit 1; \
		fi; \
		if ! $(TARGET_READELF) -h "$$bin" | grep -q "Machine:[[:space:]]*AArch64"; then \
			$(TARGET_READELF) -h "$$bin"; \
			exit 1; \
		fi; \
	done
	@if $(TARGET_READELF) -d $(ARM64_LOADER_BIN) 2>/dev/null | grep -q NEEDED; then \
		echo "ERROR: $(ARM64_LOADER_BIN) must be statically linked"; \
		exit 1; \
	fi
	@if $(TARGET_READELF) -d $(ARM64_STUBGEN_BIN) 2>/dev/null | grep -q NEEDED; then \
		echo "ERROR: $(ARM64_STUBGEN_BIN) must be statically linked"; \
		exit 1; \
	fi
	@if [ "$(HOST_BUILD_NAME)" != "ARM64" ]; then \
		echo "Verifying $(HOST_BUILD_NAME) host tools..."; \
		for bin in $(HOST_PACKER_BIN) $(HOST_STUBGEN_BIN); do \
			if [ ! -x "$$bin" ]; then \
				echo "ERROR: missing executable artifact: $$bin"; \
				exit 1; \
			fi; \
			if ! file "$$bin" | grep -q "x86-64"; then \
				file "$$bin"; \
				exit 1; \
			fi; \
		done; \
	fi
	@echo "Build artifacts verified."

verify-pack-tools: all
	@echo "Checking pack tool runtime..."
	@$(PACKER_BIN) >/dev/null 2>&1; status=$$?; \
		if [ $$status -eq 126 ] || [ $$status -eq 127 ]; then \
			echo "ERROR: $(PACKER_BIN) cannot run on this host."; \
			exit 1; \
		fi
	@$(STUBGEN_BIN) >/dev/null 2>&1; status=$$?; \
		if [ $$status -eq 126 ] || [ $$status -eq 127 ]; then \
			echo "ERROR: $(STUBGEN_BIN) cannot run on this host."; \
			exit 1; \
		fi
	@echo "Pack tools are executable on this host."

verify-build32: all32
	@echo "Verifying ARM32/EABI5 build artifacts..."
	@for bin in $(ARM32_PACKER_BIN) $(ARM32_LOADER_BIN) $(ARM32_STUBGEN_BIN); do \
		if [ ! -x "$$bin" ]; then \
			echo "ERROR: missing executable artifact: $$bin"; \
			exit 1; \
		fi; \
		if ! file "$$bin" | grep -q "ARM"; then \
			file "$$bin"; \
			exit 1; \
		fi; \
		if ! $(ARM32_READELF) -h "$$bin" | grep -q "Machine:[[:space:]]*ARM"; then \
			$(ARM32_READELF) -h "$$bin"; \
			exit 1; \
		fi; \
	done
	@if $(ARM32_READELF) -d $(ARM32_LOADER_BIN) 2>/dev/null | grep -q NEEDED; then \
		echo "ERROR: $(ARM32_LOADER_BIN) must be statically linked"; \
		exit 1; \
	fi
	@if $(ARM32_READELF) -d $(ARM32_STUBGEN_BIN) 2>/dev/null | grep -q NEEDED; then \
		echo "ERROR: $(ARM32_STUBGEN_BIN) must be statically linked"; \
		exit 1; \
	fi
	@if [ "$(HOST_BUILD_NAME)" != "ARM32_EABI5" ]; then \
		echo "Verifying $(HOST_BUILD_NAME) ARM32 pack tools..."; \
		for bin in $(HOST_ARM32_PACKER_BIN) $(HOST_STUBGEN_BIN); do \
			if [ ! -x "$$bin" ]; then \
				echo "ERROR: missing executable artifact: $$bin"; \
				exit 1; \
			fi; \
			if ! file "$$bin" | grep -q "x86-64\\|ARM aarch64"; then \
				file "$$bin"; \
				exit 1; \
			fi; \
		done; \
	fi
	@echo "ARM32/EABI5 build artifacts verified."

verify-pack-tools32: all32
	@echo "Checking ARM32 pack tool runtime..."
	@$(HOST_ARM32_PACKER_BIN) >/dev/null 2>&1; status=$$?; \
		if [ $$status -eq 126 ] || [ $$status -eq 127 ]; then \
			echo "ERROR: $(HOST_ARM32_PACKER_BIN) cannot run on this host."; \
			exit 1; \
		fi
	@$(HOST_STUBGEN_BIN) >/dev/null 2>&1; status=$$?; \
		if [ $$status -eq 126 ] || [ $$status -eq 127 ]; then \
			echo "ERROR: $(HOST_STUBGEN_BIN) cannot run on this host."; \
			exit 1; \
		fi
	@echo "ARM32 pack tools are executable on this host."

$(BUILD_DIRS) $(ARM32_BUILD_DIR):
	mkdir -p $@

$(ARM64_PACKER_BIN): $(PACKER_SOURCES) | $(ARM64_BUILD_DIR)
	$(TARGET_CC) $(CFLAGS) $(SECURITY_FLAGS) $(TARGET_ARCH_FLAGS) $(TARGET_OPENSSL_CFLAGS) $(INCLUDES) -o $@ $^ $(TARGET_OPENSSL_LDFLAGS)

$(ARM64_LOADER_BIN): $(LOADER_SOURCES) | $(ARM64_BUILD_DIR)
	$(TARGET_CC) $(TARGET_CFLAGS) $(STEALTH_FLAGS) $(TARGET_ARCH_FLAGS) $(TARGET_OPENSSL_CFLAGS) $(INCLUDES) -o $@ $^ $(TARGET_OPENSSL_LDFLAGS) 2>/dev/null || $(TARGET_CC) $(TARGET_CFLAGS) $(STEALTH_FLAGS) $(TARGET_ARCH_FLAGS) $(TARGET_OPENSSL_CFLAGS) $(INCLUDES) -o $@ $^ $(TARGET_OPENSSL_LDFLAGS) -lzstd -lz

$(ARM64_STUBGEN_BIN): $(STUBGEN_SOURCES) | $(ARM64_BUILD_DIR)
	$(TARGET_CC) $(CFLAGS) $(TARGET_ARCH_FLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

$(ARM32_PACKER_BIN): $(PACKER_SOURCES) | $(ARM32_BUILD_DIR)
	$(ARM32_CC) $(CFLAGS) $(SECURITY_FLAGS) $(ARM32_TARGET_ARCH_FLAGS) $(ARM32_OPENSSL_CFLAGS) $(INCLUDES) -o $@ $^ $(ARM32_OPENSSL_LDFLAGS)

$(ARM32_LOADER_BIN): $(LOADER_SOURCES) | $(ARM32_BUILD_DIR)
	$(ARM32_CC) $(ARM32_TARGET_CFLAGS) $(STEALTH_FLAGS) $(ARM32_TARGET_ARCH_FLAGS) $(ARM32_OPENSSL_CFLAGS) $(INCLUDES) -o $@ $^ $(ARM32_OPENSSL_LDFLAGS) 2>/dev/null || $(ARM32_CC) $(ARM32_TARGET_CFLAGS) $(STEALTH_FLAGS) $(ARM32_TARGET_ARCH_FLAGS) $(ARM32_OPENSSL_CFLAGS) $(INCLUDES) -o $@ $^ $(ARM32_OPENSSL_LDFLAGS) -lzstd -lz

$(ARM32_STUBGEN_BIN): $(STUBGEN_SOURCES) | $(ARM32_BUILD_DIR)
	$(ARM32_CC) $(CFLAGS) $(ARM32_TARGET_ARCH_FLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

ifneq ($(HOST_TOOL_BINS),)
$(HOST_PACKER_BIN): $(PACKER_SOURCES) | $(HOST_BUILD_DIR)
	$(HOST_CC) $(CFLAGS) $(SECURITY_FLAGS) $(HOST_TARGET_FLAGS) $(HOST_OPENSSL_CFLAGS) $(INCLUDES) -o $@ $^ $(HOST_OPENSSL_LDFLAGS)

$(HOST_STUBGEN_BIN): $(STUBGEN_SOURCES) | $(HOST_BUILD_DIR)
	$(HOST_CC) $(CFLAGS) $(HOST_TARGET_FLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)
endif

$(HOST_ARM32_PACKER_BIN): $(PACKER_SOURCES) | $(HOST_BUILD_DIR)
	$(HOST_CC) $(CFLAGS) $(SECURITY_FLAGS) $(ARM32_TARGET_ARCH_FLAGS) $(HOST_OPENSSL_CFLAGS) $(INCLUDES) -o $@ $^ $(HOST_OPENSSL_LDFLAGS)

pack: verify-pack-tools
	@if [ -z "$(INPUT)" ] || [ -z "$(OUTPUT)" ]; then \
		echo "Usage: make pack INPUT=<arm64_elf> OUTPUT=<packed_arm64_elf>"; \
		exit 1; \
	fi
	"$(PACKER_BIN)" "$(INPUT)" "$(OUTPUT).packed"
	"$(STUBGEN_BIN)" "$(LOADER_BIN)" "$(OUTPUT).packed" "$(OUTPUT)"
	@echo "Output packed ARM64 binary created: $(OUTPUT)"

pack32: verify-pack-tools32
	@if [ -z "$(INPUT)" ] || [ -z "$(OUTPUT)" ]; then \
		echo "Usage: make pack32 INPUT=<arm32_eabi5_elf> OUTPUT=<packed_arm32_eabi5_elf>"; \
		exit 1; \
	fi
	"$(HOST_ARM32_PACKER_BIN)" "$(INPUT)" "$(OUTPUT).packed"
	"$(HOST_STUBGEN_BIN)" "$(ARM32_LOADER_BIN)" "$(OUTPUT).packed" "$(OUTPUT)"
	@echo "Output packed ARM32/EABI5 binary created: $(OUTPUT)"

clean:
	rm -rf $(BUILD_DIR)
	rm -f *.packed
	rm -f test_* bench_*

test: test-smoke

test-smoke:
	@echo "Running build and pack smoke tests..."
	@bash tests/runtime_guard_test.sh
	@bash tests/platform_layout_test.sh

test-runtime:
	@echo "Running ARM64 runtime tests..."
	@bash tests/unit_test.sh

test32:
	@echo "Running ARM32/EABI5 smoke and runtime tests..."
	@bash tests/arm32_eabi5_test.sh

install-deps:
	@echo "Installing ARM64 packing dependencies for host $(UNAME_M)..."
	@if command -v apt-get >/dev/null 2>&1; then \
		if [ "$(UNAME_M)" = "x86_64" ]; then \
			sudo dpkg --add-architecture arm64 && \
			sudo apt-get update && \
			sudo apt-get install -y gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu libssl-dev:amd64 libssl-dev:arm64 zlib1g-dev:arm64 libzstd-dev:arm64; \
		else \
			sudo apt-get update && \
			sudo apt-get install -y build-essential libssl-dev zlib1g-dev libzstd-dev; \
		fi; \
	elif command -v yum >/dev/null 2>&1; then \
		sudo yum install -y gcc openssl-devel; \
	elif command -v pacman >/dev/null 2>&1; then \
		sudo pacman -S gcc openssl; \
	else \
		echo "Please install ARM64 cross-compilation and OpenSSL tools manually"; \
	fi

install-deps32:
	@echo "Installing ARM32/EABI5 packing dependencies for host $(UNAME_M)..."
	@if command -v apt-get >/dev/null 2>&1; then \
		if [ "$(UNAME_M)" = "x86_64" ]; then \
			sudo dpkg --add-architecture armhf && \
			sudo apt-get update && \
			sudo apt-get install -y gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf qemu-user libssl-dev:amd64 libssl-dev:armhf zlib1g-dev:armhf libzstd-dev:armhf; \
		else \
			sudo apt-get update && \
			sudo apt-get install -y gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf qemu-user libssl-dev zlib1g-dev libzstd-dev; \
		fi; \
	else \
		echo "Please install ARM32/EABI5 cross-compilation, qemu-user and OpenSSL tools manually"; \
	fi
