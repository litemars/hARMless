# Compiler detection
UNAME_M := $(shell uname -m)
CC := gcc
TARGET_CC := gcc

# Cross-compilation setup for ARM64
ifeq ($(UNAME_M), x86_64)
    TARGET_CC := aarch64-linux-gnu-gcc
endif

# Compiler flags
CFLAGS := -Wall -Wextra -O2 -std=c99 
TARGET_CFLAGS := -Wall -Wextra -O2 -std=c99 -static
LDFLAGS := -static

# Directories
SRC_DIR := .
INCLUDE_DIR := include
PACKER_DIR := packer
LOADER_DIR := loader
STUBGEN_DIR := stubgen
BUILD_DIR := build

# Output binaries
PACKER_BIN := $(BUILD_DIR)/packer
LOADER_BIN := $(BUILD_DIR)/loader
STUBGEN_BIN := $(BUILD_DIR)/stubgen

# Source files
PACKER_SOURCES := $(PACKER_DIR)/packer.c $(PACKER_DIR)/rc4.c $(PACKER_DIR)/elf64.c
LOADER_SOURCES := $(LOADER_DIR)/loader.c $(LOADER_DIR)/memexec.c $(PACKER_DIR)/elf64.c $(PACKER_DIR)/rc4.c
STUBGEN_SOURCES := $(STUBGEN_DIR)/stubgen.c

# Include paths
INCLUDES := -I$(INCLUDE_DIR)

# Default target
all: $(BUILD_DIR) $(PACKER_BIN) $(LOADER_BIN) $(STUBGEN_BIN)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build packer (runs on host)
$(PACKER_BIN): $(PACKER_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# Build loader (ARM64 target)
$(LOADER_BIN): $(LOADER_SOURCES)
	$(TARGET_CC) $(TARGET_CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# Build stub generator (runs on host)
$(STUBGEN_BIN): $(STUBGEN_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)


# Pack a binary
pack: $(PACKER_BIN) $(LOADER_BIN) $(STUBGEN_BIN)
	@if [ -z "$(INPUT)" ] || [ -z "$(OUTPUT)" ]; then \
		echo "Usage: make pack INPUT=<input_binary> OUTPUT=<output_binary>"; \
		exit 1; \
	fi
	@echo "Packing $(INPUT) -> $(OUTPUT)"
	$(PACKER_BIN) $(INPUT) $(OUTPUT).packed
	$(STUBGEN_BIN) $(LOADER_BIN) $(OUTPUT).packed $(OUTPUT)
	@echo "Packed binary created: $(OUTPUT)"


# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f *.packed



# Help target
help:
	@echo "ARM64 ELF Packer/Loader Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all                     - Build all components"
	@echo "  pack INPUT=<> OUTPUT=<> - Pack a binary"
	@echo "  clean                   - Clean build artifacts"
	@echo "  help                    - Show this help"

.PHONY: all pack clean help
