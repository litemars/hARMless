# AArch64 ELF Packer - Corrected Implementation
# Addresses the fundamental issues in hARMless project

CC = gcc
CFLAGS = -O2 -Wall -Wextra -fno-stack-protector -static
AARCH64_CC = aarch64-linux-gnu-gcc
AARCH64_CFLAGS = -O2 -Wall -Wextra -fno-stack-protector -fPIC -static
SRC_DIR = src
OBJ_DIR = obj
INCLUDES_DIR = $(SRC_DIR)/includes
TARGET = aarch64-packer

# Source files
PACKER_SOURCES = $(SRC_DIR)/packer.c $(SRC_DIR)/elf_utils.c $(SRC_DIR)/crypto.c
LOADER_SOURCE = $(SRC_DIR)/loader.c
LOADER_ASM = $(SRC_DIR)/loader_entry.S

# Object files
PACKER_OBJECTS = $(OBJ_DIR)/packer.o $(OBJ_DIR)/elf_utils.o $(OBJ_DIR)/crypto.o
LOADER_OBJECTS = $(OBJ_DIR)/loader.o $(OBJ_DIR)/loader_entry.o

# Include paths
INCLUDE_FLAGS = -I$(INCLUDES_DIR)

.PHONY: all clean loader packer install debug test

all: $(TARGET)

# Create directories
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Generate loader stub (position-independent for injection)
loader: $(OBJ_DIR) $(SRC_DIR)/loader_stub.h

$(SRC_DIR)/loader_stub.h: $(LOADER_OBJECTS)
	$(AARCH64_CC) -nostdlib -Wl,--build-id=none -T $(SRC_DIR)/loader.lds $(LOADER_OBJECTS) -o $(OBJ_DIR)/loader_stub
	objcopy -O binary $(OBJ_DIR)/loader_stub $(OBJ_DIR)/loader_stub.bin
	xxd -i $(OBJ_DIR)/loader_stub.bin > $(SRC_DIR)/loader_stub.h
	sed -i 's/unsigned char/static unsigned char/g' $(SRC_DIR)/loader_stub.h
	sed -i 's/unsigned int/static unsigned int/g' $(SRC_DIR)/loader_stub.h

# Compile loader objects with position-independent code
$(OBJ_DIR)/loader.o: $(SRC_DIR)/loader.c | $(OBJ_DIR)
	$(AARCH64_CC) $(AARCH64_CFLAGS) $(INCLUDE_FLAGS) -c $< -o $@

$(OBJ_DIR)/loader_entry.o: $(SRC_DIR)/loader_entry.S | $(OBJ_DIR)
	$(AARCH64_CC) $(AARCH64_CFLAGS) -c $< -o $@

# Compile packer objects
$(OBJ_DIR)/packer.o: $(SRC_DIR)/packer.c $(SRC_DIR)/loader_stub.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c $< -o $@

$(OBJ_DIR)/elf_utils.o: $(SRC_DIR)/elf_utils.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c $< -o $@

$(OBJ_DIR)/crypto.o: $(SRC_DIR)/crypto.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c $< -o $@

# Link packer with crypto library
$(TARGET): loader $(PACKER_OBJECTS)
	$(CC) $(CFLAGS) $(PACKER_OBJECTS) -o $@ -lcrypto

clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(SRC_DIR)/loader_stub.h

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

debug: CFLAGS += -g -DDEBUG
debug: AARCH64_CFLAGS += -g -DDEBUG
debug: $(TARGET)

test: $(TARGET)
	./tests/test.sh

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@which $(CC) >/dev/null || (echo "Error: $(CC) not found" && exit 1)
	@which $(AARCH64_CC) >/dev/null || (echo "Error: $(AARCH64_CC) not found" && exit 1)
	@pkg-config --exists libcrypto || (echo "Error: libcrypto not found" && exit 1)
	@echo "All dependencies satisfied!"

help:
	@echo "AArch64 ELF Packer - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build the complete packer"
	@echo "  loader     - Build only the loader stub"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install to system (/usr/local/bin)"
	@echo "  debug      - Build with debug symbols"
	@echo "  test       - Run test suite"
	@echo "  check-deps - Check build dependencies"
	@echo "  help       - Show this help"

.PHONY: all clean loader packer install debug test check-deps help