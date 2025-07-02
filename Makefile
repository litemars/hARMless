CC = gcc
CFLAGS = -O2 -Wall -Wextra -fno-stack-protector -static
AARCH64_CC = aarch64-linux-gnu-gcc
AARCH64_CFLAGS = -O2 -Wall -Wextra -fno-stack-protector -static
SRC_DIR = src
OBJ_DIR = obj
TARGET = aarch64-packer

# Source files
PACKER_SOURCES = $(SRC_DIR)/packer.c $(SRC_DIR)/elf_utils.c $(SRC_DIR)/crypto.c
LOADER_SOURCE = $(SRC_DIR)/loader.c
LOADER_ASM = $(SRC_DIR)/loader_entry.S

# Object files
PACKER_OBJECTS = $(OBJ_DIR)/packer.o $(OBJ_DIR)/elf_utils.o $(OBJ_DIR)/crypto.o
LOADER_OBJECTS = $(OBJ_DIR)/loader.o $(OBJ_DIR)/loader_entry.o

.PHONY: all clean loader packer

all: $(TARGET)

# Create directories
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Compile loader (this gets embedded in packer)
loader: $(OBJ_DIR) $(SRC_DIR)/loader_stub.h

$(SRC_DIR)/loader_stub.h: $(LOADER_OBJECTS)
	$(AARCH64_CC) -nostdlib -Wl,--build-id=none -T $(SRC_DIR)/loader.lds $(LOADER_OBJECTS) -o $(OBJ_DIR)/loader_stub
	objcopy -O binary $(OBJ_DIR)/loader_stub $(OBJ_DIR)/loader_stub.bin
	xxd -i $(OBJ_DIR)/loader_stub.bin > $(SRC_DIR)/loader_stub.h
	sed -i 's/unsigned char/static unsigned char/g' $(SRC_DIR)/loader_stub.h
	sed -i 's/unsigned int/static unsigned int/g' $(SRC_DIR)/loader_stub.h

# Compile loader objects
$(OBJ_DIR)/loader.o: $(SRC_DIR)/loader.c | $(OBJ_DIR)
	$(AARCH64_CC) $(AARCH64_CFLAGS) -c $< -o $@

$(OBJ_DIR)/loader_entry.o: $(SRC_DIR)/loader_entry.S | $(OBJ_DIR)
	$(AARCH64_CC) $(AARCH64_CFLAGS) -c $< -o $@

# Compile packer objects
$(OBJ_DIR)/packer.o: $(SRC_DIR)/packer.c $(SRC_DIR)/loader_stub.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/elf_utils.o: $(SRC_DIR)/elf_utils.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/crypto.o: $(SRC_DIR)/crypto.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link packer
$(TARGET): loader $(PACKER_OBJECTS)
	$(CC) $(CFLAGS) $(PACKER_OBJECTS) -o $@ -lcrypto

clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(SRC_DIR)/loader_stub.h

install:
	install -m 755 $(TARGET) /usr/local/bin/

debug: CFLAGS += -g -DDEBUG
debug: AARCH64_CFLAGS += -g -DDEBUG
debug: $(TARGET)

test: $(TARGET)
	./test.sh

.PHONY: all clean loader packer install debug test
