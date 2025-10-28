# PQC Hybrid TLS Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lssl -lcrypto -lm

# macOS specific
UNAME := $(shell uname -s)
ifeq ($(UNAME), Darwin)
    CFLAGS += -I/opt/homebrew/include
    LDFLAGS += -L/opt/homebrew/lib
endif

# Directories
CLIENT_DIR = Client
SERVER_DIR = Server
COMMON_DIR = Common
BUILD_DIR = build

# Source files
COMMON_SRC = $(COMMON_DIR)/metrics.c $(COMMON_DIR)/json_output.c
SERVER_SRC = $(SERVER_DIR)/tls_server.c
CLIENT_SRC = $(CLIENT_DIR)/tls_client.c

# Object files
COMMON_OBJ = $(BUILD_DIR)/metrics.o $(BUILD_DIR)/json_output.o
SERVER_OBJ = $(BUILD_DIR)/tls_server.o
CLIENT_OBJ = $(BUILD_DIR)/tls_client.o

# Executables
SERVER_BIN = $(BUILD_DIR)/tls_server
CLIENT_BIN = $(BUILD_DIR)/tls_client

.PHONY: all clean server client common dirs

all: dirs common server client

dirs:
	@mkdir -p $(BUILD_DIR)

common: $(COMMON_OBJ)

server: $(SERVER_BIN)

client: $(CLIENT_BIN)

# Common objects
$(BUILD_DIR)/metrics.o: $(COMMON_DIR)/metrics.c $(COMMON_DIR)/metrics.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/json_output.o: $(COMMON_DIR)/json_output.c $(COMMON_DIR)/json_output.h
	$(CC) $(CFLAGS) -c $< -o $@

# Server
$(BUILD_DIR)/tls_server.o: $(SERVER_DIR)/tls_server.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER_BIN): $(SERVER_OBJ) $(COMMON_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "✅ Server built: $(SERVER_BIN)"

# Client
$(BUILD_DIR)/tls_client.o: $(CLIENT_DIR)/tls_client.c
	$(CC) $(CFLAGS) -c $< -o $@

$(CLIENT_BIN): $(CLIENT_OBJ) $(COMMON_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "✅ Client built: $(CLIENT_BIN)"

clean:
	rm -rf $(BUILD_DIR)
	@echo "🧹 Cleaned build directory"

help:
	@echo "PQC Hybrid TLS Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build everything (default)"
	@echo "  server  - Build TLS server only"
	@echo "  client  - Build TLS client only"
	@echo "  clean   - Remove build artifacts"
	@echo "  help    - Show this help message"

