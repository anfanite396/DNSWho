# Variables
CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lssl -lcrypto  # Add linker flags for SSL and Crypto
TARGET_SERVER = app/server
TARGET_CLIENT = app/testclient
SRC_SERVER = app/server.c
SRC_CLIENT = app/testclient.c
HEADERS = app/server.h

# Default target
all: $(TARGET_SERVER) $(TARGET_CLIENT)

# Build server target
$(TARGET_SERVER): $(SRC_SERVER) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET_SERVER) $(SRC_SERVER) $(LDFLAGS)

# Build client target
$(TARGET_CLIENT): $(SRC_CLIENT) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET_CLIENT) $(SRC_CLIENT) $(LDFLAGS)

# Run server target
run_server: $(TARGET_SERVER)
	./$(TARGET_SERVER)

# Run client target
run_client: $(TARGET_CLIENT)
	./$(TARGET_CLIENT)

# Clean target
clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT)

# Phony targets
.PHONY: all clean run_server run_client
