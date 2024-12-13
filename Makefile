# Variables
CC = gcc
CFLAGS = -Wall -Wextra -g
TARGET = app/server
SRC = app/server.c
HEADERS = app/server.h

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# Run target
run: $(TARGET)
	./$(TARGET)

# Clean target
clean:
	rm -f $(TARGET)

# Phony targets
.PHONY: all clean run
