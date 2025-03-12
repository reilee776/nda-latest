# Load build configuration
include ../02_scripts/buildinfo.conf

# Ensure variables are expanded correctly
PKG_ROOTDIR := $(shell echo $(PKG_ROOTDIR))
LIBS_ROOTDIR := /src/libs

LIBS_LIB_UUID_DIR := $(shell echo $(LIBS_ROOTDIR)/uuid)
LIBS_LIB_JSONC_DIR := $(shell echo $(LIBS_ROOTDIR)/json-c)
LIBS_LIB_OPENSSL_DIR := $(shell echo $(LIBS_ROOTDIR)/openssl)
LIBS_LIB_CURL_DIR := $(shell echo $(LIBS_ROOTDIR)/curl)
LIBS_LIB_ZLIB_DIR := $(shell echo $(LIBS_ROOTDIR)/zlib)

# Debugging: Print loaded variables
$(info PKG_ROOTDIR = $(PKG_ROOTDIR))
$(info LIBS_ROOTDIR = $(PKG_ROOTDIR)/libs)
$(info LIBS_LIB_UUID_DIR = $(LIBS_LIB_UUID_DIR))
$(info LIBS_LIB_JSONC_DIR = $(LIBS_LIB_JSONC_DIR))
$(info LIBS_LIB_OPENSSL_DIR = $(LIBS_LIB_OPENSSL_DIR))
$(info LIBS_LIB_CURL_DIR = $(LIBS_LIB_CURL_DIR))
$(info LIBS_LIB_ZLIB_DIR = $(LIBS_LIB_ZLIB_DIR))

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -g -fPIC \
         -I$(LIBS_LIB_UUID_DIR)/include \
         -I$(LIBS_LIB_JSONC_DIR)/include \
         -I$(LIBS_LIB_OPENSSL_DIR)/include \
         -I$(LIBS_LIB_CURL_DIR)/include \
         -I$(LIBS_LIB_ZLIB_DIR)/include \
         -Wall -Wextra -g -std=c99

# Target output
TARGET = nda-pam.so

# Custom library path
CUSTOM_LIB_PATH = /hiagt/lib/nda-pam


# Linker flags (use dynamic libraries instead of static)
LDFLAGS = -g -shared -fPIC \
          -Wl,-rpath,$(LIBS_LIB_JSONC_DIR)/lib64 \
          -Wl,-rpath,$(LIBS_LIB_UUID_DIR)/lib \
          -Wl,-rpath,$(LIBS_LIB_OPENSSL_DIR)/lib \
          -Wl,-rpath,$(LIBS_LIB_CURL_DIR)/lib \
          -Wl,-rpath,$(LIBS_LIB_ZLIB_DIR)/lib \
          -L$(LIBS_LIB_JSONC_DIR)/lib64 -ljson-c \
          -L$(LIBS_LIB_UUID_DIR)/lib -luuid \
          -L$(LIBS_LIB_CURL_DIR)/lib -lcurl \
          -L$(LIBS_LIB_OPENSSL_DIR)/lib -lcrypto -lssl \
          -L$(LIBS_LIB_ZLIB_DIR)/lib -lz

# Libraries to link against
LIBS = -lpam

# Source and object files
PAM_MODULE_SRC = nd_nix_pam.c
ND_UTILS_C = ./libsrc/nd_utils.c
ND_UTILS_H = ./libsrc/nd_utils.h
ND_LOGS_C = ./libsrc/nd_nix_logs.c
ND_LOGS_H = ./libsrc/nd_nix_logs.h
ND_RESTAPI_C = ./libsrc/nd_restapi_func.c
ND_RESTAPI_H = ./libsrc/nd_restapi_func.h

SRCS = $(PAM_MODULE_SRC) $(ND_UTILS_C) $(ND_LOGS_C) $(ND_RESTAPI_C)
HEADERS = $(ND_UTILS_H) $(ND_LOGS_H) $(ND_RESTAPI_H)
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Build shared object
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

# Compile source files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up generated files
clean:
	rm -f $(OBJS) $(TARGET)

# Debugging: Print variables
print-vars:
	@echo "PKG_ROOTDIR = $(PKG_ROOTDIR)"
	@echo "LIBS_ROOTDIR = $(PKG_ROOTDIR)/libs"
	@echo "LIBS_LIB_UUID_DIR = $(LIBS_LIB_UUID_DIR)"
	@echo "LIBS_LIB_JSONC_DIR = $(LIBS_LIB_JSONC_DIR)"
	@echo "LIBS_LIB_OPENSSL_DIR = $(LIBS_LIB_OPENSSL_DIR)"
	@echo "LIBS_LIB_CURL_DIR = $(LIBS_LIB_CURL_DIR)"
	@echo "LIBS_LIB_ZLIB_DIR = $(LIBS_LIB_ZLIB_DIR)"


.PHONY: all clean print-vars
