# 📌 Load build configuration
include ../scripts/buildinfo.conf

# Ensure variables are expanded correctly
PKG_ROOTDIR := $(shell echo $(PKG_ROOTDIR))
LIBS_ROOTDIR := $(shell echo $(PKG_ROOTDIR)/libs)

LIBS_LIB_UUID_DIR := $(shell echo $(LIBS_ROOTDIR)/uuid)
LIBS_LIB_JSONC_DIR := $(shell echo $(LIBS_ROOTDIR)/json-c)
LIBS_LIB_OPENSSL_DIR := $(shell echo $(LIBS_ROOTDIR)/openssl)
LIBS_LIB_CURL_DIR := $(shell echo $(LIBS_ROOTDIR)/curl)
LIBS_LIB_ZLIB_DIR := $(shell echo $(LIBS_ROOTDIR)/zlib)

# 📌 Debugging: Print loaded variables
$(info 📌 PKG_ROOTDIR = $(PKG_ROOTDIR))
$(info 📌 LIBS_ROOTDIR = $(PKG_ROOTDIR)/libs)
$(info 📌 LIBS_LIB_UUID_DIR = $(PKG_ROOTDIR)/uuid)
$(info 📌 LIBS_LIB_JSONC_DIR = $(PKG_ROOTDIR)/json-c)
$(info 📌 LIBS_LIB_OPENSSL_DIR = $(PKG_ROOTDIR)/openssl)
$(info 📌 LIBS_LIB_CURL_DIR = $(PKG_ROOTDIR)/curl)
$(info 📌 LIBS_LIB_ZLIB_DIR = $(PKG_ROOTDIR)/zlib)

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

# Linker flags
LDFLAGS = -g -shared -fPIC -Wl,-rpath,$(CUSTOM_LIB_PATH) \
          $(LIBS_LIB_UUID_DIR)/lib/libuuid.a \
          -Wl,--whole-archive $(LIBS_LIB_JSONC_DIR)/lib64/libjson-c.a -Wl,--no-whole-archive \
          -Wl,--whole-archive $(LIBS_LIB_CURL_DIR)/lib/libcurl.a -Wl,--no-whole-archive \
          -Wl,--whole-archive $(LIBS_LIB_OPENSSL_DIR)/lib/libcrypto.a -Wl,--whole-archive $(LIBS_LIB_OPENSSL_DIR)/lib/libssl.a -Wl,--no-whole-archive \
          $(LIBS_LIB_ZLIB_DIR)/lib/libz.a

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
	@echo "📌 PKG_ROOTDIR = $(PKG_ROOTDIR)"
	@echo "📌 LIBS_ROOTDIR = $(PKG_ROOTDIR)/libs"
	@echo "📌 LIBS_LIB_UUID_DIR = $(LIBS_LIB_UUID_DIR)"
	@echo "📌 LIBS_LIB_JSONC_DIR = $(LIBS_LIB_JSONC_DIR)"
	@echo "📌 LIBS_LIB_OPENSSL_DIR = $(LIBS_LIB_OPENSSL_DIR)"
	@echo "📌 LIBS_LIB_CURL_DIR = $(LIBS_LIB_CURL_DIR)"
	@echo "📌 LIBS_LIB_ZLIB_DIR = $(LIBS_LIB_ZLIB_DIR)"

.PHONY: all clean print-vars

