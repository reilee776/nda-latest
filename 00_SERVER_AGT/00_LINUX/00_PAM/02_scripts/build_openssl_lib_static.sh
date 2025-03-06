#!/bin/bash

set -e  # Exit on error

# Load configuration
CONFIG_FILE="./buildinfo.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "❌ Error: Configuration file $CONFIG_FILE not found!"
    exit 1
fi

source "$CONFIG_FILE"

OPENSSL_VERSION=$1
SRC_DIR="$PKG_SRC_DIR"
INSTALL_PREFIX="$LIBS_LIB_OPENSSL_DIR"
TARBALL="openssl-${OPENSSL_VERSION}.tar.gz"
TARBALL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
EXTRACTED_DIR="openssl-${OPENSSL_VERSION}"

# Zlib dependency paths
ZLIB_LIB="$LIBS_LIB_ZLIB_DIR/lib"
ZLIB_INCLUDE="$LIBS_LIB_ZLIB_DIR/include"

echo "🚀 Building OpenSSL version: ${OPENSSL_VERSION}"

# Ensure required directories exist
mkdir -p "$SRC_DIR"
mkdir -p "$INSTALL_PREFIX"

# Navigate to source directory
cd "$SRC_DIR"

# Download source code if not already present
if [[ ! -f "$TARBALL" ]]; then
    echo "📥 Downloading $TARBALL..."
    wget "$TARBALL_URL"
else
    echo "✅ Source tarball already exists: $TARBALL"
fi

# Extract the source code
echo "📦 Extracting $TARBALL..."
tar -xvzf "$TARBALL"

# Change to extracted directory
cd "$EXTRACTED_DIR"

# Configure the build
echo "⚙️ Configuring build for OpenSSL..."
./config no-shared no-dso no-ssl2 no-ssl3 \
    --prefix="$INSTALL_PREFIX" \
    --openssldir="$INSTALL_PREFIX" \
    -fPIC -static \
    --with-zlib-lib="$ZLIB_LIB" \
    --with-zlib-include="$ZLIB_INCLUDE"

# Clean, compile, and install
echo "🛠️ Cleaning previous builds..."
make clean

echo "🚀 Building OpenSSL..."
make -j"$(nproc)"

echo "🚀 Installing OpenSSL..."
make install

echo "✅ OpenSSL version ${OPENSSL_VERSION} built and installed successfully in ${INSTALL_PREFIX}"

