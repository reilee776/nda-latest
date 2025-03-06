#!/bin/bash

set -e  # Exit on error

# Load configuration
CONFIG_FILE="./buildinfo.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "❌ Error: Configuration file $CONFIG_FILE not found!"
    exit 1
fi

source "$CONFIG_FILE"

CURL_VERSION=$1
SRC_DIR="$PKG_SRC_DIR"
INSTALL_PREFIX="$LIBS_LIB_CURL_DIR"
TARBALL="curl-${CURL_VERSION}.tar.gz"
TARBALL_URL="https://curl.se/download/curl-${CURL_VERSION}.tar.gz"
EXTRACTED_DIR="curl-${CURL_VERSION}"

# OpenSSL and Zlib dependency paths
OPENSSL_PREFIX="$LIBS_LIB_OPENSSL_DIR"
ZLIB_PREFIX="$LIBS_LIB_ZLIB_DIR"

echo "🚀 Building Curl version: ${CURL_VERSION}"

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
echo "⚙️ Configuring build for Curl..."
./configure --prefix="$INSTALL_PREFIX" \
            --disable-shared \
            --enable-static \
            --with-ssl="$OPENSSL_PREFIX" \
            --with-zlib="$ZLIB_PREFIX" \
            --disable-ldap \
            --disable-ldaps \
            CFLAGS="-fPIC -static" \
            CXXFLAGS="-fPIC -static"

# Clean, compile, and install
echo "🛠️ Cleaning previous builds..."
make clean

echo "🚀 Building Curl..."
make -j"$(nproc)"

echo "🚀 Installing Curl..."
make install

echo "✅ Curl version ${CURL_VERSION} built and installed successfully in ${INSTALL_PREFIX}"

