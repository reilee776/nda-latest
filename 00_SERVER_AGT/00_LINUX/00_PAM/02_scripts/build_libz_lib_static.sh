#!/bin/bash

set -e  # Exit on error

# Load configuration
CONFIG_FILE="./buildinfo.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "❌ Error: Configuration file $CONFIG_FILE not found!"
    exit 1
fi

source "$CONFIG_FILE"

LIBZ_VERSION="$LIBZ_VERSION"  # Read from buildinfo.conf
SRC_DIR="$PKG_SRC_DIR"
INSTALL_PREFIX="$LIBS_LIB_ZLIB_DIR"
TARBALL="zlib-${LIBZ_VERSION}.tar.gz"
TARBALL_URL="http://www.zlib.net/fossils/zlib-${LIBZ_VERSION}.tar.gz"
EXTRACTED_DIR="zlib-${LIBZ_VERSION}"

echo "🚀 Building Zlib (libz) TARBALL_URL: ${TARBALL_URL}"
echo "🚀 Building Zlib (libz) version: ${LIBZ_VERSION}"

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

# Configure the build with -fPIC
echo "⚙️ Configuring build for Zlib with -fPIC..."
CFLAGS="-fPIC" ./configure --prefix="$INSTALL_PREFIX" --static

# Clean previous builds
echo "🛠️  Cleaning previous builds..."
make clean

# Compile with -fPIC
echo "🚀 Building Zlib with -fPIC..."
CFLAGS="-fPIC" make -j"$(nproc)"

# Install
echo "🚀 Installing Zlib..."
make install

echo "✅ Zlib version ${LIBZ_VERSION} built and installed successfully in ${INSTALL_PREFIX}"

