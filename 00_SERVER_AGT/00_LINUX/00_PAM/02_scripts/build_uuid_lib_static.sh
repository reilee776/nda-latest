#!/bin/bash

set -e  # Exit on error

# Load configuration
CONFIG_FILE="./buildinfo.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "❌ Error: Configuration file $CONFIG_FILE not found!"
    exit 1
fi

source "$CONFIG_FILE"

UUID_VERSION=$1
SRC_DIR="$PKG_SRC_DIR"
INSTALL_PREFIX="$LIBS_LIB_UUID_DIR"
TARBALL="util-linux-${UUID_VERSION}.tar.xz"
TARBALL_URL="https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v${UUID_VERSION}/${TARBALL}"
EXTRACTED_DIR="util-linux-${UUID_VERSION}"

echo "🚀 Building UUID (libuuid) version: ${UUID_VERSION}"

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
tar xvf "$TARBALL"

# Change to extracted directory
cd "$EXTRACTED_DIR"

# Configure the build
echo "⚙️ Configuring build for UUID (libuuid)..."
./configure --disable-all-programs --enable-libuuid --disable-shared --enable-static --prefix="$INSTALL_PREFIX"

# Compile and install
echo "🛠️ Building libuuid..."
make -j"$(nproc)"
echo "🚀 Installing libuuid..."
make install

echo "✅ UUID (libuuid) version ${UUID_VERSION} built and installed successfully in ${INSTALL_PREFIX}"

