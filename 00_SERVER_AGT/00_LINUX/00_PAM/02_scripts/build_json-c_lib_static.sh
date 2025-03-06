#!/bin/bash

set -e  # Exit on error

# Load configuration
CONFIG_FILE="./buildinfo.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "❌ Error: Configuration file $CONFIG_FILE not found!"
    exit 1
fi

source "$CONFIG_FILE"

JSON_C_VERSION=$1
SRC_DIR="$PKG_SRC_DIR"
INSTALL_PREFIX="$LIBS_LIB_JSONC_DIR"
TARBALL="json-c-${JSON_C_VERSION}.tar.gz"
TARBALL_URL="https://s3.amazonaws.com/json-c_releases/releases/${TARBALL}"
EXTRACTED_DIR="json-c-${JSON_C_VERSION}"

echo "🚀 Building JSON-C version: ${JSON_C_VERSION}"

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

# Create build directory
mkdir -p build
cd build

# Configure the build
echo "⚙️ Configuring JSON-C build..."
cmake -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
      -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      -DCMAKE_C_FLAGS="-fPIC -static" ..

# Compile and install
echo "🛠️ Building JSON-C..."
make -j"$(nproc)"
echo "🚀 Installing JSON-C..."
make install

echo "✅ JSON-C version ${JSON_C_VERSION} built and installed successfully in ${INSTALL_PREFIX}"

