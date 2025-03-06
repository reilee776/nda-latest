#!/bin/bash

set -e  # Exit immediately if a command fails

# Load configuration file
CONFIG_FILE="./buildinfo.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "❌ Error: Configuration file $CONFIG_FILE not found!"
    exit 1
fi

# Source the configuration file
source "$CONFIG_FILE"

# 🚀 Function to get user input with validation (only yes/no)
get_user_input() {
    local prompt_message=$1
    local selection_var=$2
    local user_input=""

    while true; do
        read -p "$prompt_message (yes/no): " user_input
        if [[ "$user_input" == "yes" ]]; then
            eval "$selection_var=true"
            break
        elif [[ "$user_input" == "no" ]]; then
            eval "$selection_var=false"
            break
        else
            echo "❌ Invalid input! Please enter 'yes' or 'no'."
        fi
    done
}

# 🚀 Collect user inputs for each library
get_user_input "🔹 Do you want to build UUID (libuuid) ${UUID_VERSION}?" BUILD_UUID
get_user_input "🔹 Do you want to build JSON-C ${JSON_C_VERSION}?" BUILD_JSONC
get_user_input "🔹 Do you want to build OpenSSL ${OPENSSL_VERSION}?" BUILD_OPENSSL

# If OpenSSL is selected, ask for libz (Zlib)
if [[ "$BUILD_OPENSSL" == "true" ]]; then
    get_user_input "🔹 OpenSSL requires Zlib (libz) ${LIBZ_VERSION}. Do you want to build it?" BUILD_LIBZ
fi

get_user_input "🔹 Do you want to build Curl ${CURL_VERSION}?" BUILD_CURL

# 🎯 Display final selection summary
echo ""
echo "📌 Final Selection Summary:"
echo "------------------------------------"
echo "🔹 UUID Build: $BUILD_UUID"
echo "🔹 JSON-C Build: $BUILD_JSONC"
echo "🔹 OpenSSL Build: $BUILD_OPENSSL"
echo "🔹 Libz (Zlib) Build: $BUILD_LIBZ"
echo "🔹 Curl Build: $BUILD_CURL"
echo "------------------------------------"

# 🚀 Run selected builds
run_build_script() {
    local script_file=$1
    local version_var=$2
    local dir_to_create=$3

    local version_value=$(eval echo \$$version_var)

    echo "📁 Ensuring directory exists: $dir_to_create"
    mkdir -p "$dir_to_create"

    if [[ -x "./$script_file" ]]; then
        echo "🚀 Running $script_file for version $version_value..."
        ./"$script_file" "$version_value"
    else
        echo "❌ Error: Script $script_file not found or not executable!"
        exit 1
    fi
}

# Run builds based on selection
if [[ "$BUILD_UUID" == "true" ]]; then
    run_build_script "build_uuid_lib_static.sh" "UUID_VERSION" "$LIBS_LIB_UUID_DIR"
fi

if [[ "$BUILD_JSONC" == "true" ]]; then
    run_build_script "build_json-c_lib_static.sh" "JSON_C_VERSION" "$LIBS_LIB_JSONC_DIR"
fi

if [[ "$BUILD_LIBZ" == "true" ]]; then
    run_build_script "build_libz_lib_static.sh" "LIBZ_VERSION" "$LIBS_LIB_ZLIB_DIR"
fi

if [[ "$BUILD_OPENSSL" == "true" ]]; then
    run_build_script "build_openssl_lib_static.sh" "OPENSSL_VERSION" "$LIBS_LIB_OPENSSL_DIR"
fi

if [[ "$BUILD_CURL" == "true" ]]; then
    run_build_script "build_curl_lib_static.sh" "CURL_VERSION" "$LIBS_LIB_CURL_DIR"
fi

echo "🎉 All selected builds completed!"

