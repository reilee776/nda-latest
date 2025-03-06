#!/bin/bash

# Paths
SCRIPT_DIR=$(dirname $(readlink -f $0))
PAM_MODULE_SRC="$SCRIPT_DIR/bin/nda-pam/nda-pam.so"
PAM_MODULE_DST="/usr/lib64/security/nda-pam.so"
LIB_PATH="$HIAGT_HOME/lib/nda-pam"
INSTALL_SRC="$SCRIPT_DIR"

# Environment variable for installation path
HIAGT_HOME=${HIAGT_HOME:-/hiagt}

# 0. Copy all files under install to HIAGT_HOME
if [ ! -d "$HIAGT_HOME" ]; then
    mkdir -p "$HIAGT_HOME"
fi
if [ -d "$INSTALL_SRC" ]; then
    cp -r "$INSTALL_SRC"/* "$HIAGT_HOME/"
    echo "Files copied to: $HIAGT_HOME"
else
    echo "Source directory not found: $INSTALL_SRC"
    exit 1
fi

# PAM configuration files
SSHD_CONFIG="/etc/ssh/sshd_config"
PAM_SSHD="/etc/pam.d/sshd"
PAM_SU="/etc/pam.d/su"

# 1. Copy PAM module
if [ -f "$PAM_MODULE_SRC" ]; then
    cp "$PAM_MODULE_SRC" "$PAM_MODULE_DST"
    chmod 644 "$PAM_MODULE_DST"
    echo "PAM module copied successfully: $PAM_MODULE_DST"
else
    echo "PAM module file not found: $PAM_MODULE_SRC"
    exit 1
fi

# 2-0. Prompt for configuration changes
read -p "Do you want to change configuration settings? (yes/no): " config_change
if [ "$config_change" != "yes" ]; then
    echo "Skipping configuration changes."
else
    # 2-1. Update sshd settings
    sed -i '/^#*ChallengeResponseAuthentication/d' "$SSHD_CONFIG"
    sed -i '/^ChallengeResponseAuthentication/d' "$SSHD_CONFIG"
    echo "ChallengeResponseAuthentication yes" >> "$SSHD_CONFIG"

    sed -i '/^#*UsePAM/d' "$SSHD_CONFIG"
    sed -i '/^UsePAM/d' "$SSHD_CONFIG"
    echo "UsePAM yes" >> "$SSHD_CONFIG"

    echo "SSHD configuration updated."

    # 2-2. Register PAM module in sshd
    read -p "Do you want to register in /etc/pam.d/sshd? (yes/no): " sshd_register
    if [ "$sshd_register" == "yes" ]; then
        read -p "Register at the top (1) or bottom (2): " sshd_position
        if [ "$sshd_position" == "1" ]; then
            sed -i "1i auth requisite nda-pam.so" "$PAM_SSHD"
            sed -i "2i session required nda-pam.so" "$PAM_SSHD"
        else
            echo "auth requisite nda-pam.so" >> "$PAM_SSHD"
            echo "session required nda-pam.so" >> "$PAM_SSHD"
        fi
        echo "SSHD PAM registration completed."
    fi

    # 2-4. Register PAM module in su
    read -p "Do you want to register in /etc/pam.d/su? (yes/no): " su_register
    if [ "$su_register" == "yes" ]; then
        read -p "Register at the top (1) or bottom (2): " su_position
        if [ "$su_position" == "1" ]; then
            sed -i "1i auth requisite nda-pam.so" "$PAM_SU"
            sed -i "2i session required nda-pam.so" "$PAM_SU"
        else
            echo "auth requisite nda-pam.so" >> "$PAM_SU"
            echo "session required nda-pam.so" >> "$PAM_SU"
        fi
        echo "SU PAM registration completed."
    fi

    # 2-6. Register library path
    if [ -d "$LIB_PATH" ]; then
        echo "$LIB_PATH" > /etc/ld.so.conf.d/nda-pam.conf
        ldconfig
        echo "Library path registered successfully."
    else
        echo "Library path not found: $LIB_PATH"
        exit 1
    fi

    # 2-7. Restart sshd service
    read -p "Do you want to restart sshd service? (yes/no): " restart_sshd
    if [ "$restart_sshd" == "yes" ]; then
        systemctl restart sshd
        echo "SSHD service restarted successfully."
    else
        echo "SSHD service restart skipped."
    fi
fi

echo "Installation completed."
