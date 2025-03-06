#!/bin/bash

# 입력 인자: 바이너리 경로와 복사할 대상 디렉터리
BINARY=$1
TARGET_DIR=$2

# 유효성 검사
if [ -z "$BINARY" ] || [ -z "$TARGET_DIR" ]; then
    echo "Usage: $0 <binary> <target_directory>"
    exit 1
fi

# 대상 디렉터리 생성
mkdir -p $TARGET_DIR

# ldd 결과에서 라이브러리 경로 추출 및 복사
ldd $BINARY | awk '{print $3}' | grep -v '(' | while read -r lib; do
    if [ -f "$lib" ]; then
        echo "Copying $lib to $TARGET_DIR"
        cp --parents "$lib" $TARGET_DIR
    fi
done

# ld-linux 의존성 복사 (필요 시)
ldd $BINARY | grep 'ld-linux' | awk '{print $1}' | while read -r lib; do
    if [ -f "$lib" ]; then
        echo "Copying $lib to $TARGET_DIR"
        cp --parents "$lib" $TARGET_DIR
    fi
done

echo "Libraries copied to $TARGET_DIR"

