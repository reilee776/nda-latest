#!/bin/bash

# 스크립트 실행 디렉토리
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# SIGINT 핸들링 (Ctrl+C 포함)
trap "echo 'Exiting...'; exit 0" SIGINT

# Ctrl+X 핸들링
trap "echo 'Exiting on Ctrl+X'; exit 0" SIGQUIT

# 루프 실행
while true; do
    "$SCRIPT_DIR/ndctl" logs  # 주기적으로 명령 실행
    sleep 2  # 2초 대기
done

