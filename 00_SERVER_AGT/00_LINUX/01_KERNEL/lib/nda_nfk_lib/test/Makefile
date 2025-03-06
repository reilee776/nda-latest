# Makefile for building the user application

# 변수 정의
CC = gcc
CFLAGS = -Wall -ldl
LIB_NAME = -lnd_nix_nfm_lib
SOURCE = test.c

# 기본 타겟
all: test

# 사용자 애플리케이션 빌드
test: $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $^ -L. $(LIB_NAME)

# 클린업
clean:
	rm -f test

.PHONY: all clean

