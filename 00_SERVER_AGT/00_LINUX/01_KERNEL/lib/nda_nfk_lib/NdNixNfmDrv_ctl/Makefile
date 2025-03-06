# Makefile for building the user application

# 변수 정의
CC = gcc
CFLAGS = -Wall -ldl
LIB_NAME = -lnda_nfk_lib
SOURCE = ndctl.c

# 기본 타겟
all: ndctl

# 사용자 애플리케이션 빌드
ndctl: $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $^ -L. $(LIB_NAME)

# 클린업
clean:
	rm -f ndctl

.PHONY: all clean

