#!/bin/sh

set -e

cc \
    -O2 \
    -Wall \
    -Wextra \
    -fno-stack-protector \
    -D_FORTIFY_SOURCE=0 \
    tiny_vm.c \
    -o tiny_vm

strip tiny_vm 2>/dev/null || true

echo "[+] built tiny_vm"
