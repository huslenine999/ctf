#!/bin/sh

set -e

cc \
    -O2 \
    -Wall \
    -Wextra \
    -fno-stack-protector \
    -D_FORTIFY_SOURCE=0 \
    tea_party.c \
    -o tea_party

strip tea_party 2>/dev/null || true

echo "[+] built tea_party"
