#!/bin/sh

set -e

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$ROOT_DIR/challenge/dist/roam_client"

: "${ZIG_GLOBAL_CACHE_DIR:=$ROOT_DIR/.zig-cache}"
: "${ZIG_LOCAL_CACHE_DIR:=$ROOT_DIR/.zig-cache}"
export ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR

zig cc \
    -target x86_64-linux-musl \
    -O2 \
    -g0 \
    -s \
    -Wall \
    -Wextra \
    -fno-stack-protector \
    -D_FORTIFY_SOURCE=0 \
    "$ROOT_DIR/challenge/roam_client.c" \
    -o "$OUT"

chmod 0555 "$OUT"
file "$OUT"
