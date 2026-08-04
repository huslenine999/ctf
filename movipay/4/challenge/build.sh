#!/bin/sh
set -eu

cd "$(dirname "$0")"

rm -f roam_client

gcc -O2 -Wall -Wextra -s -fno-stack-protector -D_FORTIFY_SOURCE=0 \
    roam_client.c -o roam_client

echo "[+] built roam_client"
