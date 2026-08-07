#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHALLENGE_DIR="${SCRIPT_DIR}/../challenge"

echo "[*] Building PyJail Sandbox Docker image..."
docker build -t pyjail-sandbox:latest "${CHALLENGE_DIR}"
echo "[+] Done building pyjail-sandbox:latest"
