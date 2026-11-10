#!/bin/bash
# Cross-build MwReceiver.exe (x86_64 Windows GUI) - the LAN collector.
set -euo pipefail

ZIG="${ZIG:-/opt/zig/zig}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$ROOT/dist/MwReceiver.exe}"

mkdir -p "$(dirname "$OUT")"

"$ZIG" cc \
  --target=x86_64-windows-gnu \
  -O2 \
  -Wall -Wextra \
  -Wl,--subsystem,windows \
  -Wl,--dynamicbase \
  -Wl,--nxcompat \
  -Wl,-s \
  -o "$OUT" \
  "$ROOT"/receiver/core.c \
  "$ROOT"/receiver/gui.c \
  "$ROOT"/src/crypto.c \
  -lws2_32 -lcomctl32 -lshell32 -luser32 -lgdi32 -lbcrypt

ls -lh "$OUT"
