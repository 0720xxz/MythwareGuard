#!/bin/bash
# Cross-build MythwareGuard.exe (x86_64 Windows GUI) from any host with zig.
set -euo pipefail

ZIG="${ZIG:-/opt/zig/zig}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$ROOT/dist/MythwareGuard.exe}"

mkdir -p "$(dirname "$OUT")"

# rebuild the resource blob if the .rc is present (icon + version info)
if [ -f "$ROOT/resources/guard.rc" ]; then
  ( cd "$ROOT/resources" && "$ZIG" rc guard.rc guard.res ) >/dev/null 2>&1 || true
fi
RES_ARG=""
[ -f "$ROOT/resources/guard.res" ] && RES_ARG="$ROOT/resources/guard.res"

"$ZIG" cc \
  --target=x86_64-windows-gnu \
  -O2 \
  -Wall -Wextra \
  -Wl,--subsystem,windows \
  -Wl,--dynamicbase \
  -Wl,--nxcompat \
  -Wl,-s \
  -o "$OUT" \
  "$ROOT"/src/common.c \
  "$ROOT"/src/win.c \
  "$ROOT"/src/guard.c \
  "$ROOT"/src/engine.c \
  "$ROOT"/src/setup.c \
  "$ROOT"/src/report.c \
  "$ROOT"/src/crypto.c \
  "$ROOT"/src/main.c \
  $RES_ARG \
  -lwtsapi32 -luserenv -ladvapi32 -lshell32 -lole32 -lws2_32 -liphlpapi -lbcrypt

ls -lh "$OUT"
