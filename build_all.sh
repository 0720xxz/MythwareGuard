#!/bin/bash
# Build both products.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
"$ROOT/build.sh"
"$ROOT/build_receiver.sh"
