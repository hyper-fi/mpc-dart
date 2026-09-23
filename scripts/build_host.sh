#!/usr/bin/env bash
# Builds the bridge as a host (macOS arm64) dylib, used by `flutter test` in
# this repository and for quick local sanity checks.
set -euo pipefail
cd "$(dirname "$0")/../go/bridge"

GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 \
  go build -buildmode=c-shared -trimpath -o libmpc.dylib .

echo "built $(pwd)/libmpc.dylib"
