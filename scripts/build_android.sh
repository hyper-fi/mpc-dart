#!/usr/bin/env bash
# Cross-compiles the Go bridge for Android with 16 KB page alignment
# (Google Play requirement for Android 15+ / targeting API 35+).
#
# Requirements: Go, Android NDK r27+ (r27 enables 16 KB alignment by default;
# we additionally pass explicit linker flags below).
#
# Usage: scripts/build_android.sh [arm64-v8a]
set -euo pipefail
cd "$(dirname "$0")/../go/bridge"

ABI="${1:-arm64-v8a}"
API="${ANDROID_API:-24}"

if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
  NDK="$ANDROID_NDK_HOME"
elif [[ -n "${ANDROID_HOME:-}" && -d "$ANDROID_HOME/ndk" ]]; then
  NDK="$ANDROID_HOME/ndk/$(ls "$ANDROID_HOME/ndk" | sort -V | tail -1)"
else
  echo "error: ANDROID_NDK_HOME or ANDROID_HOME with ndk/ directory required" >&2
  exit 1
fi
echo "using NDK: $NDK"

HOST_TAG=darwin-x86_64
[[ "$(uname -s)" == Linux* ]] && HOST_TAG=linux-x86_64
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG"

OUT_DIR="$(cd .. && pwd)/../native/android/$ABI"
mkdir -p "$OUT_DIR"

case "$ABI" in
  arm64-v8a)
    GOARCH=arm64
    CC="$TOOLCHAIN/bin/aarch64-linux-android$API-clang"
    ;;
  x86_64)
    GOARCH=amd64
    CC="$TOOLCHAIN/bin/x86_64-linux-android$API-clang"
    ;;
  armeabi-v7a)
    GOARCH=arm
    CC="$TOOLCHAIN/bin/armv7a-linux-androideabi$API-clang"
    ;;
  *)
    echo "unsupported ABI: $ABI" >&2
    exit 1
    ;;
esac

# -z max-page-size / common-page-size = 16384 keeps every LOAD segment aligned
# to 16 KB, which is what Google Play's 16 KB device requirement checks.
LDFLAGS="-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"

GOOS=android GOARCH="$GOARCH" CGO_ENABLED=1 CC="$CC" \
  go build -buildmode=c-shared -trimpath \
  -ldflags="-s -w -extldflags '$LDFLAGS'" \
  -o "$OUT_DIR/libmpc.so" .

echo "built $OUT_DIR/libmpc.so"
scripts_dir="$(cd "$(dirname "$0")" && pwd)"
bash "$scripts_dir/verify_16kb.sh" "$OUT_DIR/libmpc.so"
