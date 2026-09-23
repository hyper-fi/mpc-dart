#!/usr/bin/env bash
# Verifies that an ELF shared object has 16 KB (0x4000) LOAD segment
# alignment — required by Google Play for Android 15+ 16 KB devices.
set -euo pipefail

SO="$1"
if [[ ! -f "$SO" ]]; then
  echo "file not found: $SO" >&2
  exit 1
fi

if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
  NDK="$ANDROID_NDK_HOME"
elif [[ -n "${ANDROID_HOME:-}" && -d "$ANDROID_HOME/ndk" ]]; then
  NDK="$ANDROID_HOME/ndk/$(ls "$ANDROID_HOME/ndk" | sort -V | tail -1)"
else
  echo "error: NDK required for llvm-readelf" >&2
  exit 1
fi

HOST_TAG=darwin-x86_64
[[ "$(uname -s)" == Linux* ]] && HOST_TAG=linux-x86_64
READELF="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin/llvm-readelf"

echo "--- LOAD segments of $SO ---"
"$READELF" -lW "$SO" | grep -E "LOAD"

# p_align of the last LOAD column must be 0x4000 (16384).
BAD=$("$READELF" -lW "$SO" | awk '/LOAD/ && $NF != "0x4000" {print}')
if [[ -n "$BAD" ]]; then
  echo "FAIL: LOAD segment(s) not 16 KB aligned:" >&2
  echo "$BAD" >&2
  exit 1
fi
echo "OK: all LOAD segments are 16 KB (0x4000) aligned"
