#!/usr/bin/env bash
# Builds the Go bridge for iOS (device arm64 + simulator arm64) and packages
# them as MpcDart.xcframework under native/ios/.
#
# GOOS=ios does not support -buildmode=c-shared, so we use the officially
# supported -buildmode=c-archive and link the static archive into a dynamic
# library with clang (same approach as gomobile bind).
#
# Requirements: Go, Xcode.
set -euo pipefail
cd "$(dirname "$0")/../go/bridge"

ROOT="$(cd ../.. && pwd)"
BUILD="$ROOT/go/build/ios"
rm -rf "$BUILD"
mkdir -p "$BUILD/device" "$BUILD/simulator"

MIN_IOS="${MIN_IOS:-13.0}"

# System frameworks the Go runtime may reference at link time.
FRAMEWORKS="-framework Foundation -framework CoreFoundation -framework Security -framework SystemConfiguration -framework CFNetwork"

link_dylib() { # $1: sdk name, $2: out dir
  xcrun --sdk "$1" clang -arch arm64 -dynamiclib \
    -Wl,-force_load,"$2/libmpc.a" \
    -Wl,-install_name,@rpath/libmpc.dylib \
    $FRAMEWORKS \
    -o "$2/libmpc.dylib"
}

echo "--- building ios/arm64 (device) ---"
GOOS=ios GOARCH=arm64 CGO_ENABLED=1 \
  CGO_CFLAGS="-isysroot $(xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=$MIN_IOS" \
  go build -buildmode=c-archive -trimpath -o "$BUILD/device/libmpc.a" .
link_dylib iphoneos "$BUILD/device"

echo "--- building ios/arm64 (simulator) ---"
GOOS=ios GOARCH=arm64 CGO_ENABLED=1 \
  CGO_CFLAGS="-isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) -target arm64-apple-ios$MIN_IOS-simulator" \
  go build -buildmode=c-archive -trimpath -o "$BUILD/simulator/libmpc.a" .
link_dylib iphonesimulator "$BUILD/simulator"

echo "--- creating xcframework ---"
OUT="$ROOT/native/ios/MpcDart.xcframework"
rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library "$BUILD/device/libmpc.dylib" \
  -library "$BUILD/simulator/libmpc.dylib" \
  -output "$OUT"

echo "built $OUT"
