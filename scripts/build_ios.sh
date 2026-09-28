#!/usr/bin/env bash
# Builds the Go bridge for iOS (device arm64 + simulator arm64) and packages
# the static archives as MpcDart.xcframework under native/ios/.
#
# We build -buildmode=c-archive static libraries and let the CocoaPods podspec
# force-load them into the mpc_dart.framework binary at app build time.
# (A previous version packaged dynamic dylibs, but CocoaPods neither linked
# nor embedded bare dylibs from an xcframework, which made DynamicLibrary
# fail to look up symbols at runtime.)
#
# Requirements: Go, Xcode.
set -euo pipefail
cd "$(dirname "$0")/../go/bridge"

ROOT="$(cd ../.. && pwd)"
BUILD="$ROOT/go/build/ios"
rm -rf "$BUILD"
mkdir -p "$BUILD/device" "$BUILD/simulator"

MIN_IOS="${MIN_IOS:-13.0}"

echo "--- building ios/arm64 (device) ---"
GOOS=ios GOARCH=arm64 CGO_ENABLED=1 \
  CGO_CFLAGS="-isysroot $(xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=$MIN_IOS" \
  go build -buildmode=c-archive -trimpath -o "$BUILD/device/libmpc.a" .

echo "--- building ios/arm64 (simulator) ---"
GOOS=ios GOARCH=arm64 CGO_ENABLED=1 \
  CGO_CFLAGS="-isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) -target arm64-apple-ios$MIN_IOS-simulator" \
  go build -buildmode=c-archive -trimpath -o "$BUILD/simulator/libmpc.a" .

echo "--- creating xcframework ---"
OUT="$ROOT/native/ios/MpcDart.xcframework"
rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library "$BUILD/device/libmpc.a" \
  -library "$BUILD/simulator/libmpc.a" \
  -output "$OUT"

echo "built $OUT"
