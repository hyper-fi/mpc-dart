# mpc_dart

Flutter FFI bindings for threshold signatures, powered by a Go core
([okx/threshold-lib](https://github.com/okx/threshold-lib)).

Features:

- **{2,3}-threshold ECDSA** (Lindell 17 protocol): key generation, key share
  refresh, unhardened BIP32-style child public key derivation, 2-party signing.
- **Ed25519 2-party signing** with a 3-round DKG (distributed key generation).
- Pure FFI (no method channels); all crypto runs on a Go runtime inside the
  native library. Dart calls are dispatched to a background isolate.

## Installation

```yaml
dependencies:
  mpc_dart:
    git:
      url: https://github.com/hyper-fi/mpc-dart.git
      ref: main
```

Prebuilt native binaries are bundled in this repository for:

| Platform | Architectures |
|----------|---------------|
| Android  | arm64-v8a     |
| iOS      | arm64 (device + simulator) |

### 16 KB page size (Google Play requirement)

The Android `.so` files are built and verified with 16 KB ELF segment
alignment (`-Wl,-z,max-page-size=16384`), which is required for apps
targeting Android 15+ devices with 16 KB memory pages. See
`scripts/verify_16kb.sh`.

## Usage

### ECDSA

```dart
import 'package:mpc_dart/mpc_dart.dart';

// 1. Generate a {2,3} key set — three shares, one per participant.
final shares = await Ecdsa.keygen();

// 2. Derive an unhardened BIP32 child public key (hex, X||Y).
final pubKey = await Ecdsa.derivedPubKey(shares[0], shares[1], 100);

// 3. Sign a 32-byte message hash (hex encoded).
final sig = await Ecdsa.sign(shares[0], shares[1], 100, messageHashHex);

// Optional: refresh shares (same public key, new secrets).
final refreshed = await Ecdsa.refresh(shares[0], shares[1]);
```

### Ed25519 (interactive, 3-round DKG + 3-round signing)

Each participant runs the same rounds in lockstep and relays `TssMessage`s
to their recipients (`msg.to`) over your own transport.

```dart
// DKG — three participants, everyone ends up with a share of one key.
final sessions = [1, 2, 3].map((d) => Ed25519DkgSession(deviceNumber: d, total: 3));
for (final s in sessions) { await s.start(); }

final round1 = <TssMessage>[];
for (final s in sessions) { round1.addAll(await s.step1()); }

final round2 = <TssMessage>[];
for (final s in sessions) {
  round2.addAll(await s.step2(round1.where((m) => m.to == s.deviceNumber).toList()));
}

final shares = <int, Ed25519KeyShare>{};
for (final s in sessions) {
  shares[s.deviceNumber] = await s.step3(round2.where((m) => m.to == s.deviceNumber).toList());
}

// Signing between participants 1 and 2.
const messageHex = '...'; // hex-encoded message bytes
final p1 = Ed25519SignSession(deviceNumber: 1, partList: [1, 2], keyShare: shares[1]!, messageHex: messageHex);
final p2 = Ed25519SignSession(deviceNumber: 2, partList: [1, 2], keyShare: shares[2]!, messageHex: messageHex);
await p1.start();
await p2.start();

final r1 = await p1.step1();
final r2 = await p2.step1();
final r1b = await p1.step2(r2.where((m) => m.to == 1).toList());
final r2b = await p2.step2(r1.where((m) => m.to == 2).toList());
final partial1 = await p1.step3(r2b.where((m) => m.to == 1).toList());
final partial2 = await p2.step3(r1b.where((m) => m.to == 2).toList());

final ver = await Ed25519.verify(partial1, partial2,
    messageHex: messageHex, publicKey: shares[1]!.publicKey);
print(ver.valid);       // true
print(ver.signatureHex); // 64-byte signature (r||s), hex
```

See `example/` for a runnable app and `test/mpc_dart_test.dart` for full
protocol flows.

## Rebuilding the native libraries

Requires Go (1.22+). Android additionally needs the NDK (r27+), iOS needs Xcode.

```bash
scripts/build_host.sh      # macOS arm64 dylib used by `flutter test`
scripts/build_android.sh   # arm64-v8a, 16 KB aligned (verified via llvm-readelf)
scripts/build_ios.sh       # device + simulator dylibs -> MpcDart.xcframework
```

Artifacts land in `native/` and are committed so consumers of the git
dependency do not need the Go toolchain.

## Running tests

```bash
scripts/build_host.sh
flutter test
```

## Project structure

```
go/threshold-lib/   vendored Go library (github.com/okx/threshold-lib)
go/bridge/          cgo bridge (C ABI, JSON envelopes, session handles)
native/             prebuilt binaries (android .so, ios .xcframework)
lib/                Dart FFI API
scripts/            native build & verification scripts
example/            demo app
```

## License

Apache-2.0. The vendored Go library and the bridge inherit the upstream
license (see [LICENSE](LICENSE)).
