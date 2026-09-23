# Changelog

All notable changes to this project will be documented in this file.

## 1.0.0

- Initial release.
- {2,3}-threshold ECDSA: keygen, refresh, BIP32-style derived public keys,
  2-party signing (Lindell 17).
- Ed25519: 3-round DKG, 2-party signing, signature assembly & verification.
- Prebuilt natives: Android arm64-v8a (16 KB page aligned), iOS arm64
  (device + simulator) packaged as MpcDart.xcframework.
