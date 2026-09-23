import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// dart:ffi bindings for the Go bridge (`libmpc`).
///
/// Every C entry point returns a JSON envelope
/// `{"ok":bool,"error":String?,"result":Any?}` allocated by the Go side. The
/// [MpcBindings] methods copy it into the Dart heap and release the native
/// memory; argument strings are also converted and freed here so callers
/// never touch FFI types.
class MpcBindings {
  MpcBindings._(DynamicLibrary lib)
      : _version = lib.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>(
            'MpcVersion'),
        _ecdsaKeygen = lib.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>(
            'MpcEcdsaKeygen'),
        _ecdsaRefresh = lib.lookupFunction<
                Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
                Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('MpcEcdsaRefresh'),
        _ecdsaDerivedPubKey = lib.lookupFunction<
                Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Uint32),
                Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, int)>('MpcEcdsaDerivedPubKey'),
        _ecdsaSign = lib.lookupFunction<
                Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Uint32, Pointer<Utf8>),
                Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, int, Pointer<Utf8>)>(
            'MpcEcdsaSign'),
        _ed25519DkgNew = lib.lookupFunction<Pointer<Utf8> Function(Int64, Int64),
            Pointer<Utf8> Function(int, int)>('MpcEd25519DkgNew'),
        _ed25519DkgStep1 = lib.lookupFunction<Pointer<Utf8> Function(Int64),
            Pointer<Utf8> Function(int)>('MpcEd25519DkgStep1'),
        _ed25519DkgStep2 = lib.lookupFunction<Pointer<Utf8> Function(Int64, Pointer<Utf8>),
            Pointer<Utf8> Function(int, Pointer<Utf8>)>('MpcEd25519DkgStep2'),
        _ed25519DkgStep3 = lib.lookupFunction<Pointer<Utf8> Function(Int64, Pointer<Utf8>),
            Pointer<Utf8> Function(int, Pointer<Utf8>)>('MpcEd25519DkgStep3'),
        _ed25519DkgFree = lib.lookupFunction<Pointer<Utf8> Function(Int64),
            Pointer<Utf8> Function(int)>('MpcEd25519DkgFree'),
        _ed25519SignNew = lib.lookupFunction<
                Pointer<Utf8> Function(Int64, Int64, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
                    Pointer<Utf8>),
                Pointer<Utf8> Function(int, int, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
                    Pointer<Utf8>)>('MpcEd25519SignNew'),
        _ed25519SignStep1 = lib.lookupFunction<Pointer<Utf8> Function(Int64),
            Pointer<Utf8> Function(int)>('MpcEd25519SignStep1'),
        _ed25519SignStep2 = lib.lookupFunction<Pointer<Utf8> Function(Int64, Pointer<Utf8>),
            Pointer<Utf8> Function(int, Pointer<Utf8>)>('MpcEd25519SignStep2'),
        _ed25519SignStep3 = lib.lookupFunction<Pointer<Utf8> Function(Int64, Pointer<Utf8>),
            Pointer<Utf8> Function(int, Pointer<Utf8>)>('MpcEd25519SignStep3'),
        _ed25519SignFree = lib.lookupFunction<Pointer<Utf8> Function(Int64),
            Pointer<Utf8> Function(int)>('MpcEd25519SignFree'),
        _ed25519Verify = lib.lookupFunction<
                Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
                    Pointer<Utf8>),
                Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
                    Pointer<Utf8>)>('MpcEd25519Verify'),
        _sha256Hex = lib.lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>),
            Pointer<Utf8> Function(Pointer<Utf8>)>('MpcSha256Hex'),
        _freeCString = lib.lookupFunction<Void Function(Pointer<Utf8>), void Function(Pointer<Utf8>)>(
            'MpcFreeCString');

  /// Opens the bundled native library.
  ///
  /// [path] overrides discovery (used by tests to load the host dylib).
  factory MpcBindings.load({String? path}) {
    final lib = _openLibrary(path);
    return MpcBindings._(lib);
  }

  static DynamicLibrary _openLibrary(String? path) {
    if (path != null) return DynamicLibrary.open(path);
    if (Platform.isAndroid) return DynamicLibrary.open('libmpc.so');
    // iOS: the MpcDart.xcframework is embedded and loaded at app launch.
    if (Platform.isIOS) return DynamicLibrary.process();
    throw UnsupportedError(
        'mpc_dart: platform ${Platform.operatingSystem} is not supported. '
        'Provide an explicit library path for host tests.');
  }

  final Pointer<Utf8> Function() _version;
  final Pointer<Utf8> Function() _ecdsaKeygen;
  final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) _ecdsaRefresh;
  final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, int) _ecdsaDerivedPubKey;
  final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, int, Pointer<Utf8>) _ecdsaSign;
  final Pointer<Utf8> Function(int, int) _ed25519DkgNew;
  final Pointer<Utf8> Function(int) _ed25519DkgStep1;
  final Pointer<Utf8> Function(int, Pointer<Utf8>) _ed25519DkgStep2;
  final Pointer<Utf8> Function(int, Pointer<Utf8>) _ed25519DkgStep3;
  final Pointer<Utf8> Function(int) _ed25519DkgFree;
  final Pointer<Utf8> Function(int, int, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>)
      _ed25519SignNew;
  final Pointer<Utf8> Function(int) _ed25519SignStep1;
  final Pointer<Utf8> Function(int, Pointer<Utf8>) _ed25519SignStep2;
  final Pointer<Utf8> Function(int, Pointer<Utf8>) _ed25519SignStep3;
  final Pointer<Utf8> Function(int) _ed25519SignFree;
  final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
      Pointer<Utf8>) _ed25519Verify;
  final Pointer<Utf8> Function(Pointer<Utf8>) _sha256Hex;
  final void Function(Pointer<Utf8>) _freeCString;

  // -- helpers ---------------------------------------------------------------

  /// Calls [fn], copies the returned envelope into the Dart heap and frees
  /// the native string.
  Map<String, dynamic> _invoke(Pointer<Utf8> Function() fn) {
    final ptr = fn();
    final raw = ptr.toDartString();
    _freeCString(ptr);
    return _parseEnvelope(raw);
  }

  /// Copies [s] into a native string, runs [fn] with it and frees it.
  R _withArg<R>(String s, R Function(Pointer<Utf8>) fn) {
    final ptr = s.toNativeUtf8();
    try {
      return fn(ptr);
    } finally {
      malloc.free(ptr);
    }
  }

  static Map<String, dynamic> _parseEnvelope(String raw) {
    final env = jsonDecode(raw) as Map<String, dynamic>;
    if (env['ok'] != true) {
      throw MpcException((env['error'] as String?) ?? 'unknown mpc error');
    }
    return env;
  }

  // -- version -----------------------------------------------------------------

  String version() => _invoke(_version)['result'] as String;

  String sha256Hex(String dataHex) =>
      _withArg(dataHex, (p) => _invoke(() => _sha256Hex(p)))['result'] as String;

  // -- ECDSA -------------------------------------------------------------------

  List<String> ecdsaKeygen() =>
      (_invoke(_ecdsaKeygen)['result'] as List).cast<String>();

  List<String> ecdsaRefresh(String share1st, String share2nd) => _withArg(
        share1st,
        (a) => _withArg(share2nd, (b) => _invoke(() => _ecdsaRefresh(a, b))),
      )['result'].cast<String>() as List<String>;

  String ecdsaDerivedPubKey(String share1st, String share2nd, int childIdx) => _withArg(
        share1st,
        (a) => _withArg(
          share2nd,
          (b) => _invoke(() => _ecdsaDerivedPubKey(a, b, childIdx)),
        ),
      )['result'] as String;

  Map<String, dynamic> ecdsaSign(
      String share1st, String share2nd, int childIdx, String messageHashHex) {
    return _withArg(
      share1st,
      (a) => _withArg(
        share2nd,
        (b) => _withArg(
          messageHashHex,
          (h) => _invoke(() => _ecdsaSign(a, b, childIdx, h)),
        ),
      ),
    )['result'] as Map<String, dynamic>;
  }

  // -- Ed25519 DKG -------------------------------------------------------------

  int ed25519DkgNew(int deviceNumber, int total) =>
      (_invoke(() => _ed25519DkgNew(deviceNumber, total))['result']
          as Map<String, dynamic>)['handle'] as int;

  Map<String, dynamic> ed25519DkgStep1(int handle) =>
      _invoke(() => _ed25519DkgStep1(handle));

  Map<String, dynamic> ed25519DkgStep2(int handle, String messagesJson) => _withArg(
        messagesJson,
        (m) => _invoke(() => _ed25519DkgStep2(handle, m)),
      );

  Map<String, dynamic> ed25519DkgStep3(int handle, String messagesJson) => _withArg(
        messagesJson,
        (m) => _invoke(() => _ed25519DkgStep3(handle, m)),
      );

  void ed25519DkgFree(int handle) => _invoke(() => _ed25519DkgFree(handle));

  // -- Ed25519 signing -----------------------------------------------------------

  int ed25519SignNew(int deviceNumber, int threshold, String partListJson, String shareI,
      String pubKeyJson, String messageHex) {
    final result = _withArg(
      partListJson,
      (p) => _withArg(
        shareI,
        (s) => _withArg(
          pubKeyJson,
          (k) => _withArg(
            messageHex,
            (m) => _invoke(() => _ed25519SignNew(deviceNumber, threshold, p, s, k, m)),
          ),
        ),
      ),
    )['result'] as Map<String, dynamic>;
    return result['handle'] as int;
  }

  Map<String, dynamic> ed25519SignStep1(int handle) =>
      _invoke(() => _ed25519SignStep1(handle));

  Map<String, dynamic> ed25519SignStep2(int handle, String messagesJson) => _withArg(
        messagesJson,
        (m) => _invoke(() => _ed25519SignStep2(handle, m)),
      );

  Map<String, dynamic> ed25519SignStep3(int handle, String messagesJson) => _withArg(
        messagesJson,
        (m) => _invoke(() => _ed25519SignStep3(handle, m)),
      );

  void ed25519SignFree(int handle) => _invoke(() => _ed25519SignFree(handle));

  Map<String, dynamic> ed25519VerifyResult(String si1, String si2, String r, String messageHex,
      String pubKeyJson) {
    return _withArg(
      si1,
      (a) => _withArg(
        si2,
        (b) => _withArg(
          r,
          (rr) => _withArg(
            messageHex,
            (m) => _withArg(
              pubKeyJson,
              (k) => _invoke(() => _ed25519Verify(a, b, rr, m, k)),
            ),
          ),
        ),
      ),
    )['result'] as Map<String, dynamic>;
  }
}

/// Error raised when the native side reports a failure.
class MpcException implements Exception {
  MpcException(this.message);
  final String message;

  @override
  String toString() => 'MpcException: $message';
}
