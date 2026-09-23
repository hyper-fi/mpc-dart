/// Flutter FFI bindings for threshold signatures.
///
/// Exposes:
///   - {2,n}-threshold ECDSA (Lindell 17): keygen, share refresh, unhardened
///     BIP32-style derived public keys and 2-party signing.
///   - 2-party Ed25519 signing with a 3-round DKG.
///
/// The heavy crypto runs on the Go side inside a native library; all calls
/// are dispatched to a background isolate so the UI thread is never blocked.
library mpc_dart;

import 'dart:convert';
import 'dart:isolate';

import 'src/bindings.dart';
import 'src/models.dart';

export 'src/models.dart'
    show
        TssMessage,
        PublicKey,
        Ed25519KeyShare,
        EcdsaSignature,
        Ed25519PartialSignature,
        Ed25519Verification;
export 'src/bindings.dart' show MpcException;

String? _libPath;

/// Runs [fn] on a background isolate with a fresh bindings instance.
Future<T> _run<T>(T Function(MpcBindings b) fn) {
  // Capture locally: statics are re-initialised in a fresh isolate.
  final path = _libPath;
  return Isolate.run(() => fn(MpcBindings.load(path: path)));
}

/// Configures the plugin.
abstract final class Mpc {
  /// Explicit native library path. Only needed for host-side tests
  /// (`flutter test` loading a locally built dylib); on Android/iOS the
  /// bundled library is discovered automatically.
  static void configure({String? libPath}) => _libPath = libPath;

  /// Version of the native core.
  static Future<String> version() => _run((b) => b.version());

  /// SHA-256 of hex-encoded [dataHex], returned as hex. Convenience for
  /// hashing messages before signing.
  static Future<String> sha256Hex(String dataHex) => _run((b) => b.sha256Hex(dataHex));
}

/// {2,n}-threshold ECDSA operations.
///
/// Key shares are opaque JSON strings produced/consumed by this library;
/// store them securely and treat them as secrets.
abstract final class Ecdsa {
  /// Generates a fresh {2,3} key set. Returns three key shares (index i =
  /// participant id i+1). Each participant must hold exactly one share.
  static Future<List<String>> keygen() async =>
      _run((b) => b.ecdsaKeygen());

  /// Refreshes two existing key shares into a new key set with the same
  /// public key. Use when a share is lost or a new participant joins.
  static Future<List<String>> refresh(String share1st, String share2nd) =>
      _run((b) => b.ecdsaRefresh(share1st, share2nd));

  /// Derives the unhardened BIP32-style child public key for [childIdx].
  /// Returns `X || Y` hex (128 chars, no 04 prefix).
  static Future<String> derivedPubKey(String share1st, String share2nd, int childIdx) =>
      _run((b) => b.ecdsaDerivedPubKey(share1st, share2nd, childIdx));

  /// Signs a 32-byte [messageHashHex] (hex encoded) with two key shares.
  static Future<EcdsaSignature> sign(
      String share1st, String share2nd, int childIdx, String messageHashHex) async {
    final res = await _run(
        (b) => b.ecdsaSign(share1st, share2nd, childIdx, messageHashHex));
    return EcdsaSignature.fromJson(res);
  }
}

/// Ed25519 distributed key generation (3 rounds) session.
///
/// Participants run the same rounds in lockstep, relaying [TssMessage]s via
/// their own transport. Messages produced in a round must be delivered to
/// their recipients (`msg.to`) before the next round is entered.
class Ed25519DkgSession {
  Ed25519DkgSession({required this.deviceNumber, required this.total})
      : assert(deviceNumber >= 1),
        assert(total >= 2),
        assert(deviceNumber <= total);

  /// 1-based participant id.
  final int deviceNumber;

  /// Total number of participants (n in {2,n}).
  final int total;

  int? _handle;

  bool get isClosed => _handle == null;

  /// Allocates the native session state.
  Future<void> start() async {
    _handle = await _run((b) => b.ed25519DkgNew(deviceNumber, total));
  }

  /// Round 1: produces this party's broadcast messages.
  Future<List<TssMessage>> step1() async {
    final h = _ensureOpen();
    final res = await _run((b) => b.ed25519DkgStep1(h));
    return _parseMessages(_resultOf(res));
  }

  /// Round 2: consumes round-1 messages addressed to this party.
  Future<List<TssMessage>> step2(List<TssMessage> incoming) async {
    final h = _ensureOpen();
    final res = await _run((b) => b.ed25519DkgStep2(h, encodeMessages(incoming)));
    return _parseMessages(_resultOf(res));
  }

  /// Round 3: consumes round-2 messages addressed to this party and returns
  /// the key share. The session is consumed.
  Future<Ed25519KeyShare> step3(List<TssMessage> incoming) async {
    final h = _ensureOpen();
    final res = await _run((b) => b.ed25519DkgStep3(h, encodeMessages(incoming)));
    _handle = null;
    return Ed25519KeyShare.fromJson(_resultOf(res)['keyShare'] as Map<String, dynamic>);
  }

  /// Aborts the session and releases native state.
  Future<void> abort() async {
    final h = _handle;
    if (h == null) return;
    _handle = null;
    await _run((b) => b.ed25519DkgFree(h));
  }

  int _ensureOpen() {
    final h = _handle;
    if (h == null) throw StateError('session not started or already closed');
    return h;
  }
}

/// Ed25519 2-party signing (3 rounds) session.
class Ed25519SignSession {
  Ed25519SignSession({
    required this.deviceNumber,
    required this.partList,
    required this.keyShare,
    required this.messageHex,
  })  : assert(partList.length == 2, 'this library implements 2-of-n signing'),
        assert(partList.contains(deviceNumber), 'partList must contain deviceNumber');

  /// 1-based participant id.
  final int deviceNumber;

  /// The two participating device ids, e.g. [1, 2].
  final List<int> partList;

  /// This party's key share from the DKG.
  final Ed25519KeyShare keyShare;

  /// Message to sign, hex encoded.
  final String messageHex;

  int? _handle;

  bool get isClosed => _handle == null;

  /// Allocates the native session state.
  Future<void> start() async {
    _handle = await _run((b) => b.ed25519SignNew(deviceNumber, partList.length,
        jsonEncode(partList), keyShare.shareI, jsonEncode(keyShare.publicKey.toJson()),
        messageHex));
  }

  /// Round 1: produces this party's broadcast messages.
  Future<List<TssMessage>> step1() async {
    final h = _ensureOpen();
    final res = await _run((b) => b.ed25519SignStep1(h));
    return _parseMessages(_resultOf(res));
  }

  /// Round 2: consumes round-1 messages addressed to this party.
  Future<List<TssMessage>> step2(List<TssMessage> incoming) async {
    final h = _ensureOpen();
    final res = await _run((b) => b.ed25519SignStep2(h, encodeMessages(incoming)));
    return _parseMessages(_resultOf(res));
  }

  /// Round 3: consumes round-2 messages addressed to this party and returns
  /// this party's partial signature. The session is consumed.
  Future<Ed25519PartialSignature> step3(List<TssMessage> incoming) async {
    final h = _ensureOpen();
    final res = await _run((b) => b.ed25519SignStep3(h, encodeMessages(incoming)));
    _handle = null;
    return Ed25519PartialSignature.fromJson(_resultOf(res));
  }

  /// Aborts the session and releases native state.
  Future<void> abort() async {
    final h = _handle;
    if (h == null) return;
    _handle = null;
    await _run((b) => b.ed25519SignFree(h));
  }

  int _ensureOpen() {
    final h = _handle;
    if (h == null) throw StateError('session not started or already closed');
    return h;
  }
}

/// Ed25519 signature assembly and verification.
abstract final class Ed25519 {
  /// Assembles the final signature from the two parties' partial signatures
  /// and verifies it against the aggregate [publicKey] over [messageHex].
  static Future<Ed25519Verification> verify(
    Ed25519PartialSignature first,
    Ed25519PartialSignature second, {
    required String messageHex,
    required PublicKey publicKey,
  }) async {
    final res = await _run((b) => b.ed25519VerifyResult(
        first.si, second.si, first.r, messageHex, jsonEncode(publicKey.toJson())));
    return Ed25519Verification.fromJson(res);
  }
}

List<TssMessage> _parseMessages(Map<String, dynamic> result) =>
    (result['messages'] as List)
        .map((m) => TssMessage.fromJson(m as Map<String, dynamic>))
        .toList();

Map<String, dynamic> _resultOf(Map<String, dynamic> envelope) =>
    envelope['result'] as Map<String, dynamic>;
