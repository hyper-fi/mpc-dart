import 'dart:convert';
import 'dart:io';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';
import 'package:mpc_dart/mpc_dart.dart';

String sha256HexOf(String input) =>
    hex.encode(crypto.sha256.convert(utf8.encode(input)).bytes);

void main() {
  setUpAll(() {
    final candidates = [
      Platform.environment['MPC_DART_LIB'],
      'go/bridge/libmpc.dylib',
      '../go/bridge/libmpc.dylib',
    ].whereType<String>().where((p) => File(p).existsSync()).toList();
    if (candidates.isEmpty) {
      fail('host dylib not found — run scripts/build_host.sh first');
    }
    Mpc.configure(libPath: candidates.first);
  });

  test('version', () async {
    expect(await Mpc.version(), '1.0.0');
  });

  test('sha256 helper matches dart crypto', () async {
    expect(await Mpc.sha256Hex(hex.encode(utf8.encode('hello'))), sha256HexOf('hello'));
  });

  test('ecdsa full flow: keygen -> refresh -> derivedPubKey -> sign', () async {
    final shares = await Ecdsa.keygen();
    expect(shares.length, 3);
    expect(jsonDecode(shares[0])['Id'], 1);
    expect(jsonDecode(shares[1])['Id'], 2);
    expect(jsonDecode(shares[2])['Id'], 3);

    final refreshed = await Ecdsa.refresh(shares[0], shares[1]);
    expect(refreshed.length, 3);

    final pubKey = await Ecdsa.derivedPubKey(refreshed[0], refreshed[1], 100);
    expect(pubKey.length, 128);
    expect(BigInt.tryParse(pubKey, radix: 16), isNotNull);

    final sig = await Ecdsa.sign(refreshed[0], refreshed[1], 100, sha256HexOf('hello'));
    // r/s are 64-char hex strings (32-byte big-endian, zero padded)
    expect(sig.r.length, 64);
    expect(sig.s.length, 64);
    expect(BigInt.tryParse(sig.r, radix: 16), greaterThan(BigInt.zero));
    expect(BigInt.tryParse(sig.s, radix: 16), greaterThan(BigInt.zero));
  });

  test('ed25519 dkg between 3 parties + 2-party sign', () async {
    final sessions = [1, 2, 3]
        .map((dev) => Ed25519DkgSession(deviceNumber: dev, total: 3))
        .toList();
    for (final s in sessions) {
      await s.start();
    }

    // round 1 broadcast
    final round1 = <TssMessage>[];
    for (final s in sessions) {
      round1.addAll(await s.step1());
    }

    // round 2
    final round2 = <TssMessage>[];
    for (final s in sessions) {
      round2.addAll(await s.step2(forMe(round1, s.deviceNumber)));
    }

    // round 3 -> key shares
    final shares = <int, Ed25519KeyShare>{};
    for (final s in sessions) {
      shares[s.deviceNumber] = await s.step3(forMe(round2, s.deviceNumber));
    }
    expect(shares.length, 3);

    final pub1 = shares[1]!.publicKey;
    final pub2 = shares[2]!.publicKey;
    final pub3 = shares[3]!.publicKey;
    expect(pub1.x, pub2.x);
    expect(pub1.y, pub2.y);
    expect(pub1.x, pub3.x);
    expect(pub1.y, pub3.y);

    // signing between parties 1 and 2
    final messageHex = sha256HexOf('hello');
    const partList = [1, 2];
    final s1 = Ed25519SignSession(
        deviceNumber: 1, partList: partList, keyShare: shares[1]!, messageHex: messageHex);
    final s2 = Ed25519SignSession(
        deviceNumber: 2, partList: partList, keyShare: shares[2]!, messageHex: messageHex);
    await s1.start();
    await s2.start();

    final r1 = await s1.step1();
    final r2 = await s2.step1();

    final r1b = await s1.step2(forMe(r2, 1));
    final r2b = await s2.step2(forMe(r1, 2));

    final p1 = await s1.step3(forMe(r2b, 1));
    final p2 = await s2.step3(forMe(r1b, 2));
    expect(p1.r, p2.r, reason: 'nonce commitment R must match across parties');

    final ver = await Ed25519.verify(p1, p2, messageHex: messageHex, publicKey: pub1);
    expect(ver.valid, isTrue);
    expect(ver.signatureHex.length, 128);
  });

  test('ed25519 sessions can be aborted', () async {
    final s = Ed25519DkgSession(deviceNumber: 1, total: 2);
    await s.start();
    await s.abort();
    expect(s.isClosed, isTrue);
    await expectLater(s.step1(), throwsA(isA<StateError>()));
  });

  test('ecdsa rejects bad hash hex', () async {
    final shares = await Ecdsa.keygen();
    await expectLater(
      Ecdsa.sign(shares[0], shares[1], 0, 'zz'),
      throwsA(isA<MpcException>()),
    );
  });
}

List<TssMessage> forMe(List<TssMessage> all, int id) =>
    all.where((m) => m.to == id).toList();
