import 'package:flutter/material.dart';

import 'package:mpc_dart/mpc_dart.dart';

void main() => runApp(const MyApp());

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'mpc_dart example',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  String _output = 'Press a button to run a protocol locally.';

  void _run(Future<String> Function() action) async {
    setState(() => _output = 'Running…');
    try {
      final result = await action();
      setState(() => _output = result);
    } catch (e) {
      setState(() => _output = 'Error: $e');
    }
  }

  Future<String> _ecdsaFlow() async {
    final shares = await Ecdsa.keygen();
    final refreshed = await Ecdsa.refresh(shares[0], shares[1]);
    final pubKey = await Ecdsa.derivedPubKey(refreshed[0], refreshed[1], 100);
    final sig = await Ecdsa.sign(refreshed[0], refreshed[1], 100,
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9' // sha256("hello world")
        );
    return 'public key: ${pubKey.substring(0, 24)}…\n'
        'signature r: ${sig.r.substring(0, 24)}…\n'
        'signature s: ${sig.s.substring(0, 24)}…';
  }

  Future<String> _ed25519Flow() async {
    final sessions = [1, 2, 3].map((d) => Ed25519DkgSession(deviceNumber: d, total: 3));
    for (final s in sessions) {
      await s.start();
    }

    // round 1
    final round1 = <TssMessage>[];
    for (final s in sessions) {
      round1.addAll(await s.step1());
    }
    // round 2
    final round2 = <TssMessage>[];
    for (final s in sessions) {
      round2.addAll(await s.step2(round1.where((m) => m.to == s.deviceNumber).toList()));
    }
    // round 3
    final shares = <int, Ed25519KeyShare>{};
    for (final s in sessions) {
      shares[s.deviceNumber] =
          await s.step3(round2.where((m) => m.to == s.deviceNumber).toList());
    }

    const messageHex = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
    const partList = [1, 2];
    final s1 = Ed25519SignSession(
        deviceNumber: 1, partList: partList, keyShare: shares[1]!, messageHex: messageHex);
    final s2 = Ed25519SignSession(
        deviceNumber: 2, partList: partList, keyShare: shares[2]!, messageHex: messageHex);
    await s1.start();
    await s2.start();

    final r1 = await s1.step1();
    final r2 = await s2.step1();
    final r1b = await s1.step2(r2.where((m) => m.to == 1).toList());
    final r2b = await s2.step2(r1.where((m) => m.to == 2).toList());
    final p1 = await s1.step3(r2b.where((m) => m.to == 1).toList());
    final p2 = await s2.step3(r1b.where((m) => m.to == 2).toList());

    final ver = await Ed25519.verify(p1, p2,
        messageHex: messageHex, publicKey: shares[1]!.publicKey);
    return 'aggregate public key: ${shares[1]!.publicKey.x.substring(0, 24)}…\n'
        'signature: ${ver.signatureHex.substring(0, 24)}…\n'
        'valid: ${ver.valid}';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('mpc_dart example')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              FilledButton(
                onPressed: () => _run(_ecdsaFlow),
                child: const Text('Run 2-of-3 ECDSA flow'),
              ),
              const SizedBox(height: 12),
              FilledButton(
                onPressed: () => _run(_ed25519Flow),
                child: const Text('Run Ed25519 DKG + 2-party sign'),
              ),
              const SizedBox(height: 12),
              FutureBuilder<String>(
                future: Mpc.version(),
                builder: (context, snap) => Text(
                  'native core: ${snap.data ?? '…'}',
                  textAlign: TextAlign.center,
                ),
              ),
              const SizedBox(height: 12),
              Text(_output, textAlign: TextAlign.center),
            ],
          ),
        ),
      ),
    );
  }
}
