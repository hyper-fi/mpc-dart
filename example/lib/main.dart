import 'package:flutter/material.dart';
import 'package:mpc/mpc.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  @override
  void initState() {
    super.initState();
  }

  sayHelloFromGo() {
    print('sayHelloFromGo');
    final list = MpcHelper().generate();
    if (list != null) {
      final public1 = MpcHelper().getPublicKey(list[0], list[1]);
      final recover = MpcHelper().recover(list[2], list[1]);
      if (recover != null) {
        final public2 = MpcHelper().getPublicKey(recover[0], recover[1]);
        print(public1);
        print(public2);
        print(public1 == public2);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Center(
          child: ElevatedButton(
            child: Text("Call Go"),
            onPressed: sayHelloFromGo,
          ),
        ),
      ),
    );
  }
}
