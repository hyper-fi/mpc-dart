import 'dart:developer';

class MpcServiceError extends Error {
  final String? message;

  MpcServiceError([this.message]);

  @override
  String toString() {
    log('Mpc error] $message');
    return Error.safeToString(message).replaceAll('"', '');
  }
}
