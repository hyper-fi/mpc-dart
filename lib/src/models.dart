import 'dart:convert';

/// A protocol message exchanged between participants. Relay these through
/// your own transport (network, QR, ...) — `to` identifies the recipient.
class TssMessage {
  const TssMessage({required this.from, required this.to, required this.data});

  factory TssMessage.fromJson(Map<String, dynamic> json) => TssMessage(
        from: json['From'] as int,
        to: json['To'] as int,
        data: json['Data'] as String,
      );

  final int from;
  final int to;
  final String data;

  Map<String, dynamic> toJson() => {'From': from, 'To': to, 'Data': data};

  @override
  String toString() => 'TssMessage(from: $from, to: $to)';
}

/// Serialises [messages] into the wire format the native bridge expects.
String encodeMessages(List<TssMessage> messages) =>
    jsonEncode(messages.map((m) => m.toJson()).toList());

/// A curve public key as returned in key shares.
class PublicKey {
  const PublicKey({required this.curve, required this.x, required this.y});

  factory PublicKey.fromJson(Map<String, dynamic> json) => PublicKey(
        curve: json['Curve'] as String,
        x: json['X'] as String,
        y: json['Y'] as String,
      );

  final String curve;
  final String x;
  final String y;

  Map<String, dynamic> toJson() => {'Curve': curve, 'X': x, 'Y': y};
}

/// A participant's Ed25519 key share produced by the DKG protocol.
class Ed25519KeyShare {
  const Ed25519KeyShare({
    required this.id,
    required this.shareI,
    required this.publicKey,
    required this.chainCode,
    required this.sharePubKeyMap,
  });

  factory Ed25519KeyShare.fromJson(Map<String, dynamic> json) => Ed25519KeyShare(
        id: json['Id'] as int,
        shareI: json['ShareI'] as String,
        publicKey: PublicKey.fromJson(json['PublicKey'] as Map<String, dynamic>),
        chainCode: json['ChainCode'] as String? ?? '',
        sharePubKeyMap: (json['SharePubKeyMap'] as Map<String, dynamic>? ?? {})
            .map((k, v) => MapEntry(int.parse(k), PublicKey.fromJson(v as Map<String, dynamic>))),
      );

  /// Participant id (1-based).
  final int id;

  /// Secret key share (decimal string). Store securely — never log it.
  final String shareI;

  /// Aggregate public key (identical across participants).
  final PublicKey publicKey;

  /// Chaincode used for unhardened derivation.
  final String chainCode;

  /// Each participant's public share, keyed by participant id.
  final Map<int, PublicKey> sharePubKeyMap;

  Map<String, dynamic> toJson() => {
        'Id': id,
        'ShareI': shareI,
        'PublicKey': publicKey.toJson(),
        'ChainCode': chainCode,
        'SharePubKeyMap': sharePubKeyMap.map((k, v) => MapEntry('$k', v.toJson())),
      };
}

/// One party's partial ECDSA signature.
///
/// Both components are 64-char hex strings (32-byte big-endian, zero padded),
/// as produced by the Lindell 17 protocol.
class EcdsaSignature {
  const EcdsaSignature({required this.r, required this.s});

  factory EcdsaSignature.fromJson(Map<String, dynamic> json) =>
      EcdsaSignature(r: json['r'] as String, s: json['s'] as String);

  final String r;
  final String s;

  Map<String, dynamic> toJson() => {'r': r, 's': s};
}

/// One party's partial Ed25519 signature from the final signing round.
class Ed25519PartialSignature {
  const Ed25519PartialSignature({required this.si, required this.r});

  factory Ed25519PartialSignature.fromJson(Map<String, dynamic> json) =>
      Ed25519PartialSignature(si: json['si'] as String, r: json['r'] as String);

  /// Partial signature component (decimal string).
  final String si;

  /// Nonce commitment R (decimal string), identical across parties.
  final String r;
}

/// Result of assembling and verifying an Ed25519 signature.
class Ed25519Verification {
  const Ed25519Verification({required this.valid, required this.signatureHex});

  factory Ed25519Verification.fromJson(Map<String, dynamic> json) => Ed25519Verification(
        valid: json['valid'] as bool,
        signatureHex: json['signature'] as String,
      );

  final bool valid;

  /// Standard 64-byte wire format signature (r || s), hex encoded.
  final String signatureHex;
}
