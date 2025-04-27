import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:mpc/src/error.dart';

import 'ffi.dart';

class MpcHelper {
  factory MpcHelper() => _getInstance();
  static MpcHelper get instance => _getInstance();
  static MpcHelper? _instance;
  static final DynamicLibrary _dylib = Platform.isAndroid
      ? DynamicLibrary.open('libmpc.so')
      : DynamicLibrary.process();
  NativeLibrary? _nf;
  MpcHelper._internal() {
    _nf = NativeLibrary(_dylib);
  }
  static MpcHelper _getInstance() {
    _instance ??= MpcHelper._internal();
    return _instance!;
  }

  Pointer<Utf8> _toUtf8Pointer(String dartStr) {
    final units = utf8.encode(dartStr);
    final ptr = malloc.allocate<Uint8>(units.length + 1);
    final Uint8List nativeString = ptr.asTypedList(units.length + 1);
    nativeString.setAll(0, units);
    nativeString[units.length] = 0; // null-terminate
    return ptr.cast<Utf8>();
  }

  Pointer<GoString> _createGoString(String dartStr) {
    final gStr = malloc<GoString>();
    final utf8Ptr = _toUtf8Pointer(dartStr);
    gStr.ref
      ..p = utf8Ptr.cast<Char>()
      ..n = dartStr.length;
    return gStr;
  }

  List<String>? generate() {
    List<String> resultList = [];
    final v = _nf?.EcdsaKeyGenSimple();
    if (v != null) {
      Pointer<Char> share1Char = v.r0;
      Pointer<Char> share2Char = v.r1;
      Pointer<Char> share3Char = v.r2;
      if (share1Char.address != 0 &&
          share2Char.address != 0 &&
          share3Char.address != 0) {
        String share1 = share1Char.cast<Utf8>().toDartString();
        String share2 = share2Char.cast<Utf8>().toDartString();
        String share3 = share3Char.cast<Utf8>().toDartString();
        if (share1.isNotEmpty && share2.isNotEmpty && share3.isNotEmpty) {
          resultList = [share1, share2, share3];
        }
      }

      _nf?.FreeCString(share1Char);
      _nf?.FreeCString(share2Char);
      _nf?.FreeCString(share3Char);
    }
    return resultList.isEmpty ? null : resultList;
  }

  String? getPublicKey(String share1, String share2) {
    String result = '';
    final share1st = _createGoString(share1);
    final share2nd = _createGoString(share2);
    final v = _nf?.EcdsaDerivedPubKeySimple(share1st.ref, share2nd.ref, 0);
    malloc.free(share1st.ref.p);
    malloc.free(share1st);
    malloc.free(share2nd.ref.p);
    malloc.free(share2nd);
    if (v != null) {
      Pointer<Char> publicChar = v.r0;
      Pointer<Char> errorChar = v.r1;
      if (errorChar.address != 0) {
        String error = errorChar.cast<Utf8>().toDartString();
        _nf?.FreeCString(publicChar);
        _nf?.FreeCString(errorChar);
        throw MpcServiceError(error);
      } else {
        if (publicChar.address != 0) {
          result = publicChar.cast<Utf8>().toDartString();
        }

        _nf?.FreeCString(publicChar);
        _nf?.FreeCString(errorChar);
      }
    }
    return result.isEmpty ? null : result;
  }

  List<String>? recover(String share1, String share2) {
    List<String> resultList = [];
    final share1st = _createGoString(share1);
    final share2nd = _createGoString(share2);
    final v = _nf?.EcdsaRefreshSimple(share1st.ref, share2nd.ref);
    malloc.free(share1st.ref.p);
    malloc.free(share1st);
    malloc.free(share2nd.ref.p);
    malloc.free(share2nd);
    if (v != null) {
      Pointer<Char> newLocalChar = v.r0;
      Pointer<Char> newRemoteChar = v.r1;
      Pointer<Char> newBackupChar = v.r2;
      Pointer<Char> errorChar = v.r3;
      if (errorChar.address != 0) {
        String error = errorChar.cast<Utf8>().toDartString();
        _nf?.FreeCString(newLocalChar);
        _nf?.FreeCString(newRemoteChar);
        _nf?.FreeCString(newBackupChar);
        _nf?.FreeCString(errorChar);
        throw MpcServiceError(error);
      } else {
        if (newLocalChar.address != 0 &&
            newRemoteChar.address != 0 &&
            newBackupChar.address != 0) {
          String newLocal = newLocalChar.cast<Utf8>().toDartString();
          String newRemote = newRemoteChar.cast<Utf8>().toDartString();
          String newBackup = newBackupChar.cast<Utf8>().toDartString();

          if (newLocal.isNotEmpty &&
              newRemote.isNotEmpty &&
              newBackup.isNotEmpty) {
            resultList = [newLocal, newRemote, newBackup];
          }
        }
        _nf?.FreeCString(newLocalChar);
        _nf?.FreeCString(newRemoteChar);
        _nf?.FreeCString(newBackupChar);
        _nf?.FreeCString(errorChar);
      }
    }
    return resultList.isEmpty ? null : resultList;
  }

  List<String>? sign(String share1, String share2, String hashMessage) {
    List<String> resultList = [];
    final share1st = _createGoString(share1);
    final share2nd = _createGoString(share2);
    final signMessageHashHex = _createGoString(hashMessage);
    final v = _nf?.EcdsaSignSimple(
      share1st.ref,
      share2nd.ref,
      0,
      signMessageHashHex.ref,
    );
    malloc.free(share1st.ref.p);
    malloc.free(share1st);
    malloc.free(share2nd.ref.p);
    malloc.free(share2nd);
    malloc.free(signMessageHashHex.ref.p);
    malloc.free(signMessageHashHex);
    if (v != null) {
      Pointer<Char> rChar = v.r0;
      Pointer<Char> sChar = v.r1;
      Pointer<Char> errorChar = v.r2;
      if (errorChar.address != 0) {
        String error = errorChar.cast<Utf8>().toDartString();
        _nf?.FreeCString(rChar);
        _nf?.FreeCString(sChar);
        _nf?.FreeCString(errorChar);
        throw MpcServiceError(error);
      } else {
        if (rChar.address != 0 && sChar.address != 0) {
          String r = rChar.cast<Utf8>().toDartString();
          String s = sChar.cast<Utf8>().toDartString();

          if (r.isNotEmpty && s.isNotEmpty) {
            resultList = [r, s];
          }
        }
        _nf?.FreeCString(rChar);
        _nf?.FreeCString(sChar);
        _nf?.FreeCString(errorChar);
      }
    }
    return resultList.isEmpty ? null : resultList;
  }
}
