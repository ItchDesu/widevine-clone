// lib/license_client.dart
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' show CryptoUtils;
import 'package:pointycastle/export.dart'
    show
        RSAPublicKey,
        RSASignature,
        Signer,
        PublicKeyParameter,
        RSAEngine,
        SHA256Digest;

/// Actívalo a true para logs de diagnóstico
const bool _DEBUG = false;

/// CA raíz embebida (Buzzster Local Root).
const String _embeddedCaPem = '''
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIUaEn0PI8pDhqxv8HyYE9YyDsmqFowDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCRVMxGDAWBgNVBAoMD0J1enpzdGVyIERldiBDQTEcMBoG
A1UEAwwTQnV6enN0ZXIgTG9jYWwgUm9vdDAeFw0yNTA4MTYyMzU2NDJaFw0zNTA4
MTQyMzU2NDJaMEUxCzAJBgNVBAYTAkVTMRgwFgYDVQQKDA9CdXp6c3RlciBEZXYg
Q0ExHDAaBgNVBAMME0J1enpzdGVyIExvY2FsIFJvb3QwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDKAcVDt6BY3QQIqNvmjtDdS1BqWMz/F1bnCuu7coIL
CioNy3CpAIjoevScMa8LBGWKfoDUa8IialAZaDewGN41ntcGo1tulT4cjBtT7TcG
bmS+wGD2fbv+C+qKjNAZLyBz2AndwuyHCc3CRuuFPyWvc7moMuJf2DqDU/9EptZ+
U4jQ0cYhXHGt9OmdbqVZ+KG8tnypF0lr4ufrp2bebv4INGxyYgntPq463iBWQDIo
csVr70sO4pHvahH3AidRY72B/xSqPsgs+21oPQ0YtxvbxSj8AJPr2+DkN3gMKRtx
J+xYQX+E45k30aW5zgJFvgcWiNWyDoBs3zzD+thgCJtwU5FW0TuD6Fz6GFKYkVJZ
ql706SbvAVw8aesl+TKFJgiyUFEKTBi7429K3wn2/lUHFJo718DU5/ym1A/hmxdD
W5z+7bZGdZn+bUAISIIboE5rX9fSR4A9h5mDW96JKsQxUGCZL/Rp6Kt9rnPgYMvO
WVC1sBxmldJk+RGGLfdyTuxGmSU8GqZpCIZo1NI77werr5Noh/LesvDLkitxirHx
B+QdubpGuB+DY7XyJIOPo7zO2r1bD3cwDilj7Zt5QP1Q8ZC1kpbn2kP9YgWIVniL
VXa3ZFFOWwFo8THxgBhSWe3i0M0phyCe/bf6RoF6KoICrjp6lKBquOn6nDd6matc
4wIDAQABo1MwUTAdBgNVHQ4EFgQUAnNdrzozOO2T0jqDWcShjSBhbcEwHwYDVR0j
BBgwFoAUAnNdrzozOO2T0jqDWcShjSBhbcEwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEAuN9dVfKZuo5agGgowWnbrssVfoqmCZ3q7vWZCh4KwJos
JNX4zgPlDxZGiLsTSIIwoHv2+SK8Tbr/sDQFoslJIjI5je1ZOy37LaYb+mJl897E
8oGNPSVL0mSSpJHFULSlvb8ZLGov4e8GLRPKLulSJIYn9f2kvJvySbYRrwOEfglK
PJL2lVK4iuopb5FlFlsTMaijSGsOqcBBrEPjsbJ6bUbHFJOMnSR7kl8bjhgFvRjE
S4RYmG4Q1HHLu4HhYclfeS+NQrHUnFuDZLJIa2S8ZIf06a8TV/zEVa96O9oJJJTz
p7UumUfZl3vBq/+iPGMfq9xlRtQsyTJ+79pue/Miy9W7NLdhEn224fACKHGAUqIV
WH9Xm4nMnxdWnpNy2t1Ht7aWuObNnuzLiseY17poqFKCgN6uM2eEE5OIFQ/O9LqR
g2eNwYxnaerEs1ueI0ygq+lgySun0RVCBQNEL30jUnftQlzOFuVv3NtVW/F4Rkav
NWGFiNHxk60vizuHaD4OavyIJXh5h/tTiqCd1x0qaux8LmTUNqGxyDlhdtJZjObR
sP+PUbTa5Ek+2y/C1/hnNzglJd+sFqu18y3zrLlB5rtA5Lg2mjHtvgaQp/l0d+rN
9Y47VkB3w7JyXm53aN/cm6rVaziJdVOwpMLqUDfeWq1uyAr1OqypyT7oQNJpaKY=
-----END CERTIFICATE-----
''';

/// Paquete de licencia: key + iv (16 bytes cada uno)
class LicenseBundle {
  final Uint8List key;
  final Uint8List iv;
  const LicenseBundle({required this.key, required this.iv});
}

class LicenseClient {
  final Uri server;
  final String token;
  final HttpClient _http;

  LicenseClient(String serverUrl, {required this.token})
      : server = Uri.parse(serverUrl),
        _http = (() {
          final ctx = SecurityContext(withTrustedRoots: false);
          ctx.setTrustedCertificatesBytes(
            Uint8List.fromList(utf8.encode(_embeddedCaPem)),
          );
          return HttpClient(context: ctx);
        }());

  Future<LicenseBundle> requestLicense(String contentId) async {
    // POST /license
    final req = await _http.postUrl(server.resolve('/license'));
    req.headers.contentType = ContentType.json;
    req.headers.add('Authorization', 'Bearer $token');
    req.write(jsonEncode({'content_id': contentId}));
    final resp = await req.close();
    if (resp.statusCode != 200) {
      throw HttpException('Server returned ${resp.statusCode}');
    }
    final body = await resp.transform(utf8.decoder).join();
    final map = jsonDecode(body) as Map<String, dynamic>;

    final licenseB64 = map['license'] as String; // base64 de key||iv
    final expiry     = map['expiry']  as int;    // segundos UNIX
    final sigB64     = map['signature'] as String;

    // Expiración
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    if (now >= expiry) {
      throw const FormatException('license expired');
    }

    // GET /public_key
    final pubReq  = await _http.getUrl(server.resolve('/public_key'));
    final pubResp = await pubReq.close();
    if (pubResp.statusCode != 200) {
      throw HttpException('Public key endpoint returned ${pubResp.statusCode}');
    }
    final pubPem = (await pubResp.transform(utf8.decoder).join()).trim();

    // Verificación PKCS#1 v1.5 (payload exacto)
    final ok = _verifySignature(
      pubPem: pubPem,
      signatureB64: sigB64,
      contentId: contentId,
      expiry: expiry,
      licenseB64: licenseB64,
    );
    if (!ok) {
      throw const FormatException('invalid signature');
    }

    // Decodificar license → key||iv (16+16)
    final licBytes = _b64Decode(licenseB64);
    if (licBytes.length < 32) {
      throw const FormatException('license payload too short');
    }
    final key = Uint8List.view(licBytes.buffer, licBytes.offsetInBytes, 16);
    final iv  = Uint8List.view(licBytes.buffer, licBytes.offsetInBytes + 16, 16);

    return LicenseBundle(key: Uint8List.fromList(key), iv: Uint8List.fromList(iv));
  }

  // -------- helpers base64 --------
  Uint8List _b64Decode(String s) {
    var t = s.trim().replaceAll('-', '+').replaceAll('_', '/');
    final pad = t.length % 4;
    if (pad != 0) t += '=' * (4 - pad);
    return base64Decode(t);
  }

  String _normalizeB64Text(String s) {
    // normaliza para variantes de prueba (sin espacios, url-safe→std, mantiene '=')
    var t = s.replaceAll(RegExp(r'\s+'), '');
    t = t.replaceAll('-', '+').replaceAll('_', '/');
    return t;
  }

  // -------- verificación PKCS#1 v1.5 --------
  bool _verifySignature({
    required String pubPem,
    required String signatureB64,
    required String contentId,
    required int expiry,
    required String licenseB64,
  }) {
    final RSAPublicKey pub = CryptoUtils.rsaPublicKeyFromPem(pubPem);
    final Uint8List sig = _b64Decode(signatureB64);

    // payload exacto (como tu JS): cid + expiry + licenseB64
    final String payloadText = contentId + expiry.toString() + licenseB64;
    final Uint8List payload = Uint8List.fromList(utf8.encode(payloadText));

    // 1) Intento con Signer (PKCS#1 v1.5)
    try {
      final signer = Signer('SHA-256/RSA');
      signer.init(false, PublicKeyParameter<RSAPublicKey>(pub));
      final ok = signer.verifySignature(payload, RSASignature(sig));
      if (ok) {
        if (_DEBUG) _dbg('verify(signer)=OK');
        return true;
      }
      if (_DEBUG) _dbg('verify(signer)=FAIL -> trying manual');
    } catch (e) {
      if (_DEBUG) _dbg('Signer exception: $e (trying manual)');
    }

    // 2) Manual EMSA-PKCS1-v1_5
    if (_verifyManualPkcs1v15(pub: pub, payload: payload, sig: sig)) {
      if (_DEBUG) _dbg('verify(manual)=OK');
      return true;
    }

    // 3) Variantes por si el backend firmó otra representación de licenseB64
    final variants = <String>[
      _normalizeB64Text(licenseB64),                      // sin espacios + url-safe→std
      _normalizeB64Text(licenseB64).replaceAll('=', ''),  // igual pero sin '='
      licenseB64.replaceAll(RegExp(r'\s+'), ''),          // solo sin espacios
    ];
    for (final licVar in variants) {
      final p = Uint8List.fromList(
          utf8.encode(contentId + expiry.toString() + licVar));
      try {
        final s2 = Signer('SHA-256/RSA');
        s2.init(false, PublicKeyParameter<RSAPublicKey>(pub));
        final ok2 = s2.verifySignature(p, RSASignature(sig));
        if (ok2) {
          if (_DEBUG) _dbg('verify(variant+signer)=OK');
          return true;
        }
      } catch (_) {}
      if (_verifyManualPkcs1v15(pub: pub, payload: p, sig: sig)) {
        if (_DEBUG) _dbg('verify(variant+manual)=OK');
        return true;
      }
    }

    if (_DEBUG) {
      final h = SHA256Digest().process(Uint8List.fromList(utf8.encode(payloadText)));
      _dbg('ALL FAIL. payload.sha256=${_hex(h)} len=${payload.length}');
    }
    return false;
  }

  bool _verifyManualPkcs1v15({
    required RSAPublicKey pub,
    required Uint8List payload,
    required Uint8List sig,
  }) {
    // Hash SHA-256
    final hash = SHA256Digest().process(payload);

    // DigestInfo(SHA-256)
    final di = Uint8List.fromList(const [
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
      0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    ]);
    final digestInfo = Uint8List(di.length + 32)
      ..setAll(0, di)
      ..setAll(di.length, hash);

    // EM = s^e mod n
    final engine = RSAEngine()..init(false, PublicKeyParameter<RSAPublicKey>(pub));
    Uint8List em = engine.process(sig);

    // pad a k bytes (por si el backend omite ceros a la izquierda)
    final int k = ((pub.modulus!.bitLength + 7) >> 3);
    if (em.length < k) {
      final padded = Uint8List(k);
      padded.setRange(k - em.length, k, em);
      em = padded;
    }

    // Esperado: 0x00 0x01 FF..FF 0x00 || DigestInfo
    if (em.length != k || em[0] != 0x00 || em[1] != 0x01) {
      if (_DEBUG) _dbg('EM bad header: first=${_hex(em.sublist(0, em.length > 8 ? 8 : em.length))}');
      return false;
    }
    int i = 2, ff = 0;
    while (i < em.length && em[i] == 0xFF) { ff++; i++; }
    if (ff < 8 || i >= em.length || em[i] != 0x00) {
      if (_DEBUG) _dbg('EM bad padding: ff=$ff sep=${i<em.length?em[i]:-1}');
      return false;
    }
    i++; // separador 0x00

    final remain = em.length - i;
    if (remain != digestInfo.length) {
      if (_DEBUG) _dbg('EM digestInfo len mismatch: $remain vs ${digestInfo.length}');
      return false;
    }
    for (int j = 0; j < digestInfo.length; j++) {
      if (em[i + j] != digestInfo[j]) {
        if (_DEBUG) _dbg('EM digestInfo mismatch at $j');
        return false;
      }
    }
    return true;
  }

  // -------- util debug --------
  String _hex(Uint8List b) =>
      b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
  void _dbg(String msg) { if (_DEBUG) print('[license] $msg'); }

  void close() => _http.close(force: true);
}