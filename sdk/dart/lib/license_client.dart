// lib/license_client.dart
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/export.dart'
    show RSAPublicKey, RSASignature, Signer, PublicKeyParameter;
import 'package:basic_utils/basic_utils.dart';

/// Paquete de licencia que usa tu app: key + iv (ambas de 16 bytes)
class LicenseBundle {
  final Uint8List key;
  final Uint8List iv;

  const LicenseBundle({required this.key, required this.iv});
}

/// Cliente que solicita y valida la licencia contra tu servidor.
class LicenseClient {
  final Uri server;
  final String token;
  final HttpClient _http = HttpClient();

  /// serverUrl: p.ej. "http://10.0.2.10:8080" o "https://tu-dominio"
  LicenseClient(String serverUrl, {required this.token})
      : server = Uri.parse(serverUrl);

  /// Pide la licencia para [contentId], verifica expiración y firma,
  /// y retorna un [LicenseBundle] con key e iv (16 bytes cada una).
  Future<LicenseBundle> requestLicense(String contentId) async {
    // --- POST /license
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

    final licenseB64 = map['license'] as String;
    final expiry = map['expiry'] as int;
    final signatureB64 = map['signature'] as String;

    // --- Comprobación de expiración (segundos UNIX)
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    if (now >= expiry) {
      throw const FormatException('license expired');
    }

    // --- GET /public_key
    final pubReq = await _http.getUrl(server.resolve('/public_key'));
    final pubResp = await pubReq.close();
    if (pubResp.statusCode != 200) {
      throw HttpException(
          'Public key endpoint returned ${pubResp.statusCode}');
    }
    final pubPem = await pubResp.transform(utf8.decoder).join();

    // --- Verificar firma
    final ok =
        _verifySignature(pubPem, signatureB64, contentId, expiry, licenseB64);
    if (!ok) {
      throw const FormatException('invalid signature');
    }

    // --- Decodificar licencia
    // Se asume que `licenseB64` contiene un JSON base64:
    //   {"key":"...base64...","iv":"...base64..."}
    // Ajusta esta parte si tu servidor envía otro formato.
    final licJsonStr = utf8.decode(base64Decode(licenseB64));
    final licMap = jsonDecode(licJsonStr) as Map<String, dynamic>;

    final keyB64 = licMap['key'] as String;
    final ivB64 = licMap['iv'] as String;

    final key = Uint8List.fromList(base64Decode(keyB64));
    final iv = Uint8List.fromList(base64Decode(ivB64));

    if (key.length != 16 || iv.length != 16) {
      throw const FormatException('invalid key/iv size');
    }

    return LicenseBundle(key: key, iv: iv);
  }

  bool _verifySignature(
      String pem, String sigB64, String cid, int expiry, String licB64) {
    // Parsear PEM -> RSAPublicKey
    final RSAPublicKey publicKey = CryptoUtils.rsaPublicKeyFromPem(pem);

    // El payload DEBE coincidir exactamente con lo que firma el servidor.
    // Mantengo tu concatenación original sin separadores:
    final payload = utf8.encode(cid + expiry.toString() + licB64);

    final signer = Signer('SHA-256/RSA');
    signer.init(false, PublicKeyParameter<RSAPublicKey>(publicKey));

    final sig = RSASignature(base64Decode(sigB64));
    return signer.verifySignature(payload, sig);
  }

  /// Cierra el HttpClient interno.
  void close() {
    _http.close(force: true);
  }
}