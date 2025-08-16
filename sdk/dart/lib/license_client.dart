import 'dart:convert';
import 'dart:io';

/// Simple client that requests a license from the demo server.
class LicenseClient {
  final Uri server;

  LicenseClient(String serverUrl) : server = Uri.parse(serverUrl);

  Future<List<int>> requestLicense(String contentId) async {
    final httpClient = HttpClient();
    final request = await httpClient.postUrl(server.resolve('/license'));
    request.headers.contentType = ContentType.json;
    request.write(jsonEncode({'content_id': contentId}));

    final response = await request.close();
    if (response.statusCode != 200) {
      throw HttpException('Server returned ${response.statusCode}');
    }
    final body = await response.transform(utf8.decoder).join();
    final map = jsonDecode(body) as Map<String, dynamic>;
    return base64Decode(map['license'] as String);
  }
}
