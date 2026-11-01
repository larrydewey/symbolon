// Pairing with a Symbolon Home box (symbolon-resid src/agent/home.resid).
// The box shows a QR code holding
//   symbolon://pair?h=HOST&p=PORT&c=CODE&f=CERT-SHA256
// The app connects to https://HOST:PORT and accepts only a server
// certificate whose SHA-256 is the fingerprint, before the one-time code
// is sent; the setup it then gets carries the box's CA, which the agent
// trusts from then on.

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

class HomeLink {
  final String host;
  final int port;
  final String code;
  final String fingerprint;   // base64url SHA-256 of the box's server certificate
  const HomeLink(this.host, this.port, this.code, this.fingerprint);

  /// The link, or null when [text] is not one (what a QR code or a paste
  /// gives).
  static HomeLink? parse(String text) {
    final u = Uri.tryParse(text.trim());
    if (u == null || u.scheme != 'symbolon' || u.host != 'pair') return null;
    final q = u.queryParameters;
    final port = int.tryParse(q['p'] ?? '');
    final host = q['h'] ?? '', code = q['c'] ?? '', fp = q['f'] ?? '';
    if (host.isEmpty || port == null || port < 1 || port > 65535) return null;
    if (!RegExp(r'^[A-Za-z0-9_-]{22}$').hasMatch(code) || !RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(fp)) return null;
    return HomeLink(host, port, code, fp);
  }

  static String fingerprintOf(List<int> der) => base64Url.encode(sha256.convert(der).bytes).replaceAll('=', '');
}

/// What the box tells a new device (GET /setup).
class HomeSetup {
  final String name;
  final String relayHost;
  final int relayPort;
  final String cosignerKeys;
  final List<String> witnesses;
  final String caPem;
  const HomeSetup(this.name, this.relayHost, this.relayPort, this.cosignerKeys, this.witnesses, this.caPem);
}

class HomeError implements Exception {
  final String message;
  const HomeError(this.message);
  @override
  String toString() => message;
}

class HomeClient {
  final HomeLink link;
  HomeClient(this.link);

  HttpClient _client() => HttpClient()
    ..connectionTimeout = const Duration(seconds: 10)
    // The box's certificate is not under any public CA: accept it only if
    // it is the one the link names.
    ..badCertificateCallback = (cert, host, port) => host == link.host && port == link.port && HomeLink.fingerprintOf(cert.der) == link.fingerprint;

  Future<String> _call(String method, String path, [String body = '']) async {
    final c = _client();
    try {
      final uri = Uri(scheme: 'https', host: link.host, port: link.port, path: path, queryParameters: {'c': link.code});
      final rq = method == 'POST' ? await c.postUrl(uri) : await c.getUrl(uri);
      if (body.isNotEmpty) {
        final b = utf8.encode(body);
        rq.contentLength = b.length;
        rq.add(b);
      }
      final rs = await rq.close();
      final text = await rs.transform(utf8.decoder).join();
      if (rs.statusCode == 403) throw const HomeError('This invite has been used or has expired. Make a new one on the box.');
      if (rs.statusCode != 200) throw HomeError('The box answered ${rs.statusCode}.');
      return text;
    } on HandshakeException {
      throw const HomeError('This is not the box the code was made by (its certificate does not match). Check that you are on the right network.');
    } on SocketException {
      throw HomeError('Cannot reach the box at ${link.host}:${link.port}. Is this phone on the same network, or connected to it over the VPN?');
    } finally {
      c.close(force: true);
    }
  }

  Future<HomeSetup> setup() async {
    final j = jsonDecode(await _call('GET', '/setup')) as Map<String, dynamic>;
    return HomeSetup(j['name'] as String, j['relay_host'] as String, j['relay_port'] as int, j['cosigner_keys'] as String,
        (j['witnesses'] as List).cast<String>(), j['ca'] as String);
  }

  /// Pins this device (its keys from device new) at the person's cosigner;
  /// spends the code.
  Future<void> pair(String deviceKeys) async {
    final j = jsonDecode(await _call('POST', '/pair', deviceKeys)) as Map<String, dynamic>;
    if (j['paired'] != true) throw HomeError('The box did not pair this device: ${j['error'] ?? j}');
  }
}
