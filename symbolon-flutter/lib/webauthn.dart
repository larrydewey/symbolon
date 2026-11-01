// WebAuthn requests and responses as Android's Credential Manager passes
// them (JSON, binary fields in base64url). The agent forms the
// authenticator data and signs (SPEC 10.4); this turns its output into the
// response a site expects.

import 'dart:convert';
import 'dart:typed_data';

String b64u(List<int> b) => base64Url.encode(b).replaceAll('=', '');

Uint8List unb64u(String s) => base64Url.decode(s.padRight((s.length + 3) ~/ 4 * 4, '='));

Uint8List fromHex(String h) => Uint8List.fromList([for (var i = 0; i + 1 < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)]);

String toHex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// A P-256 public key (uncompressed point) as SubjectPublicKeyInfo DER.
Uint8List spkiOf(Uint8List point) =>
    Uint8List.fromList([...fromHex('3059301306072a8648ce3d020106082a8648ce3d030107034200'), ...point]);

/// What a registration request asks for, checked.
class CreateRequest {
  final String rpId;
  final String rpName;
  final Uint8List userId;
  final String userName;
  final String displayName;
  final Set<String> exclude;          // credential IDs, base64url
  final bool es256;                   // the site accepts ES256
  CreateRequest(this.rpId, this.rpName, this.userId, this.userName, this.displayName, this.exclude, this.es256);

  static CreateRequest parse(String json, String origin) {
    final j = jsonDecode(json) as Map<String, dynamic>;
    final rp = (j['rp'] as Map?) ?? {};
    final user = (j['user'] as Map?) ?? {};
    final params = (j['pubKeyCredParams'] as List?) ?? [];
    return CreateRequest(
      (rp['id'] as String?) ?? hostOf(origin),
      (rp['name'] as String?) ?? '',
      unb64u((user['id'] as String?) ?? ''),
      (user['name'] as String?) ?? '',
      (user['displayName'] as String?) ?? '',
      {for (final e in (j['excludeCredentials'] as List?) ?? []) (e as Map)['id'] as String},
      params.isEmpty || params.any((p) => (p as Map)['alg'] == -7),
    );
  }
}

String hostOf(String origin) => Uri.tryParse(origin)?.host ?? '';

/// Whether a page at [origin] may use passkeys of [rpId]: its host is the
/// RP ID or under it, over HTTPS (or localhost). An app's origin
/// (android:apk-key-hash:…) is left to the site, which checks it against
/// its Digital Asset Links.
bool originMayUse(String origin, String rpId) {
  if (origin.startsWith('android:')) return true;
  final u = Uri.tryParse(origin);
  if (u == null) return false;
  if (u.scheme != 'https' && !(u.scheme == 'http' && u.host == 'localhost')) return false;
  return u.host == rpId || u.host.endsWith('.$rpId');
}

/// The client data in a response: the app's own when it formed it, else a
/// stand-in the browser replaces with its own (it gave only the hash).
String _clientData(String? json) => b64u(utf8.encode(json ?? '{}'));

String registrationResponse({required String cidHex, required String publicKeyHex, required String authDataHex, required String attestationHex, String? clientDataJSON}) {
  final cid = fromHex(cidHex);
  return jsonEncode({
    'id': b64u(cid),
    'rawId': b64u(cid),
    'type': 'public-key',
    'authenticatorAttachment': 'platform',
    'response': {
      'clientDataJSON': _clientData(clientDataJSON),
      'attestationObject': b64u(fromHex(attestationHex)),
      'authenticatorData': b64u(fromHex(authDataHex)),
      'transports': ['internal', 'hybrid'],
      'publicKey': b64u(spkiOf(fromHex(publicKeyHex))),
      'publicKeyAlgorithm': -7,
    },
    'clientExtensionResults': {
      'credProps': {'rk': true},
    },
  });
}

String assertionResponse({required String cidHex, required String authDataHex, required String signatureDerHex, required String userHandleHex, String? clientDataJSON}) {
  final cid = fromHex(cidHex);
  return jsonEncode({
    'id': b64u(cid),
    'rawId': b64u(cid),
    'type': 'public-key',
    'authenticatorAttachment': 'platform',
    'response': {
      'clientDataJSON': _clientData(clientDataJSON),
      'authenticatorData': b64u(fromHex(authDataHex)),
      'signature': b64u(fromHex(signatureDerHex)),
      if (userHandleHex.isNotEmpty) 'userHandle': b64u(fromHex(userHandleHex)),
    },
    'clientExtensionResults': {},
  });
}
