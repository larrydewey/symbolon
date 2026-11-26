// Digital Asset Links (SPEC 22.6 item 3): whether a site lets an Android app
// use its logins. The site's https://HOST/.well-known/assetlinks.json must
// list `delegate_permission/common.get_login_creds` for an `android_app`
// target with the app's package and signing certificate. The file is
// fetched straight from the host over TLS, without redirects and at most
// 128 KiB; a fetch that fails, or a file that does not list the app, means
// no link. Answers are kept for at most a day. Only sites the app itself
// claims are looked up, never every site in the vault.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

const _relation = 'delegate_permission/common.get_login_creds';
const _maxBytes = 128 * 1024;
const _keep = Duration(hours: 24);

/// The file's text, or null: no redirect is followed, nothing over 128 KiB
/// or slower than 10 seconds is read.
Future<String?> fetchAssetLinks(String host) async {
  final c = HttpClient()..connectionTimeout = const Duration(seconds: 10);
  try {
    final rq = await c.getUrl(Uri(scheme: 'https', host: host, path: '/.well-known/assetlinks.json')).timeout(const Duration(seconds: 10));
    rq.followRedirects = false;
    final rs = await rq.close().timeout(const Duration(seconds: 10));
    if (rs.statusCode != 200) return null;
    final b = BytesBuilder();
    await for (final chunk in rs.timeout(const Duration(seconds: 10))) {
      b.add(chunk);
      if (b.length > _maxBytes) return null;
    }
    return utf8.decode(b.takeBytes(), allowMalformed: false);
  } catch (_) {
    return null;
  } finally {
    c.close(force: true);
  }
}

/// SHA-256 as assetlinks.json writes it ("AB:CD:...") or as hex, to hex.
String _fp(String s) => s.replaceAll(':', '').toLowerCase();

/// Whether [json] (an assetlinks.json) lets [pkg], signed by one of
/// [certs] (hex SHA-256), use the site's logins. Malformed means no.
bool allowsLogins(String json, String pkg, List<String> certs) {
  final Object? d;
  try {
    d = jsonDecode(json);
  } on FormatException {
    return false;
  }
  if (d is! List) return false;
  final mine = {for (final c in certs) _fp(c)};
  for (final st in d) {
    if (st is! Map) continue;
    final rel = st['relation'], t = st['target'];
    if (rel is! List || !rel.contains(_relation) || t is! Map) continue;
    if (t['namespace'] != 'android_app' || t['package_name'] != pkg) continue;
    final fps = t['sha256_cert_fingerprints'];
    if (fps is List && fps.any((f) => f is String && mine.contains(_fp(f)))) return true;
  }
  return false;
}

/// Whether a login saved for [saved] belongs to [host], a host whose
/// Digital Asset Links list the app: `https`, no port or path, and the same
/// host once a leading "www." is dropped from each. Unlike a page in a
/// browser (SPEC 22.5 step 6), a subdomain does not inherit the parent's
/// login: an app verified by any subdomain's file (one a hosting customer
/// or a single team controls) would otherwise get the apex site's login.
bool appSiteIs(String saved, String host) {
  final a = Uri.tryParse(saved);
  if (a == null || a.scheme != 'https' || a.hasPort || a.path.isNotEmpty || a.hasQuery || a.hasFragment || a.userInfo.isNotEmpty) return false;
  String bare(String h) => h.startsWith('www.') ? h.substring(4) : h;
  final h = host.toLowerCase();
  return a.host.isNotEmpty && bare(a.host) == bare(h);
}

/// The answers, kept in [cache] (a JSON file) for a day.
class AppLinks {
  final File cache;
  final Future<String?> Function(String host) fetch;
  final DateTime Function() now;
  AppLinks(this.cache, {this.fetch = fetchAssetLinks, DateTime Function()? now}) : now = now ?? DateTime.now;

  Future<Map<String, dynamic>> _read() async {
    try {
      final j = jsonDecode(await cache.readAsString());
      return j is Map<String, dynamic> ? j : {};
    } catch (_) {
      return {};
    }
  }

  static String _key(String host, String pkg, List<String> certs) => '$host $pkg ${certs.map(_fp).join(',')}';

  /// Whether [host] links [pkg] (signed by [certs]).
  Future<bool> linked(String host, String pkg, List<String> certs) async => (await verified([host], pkg, certs)).isNotEmpty;

  /// The hosts among [claimed] that link the app. The cache is read once,
  /// the hosts it has no fresh answer for are fetched together, and it is
  /// written once, so no answer overwrites another.
  Future<List<String>> verified(List<String> claimed, String pkg, List<String> certs) async {
    final all = await _read();
    bool fresh(String h) {
      final hit = all[_key(h, pkg, certs)];
      return hit is Map && hit['at'] is int && now().difference(DateTime.fromMillisecondsSinceEpoch(hit['at'] as int)) < _keep;
    }
    final ask = [for (final h in claimed) if (!fresh(h)) h];
    if (ask.isNotEmpty) {
      final texts = await Future.wait([for (final h in ask) fetch(h)]);
      for (var i = 0; i < ask.length; i++) {
        final t = texts[i];
        all[_key(ask[i], pkg, certs)] = {'ok': t != null && allowsLogins(t, pkg, certs), 'at': now().millisecondsSinceEpoch};
      }
      try {
        await cache.parent.create(recursive: true);
        await cache.writeAsString(jsonEncode(all));
      } catch (_) {}
    }
    return [for (final h in claimed) if ((all[_key(h, pkg, certs)] as Map)['ok'] == true) h];
  }
}
