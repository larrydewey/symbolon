// Site icons for logins, fetched straight from the site (never through a
// third-party icon service, which would learn every site in the vault) and
// kept on this device. The site, and anyone watching the network, sees the
// request: Settings › Site icons turns this off.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';

class Favicons {
  final Directory dir;
  final Map<String, Future<Uint8List?>> _loading = {};
  Favicons(this.dir);

  static const _maxBytes = 200 * 1024;
  static const _retryAfter = Duration(days: 3);   // after a miss

  File _file(String origin) => File('${dir.path}/${base64Url.encode(utf8.encode(origin))}.icon');

  /// The icon of [origin] (scheme://host[:port]), or null when it has none.
  Future<Uint8List?> icon(String origin) => _loading[origin] ??= _load(origin);

  Future<Uint8List?> _load(String origin) async {
    final f = _file(origin);
    try {
      if (await f.exists()) {
        final b = await f.readAsBytes();
        // An empty file records a miss; try again after a while.
        if (b.isNotEmpty) return b;
        if (DateTime.now().difference(await f.lastModified()) < _retryAfter) return null;
      }
      Uint8List? b;
      for (final p in ['/favicon.ico', '/apple-touch-icon.png', '/favicon.png']) {
        b = await _fetch(Uri.parse('$origin$p'));
        if (b != null) break;
      }
      await dir.create(recursive: true);
      await f.writeAsBytes(b ?? Uint8List(0));
      return b;
    } catch (_) {
      return null;
    }
  }

  static Future<Uint8List?> _fetch(Uri u) async {
    final c = HttpClient()
      ..connectionTimeout = const Duration(seconds: 5)
      ..userAgent = 'Symbolon';
    try {
      final rq = await c.getUrl(u).timeout(const Duration(seconds: 5));
      final rs = await rq.close().timeout(const Duration(seconds: 5));
      if (rs.statusCode != 200) return null;
      final type = rs.headers.contentType?.primaryType ?? 'image';
      if (type != 'image' && type != 'application') return null;   // an HTML "not found" page
      final b = BytesBuilder(copy: false);
      await for (final chunk in rs.timeout(const Duration(seconds: 5))) {
        b.add(chunk);
        if (b.length > _maxBytes) return null;
      }
      final bytes = b.takeBytes();
      return bytes.length < 16 ? null : bytes;
    } catch (_) {
      return null;
    } finally {
      c.close(force: true);
    }
  }
}

/// A login's icon in a circle, or [fallback] while there is none.
class SiteIcon extends StatelessWidget {
  final Favicons? favicons;
  final String origin;
  final Widget fallback;
  const SiteIcon({super.key, required this.favicons, required this.origin, required this.fallback});

  @override
  Widget build(BuildContext context) {
    final f = favicons;
    if (f == null || origin.isEmpty) return fallback;
    return FutureBuilder<Uint8List?>(
      future: f.icon(origin),
      builder: (context, s) {
        final b = s.data;
        if (b == null) return fallback;
        return CircleAvatar(
          backgroundColor: Colors.white,
          child: Padding(
            padding: const EdgeInsets.all(6),
            child: Image.memory(b, width: 24, height: 24, fit: BoxFit.contain, gaplessPlayback: true, errorBuilder: (_, _, _) => fallback),
          ),
        );
      },
    );
  }
}
