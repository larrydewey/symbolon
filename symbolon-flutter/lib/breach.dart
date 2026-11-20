// The breach check (SPEC 26.1): each login's password against Pwned
// Passwords, run by the agent (`symbolon device vault breach`). Only five
// hex digits of each password's SHA-1 leave the device. This file reads the
// agent's report and gives the agent what it needs to reach the service:
// trust anchors where the system has no PEM bundle (Android) and, on
// Android, the network's DNS servers.

import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

import 'settings.dart';

/// What one check found.
class BreachReport {
  /// Breached logins: the item's name and how many times the corpus has
  /// seen its password.
  final Map<String, int> breached;
  final int checked;

  /// Protected items (SPEC 18.10), skipped: their passwords need the quorum.
  final int protected;
  const BreachReport(this.breached, this.checked, this.protected);

  /// The agent's lines: "breached NAME-HEX COUNT", "protected N not
  /// checked", "checked N breached M". Null without the final tally (the
  /// run did not finish).
  static BreachReport? parse(List<String> lines) {
    final breached = <String, int>{};
    int? checked;
    var protected = 0;
    for (final l in lines) {
      final f = l.trim().split(' ');
      if (f.length == 3 && f[0] == 'breached') {
        final n = int.tryParse(f[2]);
        final name = _unhex(f[1]);
        if (n != null && name != null) breached[name] = n;
      } else if (f.length == 4 && f[0] == 'protected' && f[2] == 'not') {
        protected = int.tryParse(f[1]) ?? 0;
      } else if (f.length == 4 && f[0] == 'checked' && f[2] == 'breached') {
        checked = int.tryParse(f[1]);
      }
    }
    return checked == null ? null : BreachReport(breached, checked, protected);
  }

  static String? _unhex(String h) {
    if (h.length.isOdd) return null;
    try {
      return utf8.decode([for (var i = 0; i < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)]);
    } on FormatException {
      return null;
    }
  }
}

/// PEM bundles a Linux system may keep its roots in; the agent's default is
/// the first (Debian, Ubuntu, Arch).
const linuxBundles = ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/cert.pem', '/etc/ssl/ca-bundle.pem'];

/// Where Android keeps its system roots, one certificate per file: the
/// Conscrypt module's copy (Android 14 and later, updated with the module)
/// first, then the system image's.
const androidRootDirs = ['/apex/com.android.conscrypt/cacerts', '/system/etc/security/cacerts'];

final _pem = RegExp(r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----');

/// The certificates in [dir]'s files, as one PEM bundle; empty when none.
String pemBundleOf(Directory dir) {
  final out = StringBuffer();
  final files = dir.listSync().whereType<File>().toList()..sort((a, b) => a.path.compareTo(b.path));
  for (final f in files) {
    try {
      for (final m in _pem.allMatches(f.readAsStringSync())) {
        out.writeln(m.group(0));
      }
    } on FileSystemException {
      continue;
    }
  }
  return out.toString();
}

/// The environment the agent's breach check needs here, on top of
/// [Settings.agentEnv]: SYMBOLON_BREACH_CA where the agent's default bundle
/// is missing, and RESID_RESOLV_CONF on Android. Throws a [StateError] with
/// a message for the user when the check cannot run on this system.
Future<Map<String, String>> breachEnv(Settings settings) async {
  if (Platform.isAndroid) return _androidEnv(settings);
  if (File(linuxBundles.first).existsSync()) return const {};
  final other = linuxBundles.skip(1).where((p) => File(p).existsSync()).firstOrNull;
  if (other == null) throw StateError('No certificate bundle found on this system (looked for ${linuxBundles.join(', ')}).');
  return {'SYMBOLON_BREACH_CA': other};
}

Future<Map<String, String>> _androidEnv(Settings settings) async {
  // The roots, gathered afresh each time: they change with system updates.
  var pem = '';
  for (final d in androidRootDirs) {
    final dir = Directory(d);
    if (dir.existsSync()) pem = pemBundleOf(dir);
    if (pem.isNotEmpty) break;
  }
  if (pem.isEmpty) throw StateError('Could not read the phone\'s trusted certificates.');
  final bundle = File('${settings.file.parent.path}/breach-roots.pem');
  await bundle.writeAsString(pem, flush: true);
  final servers = await const MethodChannel('symbolon/platform').invokeListMethod<String>('dnsServers') ?? [];
  if (servers.isEmpty) throw StateError('No network connection.');
  return {
    'SYMBOLON_BREACH_CA': bundle.path,
    'RESID_RESOLV_CONF': [for (final s in servers) 'nameserver $s'].join('\n'),
  };
}

/// 9659365 as "9,659,365".
String groupedCount(int n) {
  final s = n.toString();
  final out = StringBuffer();
  for (var i = 0; i < s.length; i++) {
    if (i > 0 && (s.length - i) % 3 == 0) out.write(',');
    out.write(s[i]);
  }
  return out.toString();
}

/// "Seen 3 times in data breaches", for a breached login's warning.
String seenInBreaches(int n) => n == 1 ? 'Seen once in data breaches' : 'Seen ${groupedCount(n)} times in data breaches';
