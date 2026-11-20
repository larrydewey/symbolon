import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/breach.dart';
import 'package:symbolon_ui/settings.dart';

String hexOf(String s) => s.codeUnits.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('the agent\'s report', () {
    test('breached logins with their counts, the protected items skipped and the tally', () {
      final r = BreachReport.parse(['breached ${hexOf('mail')} 9659365', 'breached ${hexOf('bank login')} 1', 'protected 2 not checked', 'checked 5 breached 2'])!;
      expect(r.breached, {'mail': 9659365, 'bank login': 1});
      expect(r.checked, 5);
      expect(r.protected, 2);
    });

    test('a clean vault', () {
      final r = BreachReport.parse(['checked 3 breached 0'])!;
      expect(r.breached, isEmpty);
      expect(r.checked, 3);
      expect(r.protected, 0);
    });

    test('without the tally the run did not finish, and nothing is reported', () {
      expect(BreachReport.parse(['breached ${hexOf('mail')} 4']), isNull);
    });

    test('malformed lines are skipped', () {
      final r = BreachReport.parse(['breached zz 4', 'breached ${hexOf('a')} many', 'breached abc 3', 'checked 1 breached 0'])!;
      expect(r.breached, isEmpty);
    });
  });

  test('counts read as people write them', () {
    expect(groupedCount(0), '0');
    expect(groupedCount(999), '999');
    expect(groupedCount(1000), '1,000');
    expect(groupedCount(9659365), '9,659,365');
    expect(seenInBreaches(1), 'Seen once in data breaches');
    expect(seenInBreaches(4242), 'Seen 4,242 times in data breaches');
  });

  test('Android\'s one-certificate-per-file roots become one PEM bundle; text around each is dropped', () async {
    final d = await Directory.systemTemp.createTemp('roots');
    addTearDown(() => d.delete(recursive: true));
    const a = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----';
    const b = '-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----';
    File('${d.path}/5ad8a5d6.0').writeAsStringSync('$a\nCertificate:\n    Data: ...\n');
    File('${d.path}/0a775a30.0').writeAsStringSync(b);
    File('${d.path}/readme').writeAsStringSync('not a certificate');
    expect(pemBundleOf(d), '$b\n$a\n');
  });

  group('findings kept in the settings', () {
    late Directory d;
    setUp(() async => d = await Directory.systemTemp.createTemp('breach-settings'));
    tearDown(() => d.delete(recursive: true));

    test('survive a restart, per vault, and go when the password does', () async {
      final f = File('${d.path}/settings.json');
      final s = Settings(f);
      await s.setBreach('', BreachFindings(DateTime.utc(2026, 11, 20, 8), {'mail': 9659365, 'shop': 3}, checked: 4, protected: 1));
      await s.setBreach('0123', BreachFindings(DateTime.utc(2026, 11, 20, 9), {'wifi': 7}, checked: 1));
      final again = await Settings.load(f);
      expect(again.breachedCount('mail'), 9659365);
      expect(again.breachedCount('wifi'), isNull);
      expect(again.breachedCount('wifi', share: '0123'), 7);
      expect(again.breach['']!.at, DateTime.utc(2026, 11, 20, 8));
      expect(again.breach['']!.checked, 4);
      expect(again.breach['']!.protected, 1);
      await again.clearBreached('mail');
      final third = await Settings.load(f);
      expect(third.breachedCount('mail'), isNull);
      expect(third.breachedCount('shop'), 3);
    });

    test('another window\'s save keeps a check the app made meanwhile', () async {
      final f = File('${d.path}/settings.json');
      final app = Settings(f);
      final window = Settings(f);   // loaded before the check
      await app.setBreach('', BreachFindings(DateTime.utc(2026, 11, 20), {'mail': 2}, checked: 1));
      await window.addCredential(const Credential('example.com', 'cc', '04'));   // reads the file again first
      expect((await Settings.load(f)).breachedCount('mail'), 2);
    });
  });
}
