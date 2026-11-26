// Pairing links, and the pairing client against a real Symbolon Home box
// (symbolon-resid/target/symbolon home init/invite/serve), when the agent
// is built: the pinned TLS connection, the setup (once per code), a
// refused forged fingerprint, pairing only with the setup's token, once.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/cli.dart';
import 'package:symbolon_ui/home_link.dart';

void main() {
  final bin = File('${Directory.current.path}/../symbolon-resid/target/symbolon');
  const code = 'NKYA_F-X0islgX1gz8wVmg', fp = '3zpIrrURNjXP3LEmr3dSVn8qsaxo4zqr8bEVj7N0bMc';

  test('pairing links are read and checked', () {
    final l = HomeLink.parse('symbolon://pair?h=192.168.1.20&p=47100&c=$code&f=$fp')!;
    expect(l.host, '192.168.1.20');
    expect(l.port, 47100);
    expect(l.code, code);
    expect(HomeLink.parse('https://pair?h=x&p=1&c=$code&f=$fp'), isNull);
    expect(HomeLink.parse('symbolon://pair?h=x&p=0&c=$code&f=$fp'), isNull);
    expect(HomeLink.parse('symbolon://pair?h=x&p=47100&c=short&f=$fp'), isNull);
    expect(HomeLink.parse('symbolon://pair?h=x&p=47100&c=$code&f=short'), isNull);
    expect(HomeLink.parse('not a link'), isNull);
  });

  test('a real box: setup over the pinned connection, once; a forged fingerprint refused; pairing with the token, once', () async {
    final d = await Directory.systemTemp.createTemp('symbolon-home');
    final base = 30000 + (pid % 2000) * 10;
    Process? serve;
    try {
      // Two witnesses outside the box (named only: this test does not run
      // an inception), and the keys sealed to a passphrase.
      final keys = <String>[];
      for (final w in ['x1', 'x2']) {
        final g = await Process.run(bin.path, ['witness', 'keygen', '${d.path}/$w.key']);
        keys.add((g.stdout as String).trim());
      }
      await File('${d.path}/pass').writeAsString('household passphrase\n');
      final init = await Process.run(bin.path, ['home', 'init', '${d.path}/box', '127.0.0.1', '--ports', '$base',
          '--witness', 'pc.lan:47110:${keys[0]}', '--witness', 'w.example.org:443:${keys[1]}',
          '--seal', 'passphrase', '--passphrase-file', '${d.path}/pass', '--fast-kdf']);
      expect(init.exitCode, 0, reason: '${init.stderr}');
      final inv = await Process.run(bin.path, ['home', 'invite', '${d.path}/box', 'alice']);
      expect(inv.exitCode, 0, reason: '${inv.stderr}');
      final link = HomeLink.parse((inv.stdout as String).trim())!;
      serve = await Process.start(bin.path, ['home', 'serve', '${d.path}/box', '--passphrase-file', '${d.path}/pass']);
      for (var i = 0; i < 100; i++) {
        try {
          (await Socket.connect('127.0.0.1', base)).destroy();
          break;
        } on SocketException {
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
      }

      final forged = HomeLink(link.host, link.port, link.code, 'A' * 43);
      await expectLater(HomeClient(forged).setup(), throwsA(isA<HomeError>().having((e) => e.message, 'message', contains('certificate does not match'))));

      // The box makes alice's cosigner within ten seconds; until then the
      // setup says to retry, and the code is not spent.
      HomeSetup? got;
      for (var i = 0; i < 60 && got == null; i++) {
        try {
          got = await HomeClient(link).setup();
        } on HomeError catch (e) {
          if (!e.retry) rethrow;
          await Future<void>.delayed(const Duration(seconds: 1));
        }
      }
      final s = got!;
      expect(s.name, 'alice');
      expect(s.pairToken, hasLength(22));
      expect(s.secure, isTrue);
      expect(s.reminder, isEmpty);
      expect(s.relayPort, base + 1);
      expect(s.witnesses, hasLength(3));
      expect(s.caPem, contains('BEGIN CERTIFICATE'));
      expect(s.caPem, await File('${d.path}/box/tls/ca.pem').readAsString());

      final made = await SymbolonCli(bin.path).deviceNew('${d.path}/dev', s.relayHost, s.relayPort, '2468', '', unprotected: true, fastKdf: true);
      expect(made.ok, isTrue, reason: made.err);
      // The setup spent the code: a second one is refused.
      await expectLater(HomeClient(link).setup(), throwsA(isA<HomeError>().having((e) => e.message, 'message', contains('used or has expired'))));
      await expectLater(HomeClient(link).pair(made.lines.last, 'A' * 22), throwsA(isA<HomeError>()));
      await expectLater(HomeClient(link).pair('not keys', s.pairToken), throwsA(isA<HomeError>()));
      await HomeClient(link).pair(made.lines.last, s.pairToken);
      await expectLater(HomeClient(link).pair(made.lines.last, s.pairToken), throwsA(isA<HomeError>()));
    } finally {
      serve?.kill();
      await Process.run('pkill', ['-f', '${d.path}/']);
      await d.delete(recursive: true);
    }
  }, timeout: const Timeout(Duration(minutes: 3)), skip: bin.existsSync() ? false : 'build symbolon-resid/target/symbolon first');
}
