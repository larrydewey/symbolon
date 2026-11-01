// Against the real agent (symbolon-resid/target/symbolon), when it is
// built: a new unprotected device, then its status. No relay is needed for
// either.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/cli.dart';

void main() {
  final bin = File('${Directory.current.path}/../symbolon-resid/target/symbolon');

  test('device new and status with the real agent', () async {
    final d = await Directory.systemTemp.createTemp('symbolon-ui-real');
    try {
      final cli = SymbolonCli(bin.path);
      final made = await cli.deviceNew('${d.path}/dev', '127.0.0.1', 1, '2468', '1357', unprotected: true, fastKdf: true);
      expect(made.ok, isTrue, reason: made.err);
      expect(made.lines.last, matches(RegExp(r'^[0-9a-f]+$')));
      final s = DeviceStatus.parse(await cli.status('${d.path}/dev'));
      expect(s, isNotNull);
      expect(s!.unprotected, isTrue);
      expect(s.log, isNull);
      expect(s.party, hasLength(64));
    } finally {
      await d.delete(recursive: true);
    }
  }, timeout: const Timeout(Duration(minutes: 5)), skip: bin.existsSync() ? false : 'build symbolon-resid/target/symbolon first');
}
