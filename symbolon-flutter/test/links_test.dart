import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/links.dart';
import 'package:symbolon_ui/recovery_sheet.dart';

void main() {
  final log = '0f' * 32, kit = '9a' * 32;

  test('an org invite link round-trips, and anything else is refused', () {
    final i = OrgInvite('01' * 16, 'ab' * 32, 'cd' * 16);
    final back = OrgInvite.parse(i.link)!;
    expect([back.org, back.founder, back.code], [i.org, i.founder, i.code]);
    expect(OrgInvite.parse('symbolon://org?o=${'01' * 16}&f=${'AB' * 32}&c=${'CD' * 16}')?.founder, i.founder);   // capitals are fine
    for (final bad in ['', 'symbolon://pair?o=x', 'symbolon://org?o=01&f=${'ab' * 32}&c=${'cd' * 16}', 'https://org?o=${'01' * 16}&f=${'ab' * 32}&c=${'cd' * 16}', 'symbolon://org?o=${'zz' * 16}&f=${'ab' * 32}&c=${'cd' * 16}']) {
      expect(OrgInvite.parse(bad), isNull, reason: bad);
    }
  });

  test('a recovery sheet link carries the log and the kit', () {
    final s = RecoverySheet.parse(RecoverySheet(log, kit).link)!;
    expect([s.log, s.kit], [log, kit]);
    expect(RecoverySheet.parse('symbolon://recover?l=$log'), isNull);
    expect(RecoverySheet.parse('symbolon://recover?l=${log.substring(2)}&k=$kit'), isNull);
    expect(groupsOf('abcdefghij'), ['abcd', 'efgh', 'ij']);
  });

  test('the check asks one group of the log and one of the kit, or two different ones of a lone kit', () {
    for (var seed = 0; seed < 50; seed++) {
      final a = SheetCheck.asks(RecoverySheet(log, kit), Random(seed));
      expect(a[0].$1, startsWith('Group '));
      expect(a[0].$1, endsWith('identity log'));
      expect(a[1].$1, endsWith('recovery kit'));
      final lone = SheetCheck.asks(RecoverySheet('', kit), Random(seed));
      expect(lone[0].$1, isNot(lone[1].$1));
    }
  });
}
