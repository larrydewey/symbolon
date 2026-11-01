import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/managed.dart';
import 'package:symbolon_ui/pages/org_page.dart';

void main() {
  test('managed configuration: an organization only with a well-formed id and founder', () {
    final m = ManagedConfig.fromMap({'org_id': ' 0123456789ABCDEF0123456789abcdef ', 'org_founder': 'a' * 64, 'invite_code': 'F' * 32, 'disable_duress': true});
    expect(m.hasOrg, isTrue);
    expect(m.orgId, '0123456789abcdef0123456789abcdef');
    expect(m.inviteCode, 'f' * 32);
    expect(m.noDuress, isTrue);
    expect(ManagedConfig.fromMap({'org_id': 'short', 'org_founder': 'a' * 64}).hasOrg, isFalse);
    expect(ManagedConfig.fromMap({}).hasOrg, isFalse);
  });

  test('org show parses role, recovery and requests', () {
    final o = OrgInfo.parse(['org 0123456789abcdef0123456789abcdef 41636d65', 'version 3 gov 2', 'role admin', 'policy min_pin_len=6',
        'recovery on 2/3 delay 259200', 'recovery-request 00112233445566778899aabbccddeeff ${'b' * 64} 1800000000'])!;
    expect(o.name, 'Acme');
    expect(o.admin, isTrue);
    expect(o.recovery, 'on 2/3 delay 259200');
    expect(o.requests.single.opensAt, 1800000000);
    expect(OrgInfo.parse(['role member']), isNull);
    expect(OrgMember.parse('${'a' * 64} 416c696365 - owner -')!.name, 'Alice');
  });
}
