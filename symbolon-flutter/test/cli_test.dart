import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/cli.dart';

import 'fake_agent.dart';

void main() {
  late FakeAgent agent;
  late SymbolonCli cli;

  setUp(() async {
    agent = await FakeAgent.create();
    cli = SymbolonCli(agent.path);
  });
  tearDown(() => agent.dispose());

  test('PINs and secrets go to standard input, never into the arguments', () async {
    final r = await cli.vaultPut('/d', 'mail', 'hunter2', '2468');
    expect(r.ok, isTrue);
    final args = await agent.argsLog.readAsString();
    expect(args.trim(), 'device vault put /d mail');
    expect(args, isNot(contains('2468')));
    expect(args, isNot(contains('hunter2')));
    expect(await agent.stdinLog.readAsString(), '2468\nhunter2\n--\n');
  });

  test("a kit's passphrase goes to standard input, and only when the sheet is protected", () async {
    final plain = '9a' * 32, sealed = '01120301${'ab' * 64}';
    expect(kitIsProtected(plain), isFalse);
    expect(kitIsProtected(sealed), isTrue);
    expect(kitIsProtected('0112 0301-${'AB' * 64}'), isTrue);   // as written, in groups
    expect(newKitPassLines(''), isEmpty);
    expect(newKitPassLines('', explicitNone: true), ['']);
    expect(newKitPassLines('lantern orchard'), ['lantern orchard', 'lantern orchard']);
    await cli.deviceInit('/d', 'cc', ['w1', 'w2', 'w3'], '2468', kitPassphrase: 'lantern orchard');
    await cli.recover('/d', sealed, '0f' * 32, kitPassphrase: 'old words here', newKitPassphrase: 'new words here');
    await cli.recover('/d', plain, '0f' * 32);
    await cli.recoverFinish('/d', sealed, '2468', kitPassphrase: 'old words here');
    await cli.recoverFinish('/d', plain, '2468', kitPassphrase: 'ignored');
    expect(await cli.kitStatus('/d'), 'plain');
    await cli.kitRenew('/d', '2468', 'new words here');
    await cli.kitRenew('/d', '2468', '');
    final args = await agent.argsLog.readAsString();
    expect(args, isNot(contains('words')));
    expect(args, isNot(contains('lantern')));
    expect(await agent.stdinLog.readAsString(),
        '2468\nlantern orchard\nlantern orchard\n--\n'
        'old words here\nnew words here\nnew words here\n--\n'
        '\n--\n'
        '2468\nold words here\n--\n'
        '2468\n--\n'
        '\n--\n'
        '2468\nnew words here\nnew words here\n--\n'
        '2468\n\n--\n');
    expect(await cli.kitStatus('/d'), 'protected');
  });

  test('device status is parsed', () async {
    final s = DeviceStatus.parse(await cli.status('/d'))!;
    expect(s.party, startsWith('0011'));
    expect(s.unprotected, isFalse);
    expect(s.log, startsWith('fa8f'));
    expect([s.sequence, s.epoch, s.parties, s.threshold, s.pending], [3, 2, 4, 2, 1]);
  });

  test('a device before the security update says so, and the update sends both PINs on standard input', () async {
    const r = CliResult(0, 'security-update due\nparty ab\nprofile TPM\nlog none (run `symbolon device init`)\n', '');
    expect(DeviceStatus.parse(r)!.securityUpdate, isTrue);
    expect(DeviceStatus.parse(const CliResult(0, 'party ab\nprofile TPM\n', ''))!.securityUpdate, isFalse);
    await cli.securityUpdate('/d', '2468', '1357');
    expect((await agent.argsLog.readAsString()).trim(), 'device security-update /d');
    expect(await agent.stdinLog.readAsString(), startsWith('2468\n1357\n'));
  });

  test('a device before inception has no log', () {
    const r = CliResult(0, 'party ab\nprofile UNPROTECTED (no TPM)\nlog none (run `symbolon device init`)\n', '');
    final s = DeviceStatus.parse(r)!;
    expect(s.unprotected, isTrue);
    expect(s.log, isNull);
    expect(s.epoch, isNull);
  });

  test('register output gives the credential; a wrong PIN gives the reason', () async {
    final ok = await cli.register('/d', 'login.example.com', '2468');
    expect(ok.field('credential-id'), hasLength(64));
    expect(ok.field('public-key'), hasLength(130));
    final bad = await cli.register('/d', 'login.example.com', '9999');
    expect(bad.ok, isFalse);
    expect(bad.problem, 'wrong PIN');
  });

  test('optional flags are passed only when set', () async {
    await cli.deviceNew('/d', 'relay.example', 443, '2468', '', unprotected: true, ca: '/etc/ca.pem');
    await cli.deviceNew('/e', 'relay.example', 443, '2468', '');
    final lines = (await agent.argsLog.readAsString()).trim().split('\n');
    expect(lines[0], 'device new /d relay.example 443 --unprotected --ca /etc/ca.pem');
    expect(lines[1], 'device new /e relay.example 443');
  });

  test('a witness change passes each witness as a flag and the PIN on standard input', () async {
    await cli.witnesses('/d', '2468', add: ['pc.lan:47110:04ab'], remove: ['box.lan:47103', 'box.lan:47104']);
    final args = (await agent.argsLog.readAsString()).trim();
    expect(args, 'device witnesses /d --add pc.lan:47110:04ab --remove box.lan:47103 --remove box.lan:47104');
    expect(args, isNot(contains('2468')));
    expect(await agent.stdinLog.readAsString(), startsWith('2468\n'));
  });

  test('a missing binary is reported, not thrown', () async {
    final r = await const SymbolonCli('/nonexistent/symbolon').status('/d');
    expect(r.code, 127);
    expect(r.problem, contains('cannot run'));
  });

  test('a run past its timeout is killed', () async {
    final slow = File('${agent.dir.path}/slow');
    await slow.writeAsString('#!/bin/bash\nsleep 30\n');
    await Process.run('chmod', ['+x', slow.path]);
    final r = await SymbolonCli(slow.path).run(['x'], timeout: const Duration(milliseconds: 300));
    expect(r.code, 124);
    expect(r.problem, 'timed out');
  });
}
