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

  test('device status is parsed', () async {
    final s = DeviceStatus.parse(await cli.status('/d'))!;
    expect(s.party, startsWith('0011'));
    expect(s.unprotected, isFalse);
    expect(s.log, startsWith('fa8f'));
    expect([s.sequence, s.epoch, s.parties, s.threshold, s.pending], [3, 2, 4, 2, 1]);
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
