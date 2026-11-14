import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/app.dart';
import 'package:symbolon_ui/hardware.dart';
import 'package:symbolon_ui/pages/devices_page.dart';
import 'package:symbolon_ui/pages/join_page.dart';
import 'package:symbolon_ui/qr_view.dart';
import 'package:symbolon_ui/settings.dart';

import 'fake_agent.dart';

void main() {
  late FakeAgent agent;
  late Settings settings;

  setUp(() async {
    agent = await FakeAgent.create();
    settings = Settings(File('${agent.dir.path}/settings.json'), binary: agent.path, deviceDir: '${agent.dir.path}/dev', tutorialSeen: true, keepUnlockedMinutes: 0);
  });
  tearDown(() => agent.dispose());

  Future<void> settle(WidgetTester t, [int n = 20]) async {
    for (var i = 0; i < n; i++) {
      await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
      await t.pump(const Duration(milliseconds: 50));
    }
  }

  // As on a machine with a TPM, whatever this one has: a 4-digit PIN is enough.
  Future<HardwareState> tpm({bool keystore = false}) async => HardwareState.ready;

  void sized(WidgetTester t) {
    t.view.devicePixelRatio = 2;
    t.view.physicalSize = const Size(460, 1100) * 2;
    addTearDown(t.view.reset);
  }

  testWidgets('joining: choose a PIN, the code appears with this device\'s addresses, then the device joins', (t) async {
    sized(t);
    await t.pumpWidget(MaterialApp(home: JoinPage(app: App(settings), hardware: tpm, addresses: () async => ['192.168.1.20', '10.0.0.5'])));
    await settle(t, 4);
    await t.enterText(find.byKey(const Key('join-pin')), '2468');
    await t.enterText(find.byKey(const Key('join-pin2')), '2468');
    await t.tap(find.byKey(const Key('join-start')));
    await t.pump();
    await settle(t, 6);
    expect(find.byKey(const Key('join-qr')), findsOneWidget);
    expect(find.text('Waiting for your other device to scan the code…'), findsOneWidget);
    expect((t.widget(find.byKey(const Key('join-qr'))) as QrView).data, 'symbolon://link?a=192.168.1.20,10.0.0.5&p=40123&s=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
    await settle(t, 60);
    expect(find.byKey(const Key('join-done')), findsOneWidget);
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device link-new ${agent.dir.path}/dev --host 192.168.1.20,10.0.0.5'));
  });

  testWidgets('joining: mismatched PINs are refused before anything runs; a failure offers a retry', (t) async {
    sized(t);
    await t.pumpWidget(MaterialApp(home: JoinPage(app: App(settings), hardware: tpm, addresses: () async => ['192.168.1.20'])));
    await settle(t, 4);
    await t.enterText(find.byKey(const Key('join-pin')), '2468');
    await t.enterText(find.byKey(const Key('join-pin2')), '2469');
    await t.tap(find.byKey(const Key('join-start')));
    await t.pump();
    expect(find.text('The two PINs differ.'), findsOneWidget);
    expect(await t.runAsync(() => agent.argsLog.exists()), isFalse);
    await t.pump(const Duration(seconds: 5));
    await t.runAsync(() => File('${agent.dir.path}/link-fail').writeAsString(''));
    await t.enterText(find.byKey(const Key('join-pin2')), '2468');
    await t.tap(find.byKey(const Key('join-start')));
    await t.pump();
    await settle(t, 60);
    expect(find.byKey(const Key('join-error')), findsOneWidget);
    expect(find.text('Your other device did not scan the code in time. Try again, with both devices on the same network.'), findsOneWidget);
    await t.tap(find.byKey(const Key('join-retry')));
    await t.pump();
    expect(find.byKey(const Key('join-pin')), findsOneWidget);
  });

  testWidgets('adding: a pasted link and the PIN run link-add; something else is refused', (t) async {
    sized(t);
    await t.pumpWidget(MaterialApp(home: DevicesPage(app: App(settings))));
    await t.pump();
    await t.enterText(find.byKey(const Key('add-link')), 'symbolon://pair?h=1&p=2&c=x');
    await t.tap(find.byKey(const Key('add-device')));
    await t.pump();
    expect(await t.runAsync(() => agent.argsLog.exists()), isFalse);
    await t.pump(const Duration(seconds: 5));
    const link = 'symbolon://link?a=192.168.1.20&p=40123&s=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    await t.enterText(find.byKey(const Key('add-link')), link);
    await t.tap(find.byKey(const Key('add-device')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('secret-field')), '2468');
    await t.tap(find.byKey(const Key('secret-ok')));
    await t.pump();
    await settle(t);
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device link-add ${agent.dir.path}/dev $link'));
    expect(find.text('Device added'), findsOneWidget);
  });
}
