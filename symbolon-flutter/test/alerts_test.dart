// Duress alerts (SPEC 14.4) in the app: the agent's output parsed, the
// beacon told of each unlock (either PIN, not twice in a row), the Duress
// alerts page saving contacts and showing their ntfy topics, and the "I'm
// safe" button only on a device that did not open the window.

import 'dart:io';

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/cli.dart';
import 'package:symbolon_ui/main.dart';
import 'package:symbolon_ui/session.dart';
import 'package:symbolon_ui/settings.dart';

import 'fake_agent.dart';

void main() {
  late FakeAgent agent;
  late Settings settings;

  setUp(() async {
    agent = await FakeAgent.create();
    settings = Settings(File('${agent.dir.path}/settings.json'), binary: agent.path, deviceDir: '${agent.dir.path}/dev', tutorialSeen: true);
  });
  tearDown(() => agent.dispose());

  Future<void> settle(WidgetTester t) async {
    for (var i = 0; i < 20; i++) {
      await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
      await t.pump(const Duration(milliseconds: 50));
    }
  }

  Future<void> start(WidgetTester t) async {
    t.view.devicePixelRatio = 3;
    t.view.physicalSize = const Size(420, 1400) * 3;
    addTearDown(t.view.reset);
    await t.pumpWidget(SymbolonApp(settings: settings));
    await settle(t);
  }

  Future<void> pin(WidgetTester t, String p) async {
    await t.enterText(find.byKey(const Key('secret-field')), p);
    await t.tap(find.byKey(const Key('secret-ok')));
    await t.pump();
    await settle(t);
  }

  // Back from the page, then the lock (stops the session's timer), and
  // time for any message to go.
  Future<void> lockUp(WidgetTester t) async {
    if (find.byType(BackButton).evaluate().isNotEmpty) {
      await t.pageBack();
      await t.pumpAndSettle();
    }
    await t.pump(const Duration(seconds: 10));
    final l = find.byKey(const Key('lock'));
    if (l.evaluate().isNotEmpty) await t.tap(l.first);
    await t.pump();
    await settle(t);
  }

  Future<void> openAlerts(WidgetTester t, String p) async {
    await t.tap(find.text('More').last);
    await t.pump(const Duration(milliseconds: 300));
    await t.tap(find.byKey(const Key('open-alerts')));
    await t.pump(const Duration(milliseconds: 300));
    await settle(t);
    await pin(t, p);
  }

  String hx(String s) => s.codeUnits.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  test('device alerts parses: the name, each contact with its topic, the window', () {
    final r = CliResult(0, 'person ${hx('Larry')}\ncontact ${hx('Ann')} 1 ${hx('ann@example.com')} - - - duress-0011\ncontact ${hx('Me')} 0 - - ${hx('larry')} - -\nduress open 1800000000 00aa\n', '');
    final s = AlertSettings.parse(r)!;
    expect(s.person, 'Larry');
    expect(s.contacts.map((c) => c.name), ['Ann', 'Me']);
    expect(s.contacts[0].ntfy, isTrue);
    expect(s.contacts[0].topic, 'duress-0011');
    expect(s.contacts[0].email, 'ann@example.com');
    expect(s.contacts[1].household, 'larry');
    expect(s.contacts[1].topic, '');
    expect(s.duress, isTrue);
    expect(s.startedAt, 1800000000);
    expect(s.party, '00aa');
    expect(AlertSettings.parse(const CliResult(0, 'person -\n', '')), isNull, reason: 'no window line: not an answer');
    expect(AlertSettings.parse(const CliResult(1, '', 'device: the cosigner did not answer')), isNull);
  });

  test('a contact line is hex, - for empty, without the topic', () {
    const c = AlertContact(name: 'Ann', ntfy: true, phone: '+1555', topic: 'duress-x');
    expect(c.line, 'contact ${hx('Ann')} 1 - ${hx('+1555')} - -');
    expect(c.summary, 'ntfy · +1555');
  });

  test('household alerts parse', () {
    final a = HouseholdAlert.parse(CliResult(0, 'alert ${hx('Duress alert: Larry')} ${hx('DURESS: Larry ...')}\nnoise\n', ''));
    expect(a.length, 1);
    expect(a[0].subject, 'Duress alert: Larry');
    expect(a[0].text, 'DURESS: Larry ...');
  });

  test('each unlock is told once: either PIN, not the same one again at once', () {
    final told = <String>[];
    final s = PinSession(keepMinutes: 0)..onUnlock = told.add;
    s.remember('2468');
    s.remember('2468');
    s.remember('1357');
    s.remember('2468');
    expect(told, ['2468', '1357', '2468']);
    final k = PinSession(keepMinutes: 5)..onUnlock = told.add;
    told.clear();
    k.remember('2468');
    k.remember('2468');
    k.lock();
    expect(told, ['2468']);
    k.dispose();
  });

  testWidgets('an unlock sends the beacon in the background', (t) async {
    await start(t);
    await openAlerts(t, '2468');
    await settle(t);
    final b = await t.runAsync(() => File('${agent.dir.path}/beacons.log').readAsString());
    expect(b!.trim().split('\n').first.trim(), '2468');
    await lockUp(t);
  });

  testWidgets('the page adds a contact, saves it, and shows the ntfy topic', (t) async {
    await start(t);
    await openAlerts(t, '2468');
    expect(find.text('No one yet.'), findsOneWidget);
    await t.enterText(find.byKey(const Key('alerts-person')), 'Larry');
    await t.tap(find.byKey(const Key('add-contact')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('contact-name')), 'Ann');
    await t.enterText(find.byKey(const Key('contact-email')), 'not an address');
    await t.tap(find.byKey(const Key('contact-done')));
    await t.pump();
    expect(find.text('That email address does not look right.'), findsOneWidget);
    await t.enterText(find.byKey(const Key('contact-email')), 'ann@example.com');
    await t.enterText(find.byKey(const Key('contact-phone')), '+1 555 123 4567');
    await t.tap(find.byKey(const Key('contact-done')));
    await t.pumpAndSettle();
    expect(find.text('Ann'), findsOneWidget);
    await t.tap(find.byKey(const Key('alerts-save')));
    await t.pump();
    await settle(t);
    final stdin = await t.runAsync(() => File('${agent.dir.path}/stdin.log').readAsString());
    expect(stdin, contains('person ${hx('Larry')}\ncontact ${hx('Ann')} 1 ${hx('ann@example.com')} ${hx('+15551234567')} - -\n'));
    expect(find.textContaining('ntfy topic duress-'), findsOneWidget);
    await lockUp(t);
  });

  testWidgets('under the duress PIN the page shows no one', (t) async {
    await t.runAsync(() => File('${agent.dir.path}/alerts.state').writeAsString('person ${hx('Larry')}\ncontact ${hx('Ann')} 1 - - - - duress-01\n'));
    await start(t);
    await openAlerts(t, '1357');
    expect(find.text('No one yet.'), findsOneWidget);
    expect(find.text('Ann'), findsNothing);
    await lockUp(t);
  });

  testWidgets('another device ends the window: "I\'m safe"', (t) async {
    await t.runAsync(() => File('${agent.dir.path}/duress-open').writeAsString('ffee'));
    await start(t);
    await openAlerts(t, '2468');
    expect(find.byKey(const Key('duress-open')), findsOneWidget);
    await t.tap(find.byKey(const Key('end-duress')));
    await t.pump();
    await settle(t);
    expect(find.byKey(const Key('duress-open')), findsNothing);
    expect(await t.runAsync(() => File('${agent.dir.path}/duress-open').exists()), isFalse);
    await lockUp(t);
  });

  testWidgets('the device that opened the window has no "I\'m safe" button', (t) async {
    await t.runAsync(() => File('${agent.dir.path}/duress-open').writeAsString('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'));
    await start(t);
    await openAlerts(t, '2468');
    expect(find.byKey(const Key('duress-open')), findsOneWidget);
    expect(find.byKey(const Key('end-duress')), findsNothing);
    expect(find.textContaining('This device opened it'), findsOneWidget);
    await lockUp(t);
  });
}
