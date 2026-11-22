// Protected vault items (SPEC 18.10) in the app: the list marks them, the
// item page protects and unprotects with what changes said first, a move
// into a shared folder asks first, the Devices page turns the tier on and
// shows each device's openings, and the home page warns of an unusual day.

import 'dart:io';

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/cli.dart';
import 'package:symbolon_ui/main.dart';
import 'package:symbolon_ui/settings.dart';
import 'package:symbolon_ui/vault_types.dart';

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
    t.view.physicalSize = const Size(420, 900) * 3;
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

  // Locks the app at the end, which stops the session's timer.
  Future<void> lockUp(WidgetTester t) async {
    final l = find.byKey(const Key('lock'));
    if (l.evaluate().isNotEmpty) await t.tap(l.first);
    await t.pump();
    await settle(t);
  }

  Future<void> openVault(WidgetTester t) async {
    await t.tap(find.text('Vault').last);
    await t.pump(const Duration(milliseconds: 300));
    await t.pump(const Duration(milliseconds: 300));
    await pin(t, '2468');
  }

  test('a list line with the sixth column is a protected item', () {
    final p = VaultItem.parse('secret 62616e6b - - - protected')!;
    expect(p.name, 'bank');
    expect(p.protected, isTrue);
    expect(VaultItem.parse('secret 62616e6b -')!.protected, isFalse);
    expect(VaultItem.parse('secret 62616e6b - - - other'), isNull);
  });

  test('device openings parse: the limit, each device, the unusual flag', () {
    const out = 'limit 60\ndevice 0011 70686f6e65 hour 2 day 5 week 20 usual\ndevice 0022 6c6170746f70 hour 60 day 140 week 150 unusual\n';
    final r = CliResult(0, out, '');
    final (limit, ds) = Openings.parse(r);
    expect(limit, 60);
    expect(ds.map((d) => d.label), ['phone', 'laptop']);
    expect(ds[1].unusual, isTrue);
    expect(ds[1].day, 140);
    expect(ds[0].unusual, isFalse);
  });

  testWidgets('the vault marks a protected item; its page protects and unprotects after saying what changes', (t) async {
    await start(t);
    await openVault(t);
    expect(find.byKey(const Key('protected-tag-bank')), findsOneWidget);
    expect(find.byKey(const Key('protected-tag-mail')), findsNothing);

    await t.tap(find.byKey(const Key('item-bank')));
    await settle(t);
    expect(find.byKey(const Key('item-protected')), findsOneWidget);
    await t.tap(find.byKey(const Key('item-protect')));
    await t.pumpAndSettle();
    expect(find.textContaining('open with this device alone again'), findsOneWidget);
    await t.tap(find.byKey(const Key('confirm-protect')));
    await t.pump();
    await settle(t);
    expect(agent.argsLog.readAsStringSync(), contains('device vault unprotect ${settings.deviceDir} bank'));

    await t.tap(find.byKey(const Key('item-mail')));
    await settle(t);
    expect(find.byKey(const Key('item-protected')), findsNothing);
    await t.tap(find.byKey(const Key('item-protect')));
    await t.pumpAndSettle();
    expect(find.textContaining('cannot open it on its own'), findsOneWidget);
    await t.tap(find.byKey(const Key('confirm-protect')));
    await t.pump();
    await settle(t);
    expect(agent.argsLog.readAsStringSync(), contains('device vault protect ${settings.deviceDir} mail'));
    await lockUp(t);
  });

  testWidgets('a protected item moved into a shared folder: asked first, moved with --unprotect', (t) async {
    await start(t);
    await openVault(t);
    await t.tap(find.byKey(const Key('item-bank')));
    await settle(t);
    await t.tap(find.byKey(const Key('item-move')));
    await settle(t);
    await t.tap(find.byKey(const Key('move-Family')));
    await t.pumpAndSettle();
    expect(find.textContaining('do not hold protected items'), findsOneWidget);
    await t.tap(find.byKey(const Key('confirm-unprotect-move')));
    await t.pump();
    await settle(t);
    expect(agent.argsLog.readAsStringSync(), contains('device vault move ${settings.deviceDir} bank 0123456789abcdef0123456789abcdef --unprotect'));
    await lockUp(t);
  });

  testWidgets('Devices: protected items turned on, then each device\'s openings', (t) async {
    File('${agent.dir.path}/protection-off').writeAsStringSync('');
    File('${agent.dir.path}/unusual').writeAsStringSync('');
    await start(t);
    await t.tap(find.text('More').last);
    await t.pumpAndSettle();
    await t.tap(find.text('Devices'));
    await settle(t);
    await t.ensureVisible(find.byKey(const Key('protection-enable')));
    await t.tap(find.byKey(const Key('protection-enable')));
    await t.pump();
    await pin(t, '2468');
    expect(agent.argsLog.readAsStringSync(), contains('device protection enable'));
    await t.ensureVisible(find.byKey(const Key('openings-check')));
    await t.tap(find.byKey(const Key('openings-check')));
    await t.pump();
    await settle(t);
    expect(find.byKey(const Key('openings-phone')), findsOneWidget);
    expect(find.textContaining('140 today, 150 this week: unusually many'), findsOneWidget);
    await t.pageBack();
    await t.pumpAndSettle();
    await lockUp(t);
  });

  testWidgets('home warns of an unusual day of protected openings while unlocked', (t) async {
    File('${agent.dir.path}/unusual').writeAsStringSync('');
    await start(t);
    expect(find.byKey(const Key('unusual-openings')), findsNothing);   // locked: not asked
    await openVault(t);
    await t.tap(find.text('Home').last);
    await t.pump();
    await settle(t);
    await t.drag(find.byType(RefreshIndicator).first, const Offset(0, 400));
    await t.pump();
    await settle(t);
    expect(find.byKey(const Key('unusual-openings')), findsOneWidget);
    expect(find.textContaining('laptop opened 140 protected items today'), findsOneWidget);
    await lockUp(t);
  });
}
