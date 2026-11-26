// Items a newer Symbolon saved (SPEC 18.3): the agent lists them with the
// flag "newer"; the app shows them, locked, and says calmly that this app
// needs an update to open them. It never opens, changes or fills them, and
// never calls them damaged.

import 'dart:io';

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/cli.dart';
import 'package:symbolon_ui/main.dart';
import 'package:symbolon_ui/settings.dart';
import 'package:symbolon_ui/vault_types.dart';
import 'package:symbolon_ui/widgets.dart' show friendlyError;

import 'fake_agent.dart';

void main() {
  late FakeAgent agent;
  late Settings settings;

  setUp(() async {
    agent = await FakeAgent.create();
    File('${agent.dir.path}/newer').writeAsStringSync('');
    settings = Settings(File('${agent.dir.path}/settings.json'), binary: agent.path, deviceDir: '${agent.dir.path}/dev', tutorialSeen: true);
  });
  tearDown(() => agent.dispose());

  Future<void> settle(WidgetTester t) async {
    for (var i = 0; i < 20; i++) {
      await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
      await t.pump(const Duration(milliseconds: 50));
    }
  }

  test('list lines: the newer flag, with or without protected, and a name that did not open', () {
    final a = VaultItem.parse('login 6e6f7465 - - - newer')!;
    expect(a.newer, isTrue);
    expect(a.protected, isFalse);
    expect(a.name, 'note');
    final b = VaultItem.parse('login - - - - newer')!;
    expect(b.newer, isTrue);
    expect(b.name, '');
    expect(b.title, 'Saved by a newer Symbolon');
    final c = VaultItem.parse('secret 62616e6b - - - protected,newer')!;
    expect(c.protected && c.newer, isTrue);
    expect(VaultItem.parse('secret 62616e6b - - - protected')!.newer, isFalse);
    // A nameless line is only an item a newer agent saved.
    expect(VaultItem.parse('login - - - - protected'), isNull);
    expect(VaultItem.parse('secret 62616e6b - - - newer,other'), isNull);
  });

  test("the agent's message for such an item is shown as it is, never as an error about damage", () {
    final r = CliResult(1, '', 'device: This item was saved by a newer Symbolon; update to open it.\n');
    expect(friendlyError(r), newerItemText);
    expect(friendlyError(r).toLowerCase(), isNot(contains('tamper')));
  });

  testWidgets('the vault shows such items, locked; tapping one says to update and opens nothing', (t) async {
    t.view.devicePixelRatio = 3;
    t.view.physicalSize = const Size(420, 900) * 3;
    addTearDown(t.view.reset);
    await t.pumpWidget(SymbolonApp(settings: settings));
    await settle(t);
    await t.tap(find.text('Vault').last);
    await t.pump(const Duration(milliseconds: 300));
    await t.pump(const Duration(milliseconds: 300));
    await t.enterText(find.byKey(const Key('secret-field')), '2468');
    await t.tap(find.byKey(const Key('secret-ok')));
    await t.pump();
    await settle(t);

    expect(find.byKey(const Key('item-note')), findsOneWidget);
    expect(find.byKey(const Key('newer-tag-note')), findsOneWidget);
    expect(find.byKey(const Key('newer-tag-mail')), findsNothing);
    expect(find.text('Saved by a newer Symbolon'), findsOneWidget);
    expect(find.byKey(const Key('quick-copy-note')), findsNothing);

    await t.tap(find.byKey(const Key('item-note')));
    await t.pumpAndSettle();
    expect(find.byKey(const Key('newer-text')), findsOneWidget);
    expect(find.text(newerItemText), findsOneWidget);
    await t.tap(find.byKey(const Key('newer-ok')));
    await t.pumpAndSettle();
    final log = agent.argsLog.readAsStringSync();
    expect(log, isNot(contains('vault show ${settings.deviceDir} note')));
    expect(log, isNot(contains('vault set ${settings.deviceDir} note')));

    final l = find.byKey(const Key('lock'));
    if (l.evaluate().isNotEmpty) await t.tap(l.first);
    await t.pump();
    await settle(t);
  });
}
