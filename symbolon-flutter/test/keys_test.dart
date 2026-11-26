import 'dart:io';

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/app.dart';
import 'package:symbolon_ui/pages/keys_page.dart';
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

  testWidgets('security keys: none, add one (PIN, the agent asked), then a backup, then remove one', (t) async {
    t.view.devicePixelRatio = 2;
    t.view.physicalSize = const Size(460, 1000) * 2;
    addTearDown(t.view.reset);
    final app = App(settings);
    await t.pumpWidget(MaterialApp(home: SecurityKeysPage(app: app)));
    await settle(t);
    expect(find.byKey(const Key('keys-none')), findsOneWidget);
    expect(find.text('Add a security key'), findsOneWidget);
    Future<void> add(String n) async {
      await t.tap(find.byKey(const Key('key-add')));
      await t.pumpAndSettle();
      await t.enterText(find.byKey(const Key('key-name')), n);
      await t.tap(find.byKey(const Key('key-name-ok')));
      await t.pumpAndSettle();
      await t.enterText(find.byKey(const Key('secret-field')), '2468');
      await t.tap(find.byKey(const Key('secret-ok')));
      await t.pump();
      await settle(t);
    }
    await add('yubi');
    expect(find.byKey(const Key('key-yubi')), findsOneWidget);
    expect(find.text('Add a backup key'), findsOneWidget);
    await add('spare');
    expect(find.byKey(const Key('key-spare')), findsOneWidget);
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device key add ${agent.dir.path}/dev yubi'));
    expect(args, contains('device key add ${agent.dir.path}/dev spare'));
    await t.tap(find.byKey(const Key('key-remove-yubi')));
    await t.pumpAndSettle();
    expect(find.text('Another enrolled key still opens this device.'), findsOneWidget);
    await t.tap(find.byKey(const Key('key-remove-ok')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('secret-field')), '2468');
    await t.tap(find.byKey(const Key('secret-ok')));
    await t.pump();
    await settle(t);
    expect(find.byKey(const Key('key-yubi')), findsNothing);
    expect(find.byKey(const Key('key-spare')), findsOneWidget);
    app.session.lock();
  });

  testWidgets('under the duress PIN an added key shows in the list, which is asked for with the PIN', (t) async {
    t.view.devicePixelRatio = 2;
    t.view.physicalSize = const Size(460, 1000) * 2;
    addTearDown(t.view.reset);
    final app = App(settings);
    await t.pumpWidget(MaterialApp(home: SecurityKeysPage(app: app)));
    await settle(t);
    await t.tap(find.byKey(const Key('key-add')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('key-name')), 'yubi');
    await t.tap(find.byKey(const Key('key-name-ok')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('secret-field')), '1357');
    await t.tap(find.byKey(const Key('secret-ok')));
    await t.pump();
    await settle(t);
    // The agent acted the add; the list, asked with the same PIN, shows it.
    expect(find.byKey(const Key('key-yubi')), findsOneWidget);
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device key list ${agent.dir.path}/dev --pin'));
    expect(File('${agent.dir.path}/keys').existsSync(), isFalse);
    app.session.lock();
  });

  testWidgets('fills can be set to need a security key (SPEC 22.7), with the PIN', (t) async {
    t.view.devicePixelRatio = 2;
    t.view.physicalSize = const Size(460, 1000) * 2;
    addTearDown(t.view.reset);
    final app = App(settings);
    await t.pumpWidget(MaterialApp(home: SecurityKeysPage(app: app)));
    await settle(t);
    expect((t.widget(find.byKey(const Key('fills-need-key'))) as SwitchListTile).value, isFalse);
    await t.tap(find.byKey(const Key('fills-need-key')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('secret-field')), '2468');
    await t.tap(find.byKey(const Key('secret-ok')));
    await t.pump();
    await settle(t);
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device key fills ${agent.dir.path}/dev keys'));
    expect((t.widget(find.byKey(const Key('fills-need-key'))) as SwitchListTile).value, isTrue);
    expect(find.text('No key is enrolled, so this device fills nothing until one is.'), findsOneWidget);
    app.session.lock();
  });
}
