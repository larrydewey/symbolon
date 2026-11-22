// Passkeys imported from another manager (SPEC 5.2, 22.3): read from the
// agent's list, kept in the settings file, and replaced, then retired, on
// the Passkeys page.

import 'dart:io';

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/main.dart';
import 'package:symbolon_ui/settings.dart';

import 'fake_agent.dart';

void main() {
  test('the agent\'s list of imported passkeys is read, and kept across a save', () async {
    final cs = Credential.syncedFrom([
      'passkey dddd 6578616d706c652e636f6d 0707 616c696365 - 04ee -',
      'passkey eeee 6769746875622e636f6d - - - 04ff ${'c' * 64}',
      'vault version 3, 2 items',
    ]);
    expect(cs, hasLength(2));
    expect(cs[0].rp, 'example.com');
    expect(cs[0].userName, 'alice');
    expect(cs[0].userHandle, '0707');
    expect(cs[0].synced, isTrue);
    expect(cs[0].replacedBy, '');
    expect(cs[1].rp, 'github.com');
    expect(cs[1].replacedBy, 'c' * 64);
    final back = Credential.fromJson(cs[1].toJson());
    expect(back.synced, isTrue);
    expect(back.replacedBy, 'c' * 64);
    expect(const Credential('a', 'b', 'c').toJson().containsKey('synced'), isFalse);
  });

  group('the Passkeys page', () {
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

    Future<void> open(WidgetTester t, List<Credential> cs) async {
      t.view.devicePixelRatio = 3;
      t.view.physicalSize = const Size(420, 900) * 3;
      addTearDown(t.view.reset);
      settings.credentials = cs;
      await t.runAsync(settings.save);
      await t.pumpWidget(SymbolonApp(settings: settings));
      await settle(t);
      await t.tap(find.text('Passkeys').last);
      await settle(t);
    }

    testWidgets('an imported passkey nothing replaced says what to do next, and is not retired by default', (t) async {
      await open(t, [const Credential('example.com', 'dddd', '04ee', userName: 'alice', synced: true)]);
      expect(find.byKey(const Key('imported-passkeys')), findsOneWidget);
      expect(find.text('Next: add a Symbolon passkey at example.com for alice'), findsOneWidget);
      // It is not listed among Symbolon's own passkeys.
      expect(find.byKey(const Key('passkey-example.com')), findsNothing);
      await t.tap(find.byKey(const Key('imported-example.com')));
      await settle(t);
      expect(find.byKey(const Key('imported-retire')), findsNothing);
      expect(find.byKey(const Key('imported-retire-force')), findsOneWidget);
    });

    testWidgets('a replaced one is retired: the agent deletes it and the site is named', (t) async {
      await open(t, [
        Credential('example.com', 'dddd', '04ee', userName: 'alice', synced: true, replacedBy: 'c' * 64),
        Credential('example.com', 'c' * 64, '04bb', userName: 'alice'),
      ]);
      expect(find.text('Replaced: retire it once the new one works'), findsOneWidget);
      expect(find.byKey(const Key('passkey-example.com')), findsOneWidget);
      await t.tap(find.byKey(const Key('imported-example.com')));
      await settle(t);
      await t.tap(find.byKey(const Key('imported-retire')));
      await settle(t);
      await t.enterText(find.byKey(const Key('secret-field')), '2468');
      await t.tap(find.byKey(const Key('secret-ok')));
      await t.pump();
      await settle(t);
      expect(find.byKey(const Key('imported-retired')), findsOneWidget);
      final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
      expect(args, contains('device webauthn retire ${agent.dir.path}/dev dddd'));
      expect(args, isNot(contains('--force')));
      expect(settings.credentials.map((c) => c.id), ['c' * 64]);
      // Lock, so the PIN session's timer ends with the test.
      await t.tap(find.text('Close'));
      await t.pump(const Duration(milliseconds: 300));
      await t.tap(find.byKey(const Key('lock')));
      await settle(t);
    });
  });
}
