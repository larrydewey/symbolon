// Moving in from Bitwarden by signing in: the Import page offers it first;
// the email and master password go to the agent's standard input, a
// two-step code is asked for when the server wants one, the preview is the
// file import's, and the PIN imports. A wrong password is said plainly.

import 'dart:io';

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/main.dart';
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

  Future<void> openSignIn(WidgetTester t, {String source = 'source-signin-bitwarden'}) async {
    t.view.devicePixelRatio = 3;
    t.view.physicalSize = const Size(420, 1400) * 3;
    addTearDown(t.view.reset);
    await t.pumpWidget(SymbolonApp(settings: settings));
    await settle(t);
    await t.tap(find.text('More').last);
    await settle(t);
    await t.tap(find.text('Import'));
    await settle(t);
    await t.tap(find.byKey(Key(source)));
    await settle(t);
  }

  testWidgets('signs in, answers the two-step code, previews and imports', (t) async {
    await openSignIn(t);
    await t.enterText(find.byKey(const Key('signin-email')), 'alice@example.com');
    await t.enterText(find.byKey(const Key('signin-password')), 'correct horse');
    await t.tap(find.byKey(const Key('signin-go')));
    await settle(t);
    expect(find.text('Two-step login'), findsOneWidget);
    expect(find.text('Email me a code'), findsNothing);
    await t.enterText(find.byKey(const Key('signin-code')), '123 456');
    await t.tap(find.byKey(const Key('signin-code-go')));
    await settle(t);
    expect(find.text('Ready to import 2 items'), findsOneWidget);
    expect(find.text('bank'), findsOneWidget);
    await t.tap(find.byKey(const Key('signin-import-go')));
    await settle(t);
    await t.enterText(find.byKey(const Key('secret-field')), '2468');
    await t.tap(find.byKey(const Key('secret-ok')));
    await settle(t);
    await settle(t);
    expect(find.byKey(const Key('signin-import-done')), findsOneWidget);
    final log = (await t.runAsync(() => agent.signinLog.readAsString()))!.split('\n');
    expect(log.take(5).toList(), ['alice@example.com', 'correct horse', 'code 0 123456', 'import', '2468']);
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device vault signin-bitwarden ${agent.dir.path}/dev bitwarden.com'));
    // The master password never goes on the command line.
    expect(args, isNot(contains('correct horse')));
    // Done closes the import; locking stops the session's timer.
    await t.tap(find.text('Done'));
    await settle(t);
    final l = find.byKey(const Key('lock'));
    if (l.evaluate().isNotEmpty) await t.tap(l.first);
    await settle(t);
  });

  testWidgets('a wrong master password is said plainly', (t) async {
    await openSignIn(t);
    await t.enterText(find.byKey(const Key('signin-email')), 'alice@example.com');
    await t.enterText(find.byKey(const Key('signin-password')), 'wrong');
    await t.tap(find.byKey(const Key('signin-go')));
    await settle(t);
    expect(find.text('the email or master password is wrong'), findsOneWidget);
    expect(find.byKey(const Key('signin-go')), findsOneWidget);
  });

  testWidgets('LastPass: says it is experimental, waits for the push, asks for the code', (t) async {
    await openSignIn(t, source: 'source-signin-lastpass');
    expect(find.text('Sign in to LastPass'), findsOneWidget);
    expect(find.textContaining('Experimental'), findsOneWidget);
    expect(find.byKey(const Key('signin-server')), findsNothing);
    await t.enterText(find.byKey(const Key('signin-email')), 'bob@example.com');
    await t.enterText(find.byKey(const Key('signin-password')), 'secret phrase');
    await t.tap(find.byKey(const Key('signin-go')));
    await settle(t);
    expect(find.text('Enter the code from Google Authenticator.'), findsOneWidget);
    await t.enterText(find.byKey(const Key('signin-code')), '654321');
    await t.tap(find.byKey(const Key('signin-code-go')));
    await settle(t);
    expect(find.text('Ready to import 1 item'), findsOneWidget);
    await t.tap(find.byKey(const Key('signin-import-go')));
    await settle(t);
    await t.enterText(find.byKey(const Key('secret-field')), '2468');
    await t.tap(find.byKey(const Key('secret-ok')));
    await settle(t);
    await settle(t);
    expect(find.byKey(const Key('signin-import-done')), findsOneWidget);
    final log = (await t.runAsync(() => agent.signinLog.readAsString()))!.split('\n');
    expect(log.take(5).toList(), ['bob@example.com', 'secret phrase', 'code google 654321', 'import', '2468']);
    await t.tap(find.text('Done'));
    await settle(t);
    final l = find.byKey(const Key('lock'));
    if (l.evaluate().isNotEmpty) await t.tap(l.first);
    await settle(t);
  });
}
