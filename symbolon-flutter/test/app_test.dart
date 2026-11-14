import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/links.dart';
import 'package:symbolon_ui/main.dart';
import 'package:symbolon_ui/qr_view.dart';
import 'package:symbolon_ui/settings.dart';
import 'package:symbolon_ui/cli.dart';
import 'package:symbolon_ui/widgets.dart';
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

  // The fake agent is a real process: give its I/O real time outside the
  // test clock, frame by frame (a progress indicator never settles).
  Future<void> settle(WidgetTester t) async {
    for (var i = 0; i < 20; i++) {
      await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
      await t.pump(const Duration(milliseconds: 50));
    }
  }

  // [size] in logical pixels, as a phone (narrow) or a desktop (wide).
  Future<void> start(WidgetTester t, {Size size = const Size(420, 900)}) async {
    t.view.devicePixelRatio = 3;
    t.view.physicalSize = size * 3;
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

  Future<void> registerPasskey(WidgetTester t, String rp) async {
    await t.tap(find.text('Passkeys').last);
    await t.pump(const Duration(milliseconds: 300));
    await t.tap(find.byKey(const Key('new-passkey')));
    await t.pump(const Duration(milliseconds: 500));
    await t.enterText(find.byKey(const Key('rp')), rp);
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('register')));
    await t.pump(const Duration(milliseconds: 500));
  }

  testWidgets('home shows the verified identity and warns of a pending event', (t) async {
    await start(t);
    expect(find.text('Your identity is verified'), findsOneWidget);
    expect(find.text('Epoch 2'), findsOneWidget);
    expect(find.text('1 pending'), findsOneWidget);
    expect(find.text('Protected by the TPM and your PIN'), findsOneWidget);
    expect(find.text('Review in Recovery'), findsOneWidget);
  });

  testWidgets('the same pages work on a wide screen', (t) async {
    await start(t, size: const Size(1200, 900));
    expect(find.byType(NavigationRail), findsOneWidget);
    expect(find.text('Your identity is verified'), findsOneWidget);
  });

  testWidgets('a passkey takes the PIN once; the session keeps it until locked', (t) async {
    await start(t);
    await registerPasskey(t, 'bank.example.org');
    await pin(t, '2468');
    expect(find.byKey(const Key('passkey-bank.example.org')), findsOneWidget);
    expect(settings.credentials.single.id, hasLength(64));
    final saved = (await t.runAsync(() => settings.file.readAsString()))!;
    expect(saved, contains('bank.example.org'));
    expect(saved, isNot(contains('2468')));

    // Unlocked: the vault opens without asking.
    await t.tap(find.text('Vault').last);
    await t.pump(const Duration(milliseconds: 300));
    await settle(t);
    expect(find.byKey(const Key('secret-field')), findsNothing);
    expect(find.byKey(const Key('item-mail')), findsOneWidget);
    expect(find.byKey(const Key('item-bank')), findsOneWidget);

    // Locked: the names go and the PIN is asked again.
    await t.tap(find.byKey(const Key('lock')));
    await t.pump(const Duration(milliseconds: 300));
    expect(find.byKey(const Key('item-mail')), findsNothing);
    await t.tap(find.byKey(const Key('open-vault')));
    await t.pump(const Duration(milliseconds: 300));
    expect(find.byKey(const Key('secret-field')), findsOneWidget);
  });

  testWidgets('on a wide screen the lock button in the rail locks', (t) async {
    await start(t, size: const Size(1200, 900));
    await registerPasskey(t, 'bank.example.org');
    await pin(t, '2468');
    await t.tap(find.byKey(const Key('lock')));
    await t.pump(const Duration(milliseconds: 300));
    expect(find.byKey(const Key('lock')), findsNothing);
    expect(find.byTooltip('Locked'), findsOneWidget);
  });

  testWidgets('a wrong PIN is reported in plain words, nothing is kept, and the session stays locked', (t) async {
    await start(t);
    await registerPasskey(t, 'bank.example.org');
    await pin(t, '0000');
    expect(find.text('Wrong PIN.'), findsOneWidget);
    expect(settings.credentials, isEmpty);
    expect(find.byKey(const Key('lock')), findsNothing);
  });

  testWidgets('leaving the app locks the session', (t) async {
    await start(t);
    await registerPasskey(t, 'bank.example.org');
    await pin(t, '2468');
    expect(find.byKey(const Key('lock')), findsOneWidget);
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    // Back in the app (no frames are drawn while it is paused): locked.
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await t.pump();
    expect(find.byKey(const Key('lock')), findsNothing);
  });

  testWidgets('with "ask every time" the PIN is not kept', (t) async {
    settings.keepUnlockedMinutes = 0;
    await start(t);
    await registerPasskey(t, 'bank.example.org');
    await pin(t, '2468');
    expect(settings.credentials, hasLength(1));
    expect(find.byKey(const Key('lock')), findsNothing);
  });

  testWidgets('the first start shows the tutorial, which can be skipped and is not shown again', (t) async {
    settings.tutorialSeen = false;
    await start(t);
    expect(find.text('Welcome to Symbolon'), findsOneWidget);
    await t.tap(find.byKey(const Key('tutorial-next')));
    await t.pumpAndSettle();
    expect(find.text('Your key is split'), findsOneWidget);
    await t.tap(find.byKey(const Key('tutorial-skip')));
    await t.pumpAndSettle();
    await settle(t);
    expect(find.text('Your identity is verified'), findsOneWidget);
    expect(settings.tutorialSeen, isTrue);
  });

  testWidgets('vault items show their kind and can be searched and filtered', (t) async {
    await start(t);
    await t.tap(find.text('Vault').last);
    await t.pump(const Duration(milliseconds: 300));   // the tab asks for the PIN by itself,
    await t.pump(const Duration(milliseconds: 300));   // a frame later
    await pin(t, '2468');
    expect(find.descendant(of: find.byKey(const Key('item-mail')), matching: find.text('Login')), findsOneWidget);
    expect(find.descendant(of: find.byKey(const Key('item-mail')), matching: find.text('mail.example.com')), findsOneWidget);
    expect(find.descendant(of: find.byKey(const Key('item-bank')), matching: find.text('Secret')), findsOneWidget);
    expect(find.descendant(of: find.byKey(const Key('item-visa')), matching: find.text('•••• 1111')), findsOneWidget);

    await t.ensureVisible(find.byKey(const Key('filter-Secrets')));
    await t.tap(find.byKey(const Key('filter-Secrets')));
    await t.pump();
    expect(find.byKey(const Key('item-mail')), findsNothing);
    expect(find.byKey(const Key('item-bank')), findsOneWidget);

    await t.ensureVisible(find.byKey(const Key('filter-All')));
    await t.tap(find.byKey(const Key('filter-All')));
    await t.pump();
    await t.enterText(find.byKey(const Key('search')), 'MA');
    await t.pump();
    expect(find.byKey(const Key('item-mail')), findsOneWidget);
    expect(find.byKey(const Key('item-bank')), findsNothing);
    await t.tap(find.byKey(const Key('lock')));
    await t.pump();
  });

  testWidgets('vault folders: items show theirs, and the picker shows one folder and those inside it', (t) async {
    await start(t);
    await t.tap(find.text('Vault').last);
    await t.pump(const Duration(milliseconds: 300));   // the tab asks for the PIN by itself,
    await t.pump(const Duration(milliseconds: 300));   // a frame later
    await pin(t, '2468');
    expect(find.descendant(of: find.byKey(const Key('item-mail')), matching: find.text('Work › Email')), findsOneWidget);
    Future<void> choose(String key) async {
      await t.tap(find.byKey(const Key('folder-picker')));
      await t.pumpAndSettle();
      await t.tap(find.byKey(Key(key)).last);
      await t.pumpAndSettle();
    }

    await choose('folder-Work');
    expect(find.byKey(const Key('item-mail')), findsOneWidget);
    expect(find.byKey(const Key('item-visa')), findsNothing);
    expect(find.byKey(const Key('item-bank')), findsNothing);
    await choose('folder-');
    expect(find.byKey(const Key('item-bank')), findsOneWidget);
    expect(find.byKey(const Key('item-mail')), findsNothing);
    await choose('folder-Finance');
    expect(find.byKey(const Key('item-visa')), findsOneWidget);
    expect(find.byKey(const Key('item-bank')), findsNothing);
    await choose('folder-*');
    expect(find.byKey(const Key('item-mail')), findsOneWidget);
    await t.tap(find.byKey(const Key('lock')));
    await t.pump();
  });

  testWidgets('sharing: folders, members with fingerprints, adding a person after comparing', (t) async {
    await start(t);
    await t.tap(find.text('More').last);
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('open-sharing')));
    await t.pump(const Duration(milliseconds: 300));
    await settle(t);
    await pin(t, '2468');
    expect(find.text('12345 67890 11111 22222 33333 44444'), findsOneWidget);
    expect(find.text('Alice'), findsOneWidget);
    expect(find.byKey(const Key('folder-Family')), findsOneWidget);
    expect(find.text('Waiting for this device\'s key'), findsOneWidget);
    await t.tap(find.byKey(const Key('folder-Family')));
    await t.pump(const Duration(milliseconds: 300));
    await settle(t);
    expect(find.byKey(const Key('item-mail')), findsOneWidget);
    expect(agent.argsLog.readAsStringSync(), contains('vault list ${settings.deviceDir} --long --share 0123456789abcdef0123456789abcdef'));
    await t.tap(find.byKey(const Key('share-people')));
    await t.pump(const Duration(milliseconds: 300));
    await settle(t);
    expect(find.byKey(const Key('member-Bob')), findsOneWidget);
    expect(find.textContaining('55555 66666 77777 88888 99999 00000'), findsOneWidget);
    await t.tap(find.byKey(const Key('share-add')));
    await settle(t);
    expect(find.byKey(const Key('candidate-Bob')), findsNothing);      // already in it
    await t.tap(find.byKey(const Key('candidate-Carol')));
    await t.pumpAndSettle();
    expect(find.text('13579 24680 11223 34455 66778 89900'), findsOneWidget);
    await t.tap(find.byKey(const Key('candidate-ok')));
    await t.pump(const Duration(milliseconds: 300));
    await settle(t);
    expect(agent.argsLog.readAsStringSync(), contains('share add ${settings.deviceDir} 0123456789abcdef0123456789abcdef ${'c' * 64} Carol'));
    await t.ensureVisible(find.byKey(const Key('share-duress')));
    await t.tap(find.byKey(const Key('share-duress')));
    await t.pump(const Duration(milliseconds: 300));
    await settle(t);
    expect(agent.argsLog.readAsStringSync(), contains('share duress ${settings.deviceDir} 0123456789abcdef0123456789abcdef on'));
    expect(find.byKey(const Key('share-leave')), findsNothing);       // the owner deletes, not leaves
    for (var i = 0; i < 3; i++) {
      await t.pageBack();
      await settle(t);
    }
    await t.tap(find.byKey(const Key('lock')));
    await t.pump();
  });

  testWidgets('an item moves from the vault to a shared folder', (t) async {
    await start(t);
    await t.tap(find.text('Vault').last);
    await t.pump(const Duration(milliseconds: 300));   // the tab asks for the PIN by itself,
    await t.pump(const Duration(milliseconds: 300));   // a frame later
    await pin(t, '2468');
    await t.tap(find.byKey(const Key('item-mail')));
    await t.pump(const Duration(milliseconds: 300));
    await settle(t);
    expect(find.text('Change password at the site…'), findsOneWidget);
    await t.tap(find.byKey(const Key('item-move')));
    await t.pump(const Duration(milliseconds: 300));
    await settle(t);
    expect(find.byKey(const Key('move-own')), findsNothing);          // it is in the vault already
    await t.tap(find.byKey(const Key('move-Family')));
    await t.pump(const Duration(milliseconds: 300));
    await settle(t);
    expect(agent.argsLog.readAsStringSync(), contains('vault move ${settings.deviceDir} mail 0123456789abcdef0123456789abcdef'));
    expect(find.byKey(const Key('item-move')), findsNothing);         // back on the vault page
    await t.tap(find.byKey(const Key('lock')));
    await t.pump();
  });

  testWidgets('passkeys can be searched', (t) async {
    await start(t);
    await registerPasskey(t, 'bank.example.org');
    await pin(t, '2468');
    await t.runAsync(() => settings.addCredential(const Credential('mail.example.com', 'cc', '04dd')));
    await t.pump();
    await t.enterText(find.byKey(const Key('search')), 'mail');
    await t.pump();
    expect(find.byKey(const Key('passkey-mail.example.com')), findsOneWidget);
    expect(find.byKey(const Key('passkey-bank.example.org')), findsNothing);
    await t.tap(find.byKey(const Key('lock')));
    await t.pump();
  });

  testWidgets('the progress sheet counts the seconds', (t) async {
    final done = Completer<CliResult>();
    await t.pumpWidget(MaterialApp(
      home: Scaffold(body: Builder(builder: (c) => TextButton(onPressed: () => runTask(c, 'Working', () => done.future), child: const Text('go')))),
    ));
    await t.tap(find.text('go'));
    await t.pump();
    expect(find.textContaining('0 s'), findsOneWidget);
    await t.pump(const Duration(seconds: 1));
    await t.pump(const Duration(seconds: 1));
    expect(find.textContaining('2 s'), findsOneWidget);
    done.complete(const CliResult(0, '', ''));
    await t.pumpAndSettle();
  });

  testWidgets('text fields keep exactly what is typed', (t) async {
    final c = TextEditingController();
    await t.pumpWidget(MaterialApp(home: Scaffold(body: Field(c, 'Name'))));
    final f = t.widget<TextField>(find.byType(TextField));
    expect(f.autocorrect, isFalse);
    expect(f.enableSuggestions, isFalse);
    expect(f.keyboardType, TextInputType.visiblePassword);
    expect(f.smartDashesType, SmartDashesType.disabled);
    expect(f.textCapitalization, TextCapitalization.none);
  });

  Future<void> openVault(WidgetTester t) async {
    await t.tap(find.text('Vault').last);
    await t.pump(const Duration(milliseconds: 300));   // the tab asks for the PIN by itself,
    await t.pump(const Duration(milliseconds: 300));   // a frame later
    await pin(t, '2468');
  }

  Future<void> lock(WidgetTester t) async {
    await t.tap(find.byKey(const Key('lock')).first);
    await t.pumpAndSettle();
  }

  testWidgets('a login\'s password and a card\'s number copy from the list, without opening the item', (t) async {
    settings.siteIcons = false;
    String? copied;
    t.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, (c) async {
      if (c.method == 'Clipboard.setData') copied = (c.arguments as Map)['text'] as String?;
      return null;
    });
    addTearDown(() => t.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, null));
    await start(t);
    await openVault(t);
    await t.tap(find.byKey(const Key('quick-copy-mail')));
    await settle(t);
    expect(copied, 'hunter2');
    expect(find.textContaining('Password copied'), findsOneWidget);
    expect(find.text('alice'), findsNothing);   // the item page, with the username, did not open
    await t.tap(find.byKey(const Key('quick-copy-visa')));
    await settle(t);
    expect(copied, '4111111111111111');
    expect(find.byKey(const Key('quick-copy-bank')), findsNothing);
    await lock(t);
  });

  testWidgets('choosing the Vault tab asks to unlock at once; cancelling leaves the Unlock button', (t) async {
    await start(t);
    await t.tap(find.text('Vault').last);
    await t.pump(const Duration(milliseconds: 300));
    await t.pump(const Duration(milliseconds: 300));
    expect(find.byKey(const Key('secret-field')), findsOneWidget);
    await t.tap(find.text('Cancel'));
    await t.pumpAndSettle();
    expect(find.byKey(const Key('open-vault')), findsOneWidget);
    // Back to the tab later: asked again.
    await t.tap(find.text('Home').last);
    await t.pump(const Duration(milliseconds: 300));
    await t.tap(find.text('Vault').last);
    await t.pump(const Duration(milliseconds: 300));
    await t.pump(const Duration(milliseconds: 300));
    await pin(t, '2468');
    expect(find.byKey(const Key('item-mail')), findsOneWidget);
    await lock(t);
  });

  testWidgets('a new login can take a generated password, shown so it can be checked', (t) async {
    await start(t);
    await openVault(t);
    await t.tap(find.byKey(const Key('vault-add')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('add-login')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('generate-current')));
    await t.pump();
    final made = (t.widget(find.byKey(const Key('edit-current'))) as TextFormField).controller!.text;
    expect(made, hasLength(20));
    expect(made, matches(RegExp(r'[a-z]')));
    expect(made, matches(RegExp(r'[A-Z]')));
    expect(made, matches(RegExp(r'[2-9]')));
    expect(find.text(made), findsOneWidget);   // revealed
    // Generating again over a password asks first.
    await t.tap(find.byKey(const Key('generate-current')));
    await t.pumpAndSettle();
    expect(find.text('Replace the password?'), findsOneWidget);
    await t.tap(find.text('Cancel'));
    await t.pumpAndSettle();
    expect((t.widget(find.byKey(const Key('edit-current'))) as TextFormField).controller!.text, made);
    await t.pageBack();
    await t.pumpAndSettle();
    await lock(t);
  });

  testWidgets('a pending change opens Recovery, which leads with stopping it', (t) async {
    await start(t);
    await t.tap(find.byKey(const Key('review-recovery')));
    await t.pump(const Duration(milliseconds: 500));
    await settle(t);
    expect(find.text('Recovery'), findsWidgets);
    expect(find.byKey(const Key('recovery-pending')), findsOneWidget);
    expect(find.text('Stop this recovery'), findsOneWidget);
    expect(t.getTopLeft(find.byKey(const Key('recovery-pending'))).dy, lessThan(t.getTopLeft(find.text('Recover on a new device')).dy));
  });

  testWidgets('setup ends with the recovery sheet, checked from paper with the sheet out of sight', (t) async {
    await start(t);
    await t.tap(find.text('More').last);
    await t.pumpAndSettle();
    await t.scrollUntilVisible(find.text('Set up this device'), 200, scrollable: find.byType(Scrollable).hitTestable().first);
    await t.drag(find.byType(Scrollable).hitTestable().first, const Offset(0, -300));
    await t.pumpAndSettle();
    await t.tap(find.text('Set up this device'));
    await t.pumpAndSettle();
    await t.tap(find.text('Other ways to connect'));
    await t.pumpAndSettle();
    await t.ensureVisible(find.text('Enter the details by hand'));
    await t.pumpAndSettle();
    await t.tap(find.text('Enter the details by hand'));
    await t.pumpAndSettle();
    final list = find.ancestor(of: find.text('Hide manual setup'), matching: find.byType(Scrollable)).first;
    for (final (label, value) in [
      ('Relay host', 'relay.example.org'),
      ('Relay port', '47000'),
      ("Cosigner's keys", 'ab' * 40),
      for (var i = 1; i <= 3; i++) ('Witness $i', 'w$i.example.org:4700$i:${'cd' * 32}'),
    ]) {
      final f = find.widgetWithText(TextFormField, label);
      await t.scrollUntilVisible(f, 100, scrollable: list);
      await t.enterText(f, value);
    }
    await t.scrollUntilVisible(find.widgetWithText(FilledButton, 'Next'), 100, scrollable: list);
    await t.ensureVisible(find.widgetWithText(FilledButton, 'Next'));
    await t.pumpAndSettle();
    await t.tap(find.widgetWithText(FilledButton, 'Next'));
    await t.pump();
    await settle(t);
    await t.enterText(find.byKey(const Key('pin')), '246813');
    await t.enterText(find.byKey(const Key('pin2')), '246813');
    await t.ensureVisible(find.byKey(const Key('create')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('create')));
    await t.pump();
    for (var i = 0; i < 3; i++) {
      await settle(t);
    }
    // Both values, in full: the identity log from device status, the kit from init.
    expect(find.byKey(const Key('setup-done')), findsOneWidget);
    const kit = '9f3a1c0e7b2d4f68a1c3e5079b2d4f6810e2c4a6', log = 'fa8f008b293b5457ef989520c8bbcbc959a09c0a8619b1d190f78271bf6b5795';
    expect(find.text('9f3a'), findsOneWidget);
    expect(find.text('fa8f'), findsOneWidget);
    await t.ensureVisible(find.byKey(const Key('kept-kit')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('kept-kit')));
    await t.pumpAndSettle();
    expect(find.byKey(const Key('kit-card')), findsNothing);   // out of sight
    String answer(String k, {bool wrong = false}) {
      final label = (t.widget(find.byKey(Key(k))) as TextField).decoration!.labelText!;
      final m = RegExp(r'^Group (\d+) of \d+ of the (identity log|recovery kit)$').firstMatch(label)!;
      final g = groupsOf(m.group(2) == 'identity log' ? log : kit)[int.parse(m.group(1)!) - 1];
      return wrong ? (g == '0000' ? '1111' : '0000') : g;
    }
    await t.enterText(find.byKey(const Key('check-1')), answer('check-1'));
    await t.enterText(find.byKey(const Key('check-2')), answer('check-2', wrong: true));
    await t.tap(find.byKey(const Key('setup-finish')));
    await t.pump();
    expect(find.text('Does not match: check this group on your paper'), findsOneWidget);
    expect(find.byKey(const Key('setup-finish')), findsOneWidget);   // still here
    await t.enterText(find.byKey(const Key('check-2')), answer('check-2'));
    await t.tap(find.byKey(const Key('setup-finish')));
    await t.pumpAndSettle();
    expect(find.byKey(const Key('check-1')), findsNothing);   // setup closed
  });

  testWidgets('recovery takes the identity log and the kit from a sheet\'s link, spaces and all', (t) async {
    await start(t);
    await t.tap(find.byKey(const Key('review-recovery')));
    await t.pump(const Duration(milliseconds: 500));
    await settle(t);
    await t.enterText(find.byKey(const Key('recover-log')), 'fa8f 008b 293b 5457 ef98 9520 c8bb cbc9 59a0 9c0a 8619 b1d1 90f7 8271 bf6b 5795');
    await t.enterText(find.byKey(const Key('recover-kit')), '9F3A 1C0E');
    await t.ensureVisible(find.byKey(const Key('recover-start')));
    await t.tap(find.byKey(const Key('recover-start')));
    await t.pump();
    await settle(t);
    expect(agent.argsLog.readAsStringSync(), contains('9f3a1c0e fa8f008b293b5457ef989520c8bbcbc959a09c0a8619b1d190f78271bf6b5795'));
  });

  testWidgets('a card shows its fields: hidden ones masked, custom fields labelled', (t) async {
    settings.siteIcons = false;
    await start(t);
    await openVault(t);
    await t.tap(find.byKey(const Key('item-visa')));
    await t.pump(const Duration(milliseconds: 500));
    await settle(t);
    // The number is masked in its field as on the card face, until shown.
    expect(find.text('4111111111111111'), findsNothing);
    expect(find.text('•••• 1111'), findsOneWidget);
    await t.tap(find.descendant(of: find.byKey(const Key('field-number')), matching: find.byTooltip('Show')));
    await t.pump();
    expect(find.text('4111111111111111'), findsOneWidget);
    expect(find.text('Card number · Visa'), findsOneWidget);
    expect(find.text('•••• •••• •••• 1111'), findsOneWidget);
    await t.tap(find.byKey(const Key('card-face')));
    await t.pump();
    expect(find.text('4111 1111 1111 1111'), findsOneWidget);
    expect(find.text('123'), findsNothing);
    expect(find.text('Rewards'), findsOneWidget);
    expect(find.text('R-42'), findsOneWidget);
    await t.tap(find.descendant(of: find.byKey(const Key('field-cvv')), matching: find.byTooltip('Show')));
    await t.pump();
    expect(find.text('123'), findsOneWidget);
    await t.pageBack();
    await t.pumpAndSettle();
    await lock(t);
  });

  testWidgets('a new card is checked before it is saved, then stored with its fields', (t) async {
    settings.siteIcons = false;
    await start(t);
    await openVault(t);
    await t.tap(find.byKey(const Key('vault-add')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('add-card')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('item-name')), 'everyday');
    await t.enterText(find.byKey(const Key('edit-number')), '4111 1111 1111 1112');
    await t.enterText(find.byKey(const Key('edit-expiry')), '13/29');
    await t.pump();
    await t.tap(find.byKey(const Key('item-save')));
    await t.pump();
    expect(find.text('This card number is not valid (check the digits)'), findsOneWidget);
    expect(find.text('The month is 01 to 12'), findsOneWidget);
    expect((await t.runAsync(() => agent.argsLog.readAsString()))!, isNot(contains('vault set')));

    await t.enterText(find.byKey(const Key('edit-number')), '4111 1111 1111 1111');
    await t.enterText(find.byKey(const Key('edit-expiry')), '8/2029');
    await t.pump();
    expect((t.widget(find.byKey(const Key('card-face-number'))) as Text).data, '4111 1111 1111 1111');
    expect(find.descendant(of: find.byKey(const Key('card-face')), matching: find.text('08/29')), findsOneWidget);
    await t.scrollUntilVisible(find.byKey(const Key('add-field')), 200, scrollable: find.byType(Scrollable).first);
    await t.tap(find.byKey(const Key('add-field')));
    await t.pump();
    await t.enterText(find.byKey(const Key('custom-label-0')), 'Bank phone');
    await t.enterText(find.byKey(const Key('custom-value-0')), '+1 555 0100');
    await t.tap(find.byKey(const Key('item-save')));
    await t.pump();
    await settle(t);
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device vault set ${agent.dir.path}/dev everyday card'));
    final input = (await t.runAsync(() => agent.stdinLog.readAsString()))!;
    expect(input, contains('number ${hexOf('4111111111111111')}'));
    expect(input, contains('expiry ${hexOf('08/29')}'));
    expect(input, contains('custom_1 ${hexOf(const CustomField('Bank phone', '+1 555 0100').encode())}'));
    expect(find.byKey(const Key('item-everyday')), findsOneWidget);
    await lock(t);
  });

  testWidgets('offline, the vault shows the device copy and refuses changes', (t) async {
    settings.siteIcons = false;
    await t.runAsync(() => File('${agent.dir.path}/offline').writeAsString(''));
    await start(t);
    await openVault(t);
    expect(find.byKey(const Key('offline-banner')), findsOneWidget);
    expect(find.text('Offline'), findsOneWidget);
    expect(find.byKey(const Key('item-mail')), findsOneWidget);
    await t.tap(find.byKey(const Key('vault-add')));
    await t.pump();
    expect(find.textContaining('Changes need a connection'), findsOneWidget);
    await lock(t);
  });

  testWidgets('organization: join with an invite code, see a recovery request, invite someone', (t) async {
    await start(t);
    await t.tap(find.text('More').last);
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('open-org')));
    await t.pump(const Duration(milliseconds: 300));
    await settle(t);
    expect(find.byKey(const Key('org-join')), findsOneWidget);
    // The invite is one link: pasting it fills in the three values.
    await t.enterText(find.byKey(const Key('org-link')), 'symbolon://org?o=0123456789abcdef0123456789abcdef&f=${'a' * 64}&c=fedcba9876543210fedcba9876543210');
    await t.pump();
    expect(find.byKey(const Key('org-invite-read')), findsOneWidget);
    await t.tap(find.byKey(const Key('org-join')));
    await t.pump();
    await settle(t);
    await pin(t, '2468');
    await settle(t);
    expect(agent.argsLog.readAsStringSync(), contains('device org join ${settings.deviceDir} 0123456789abcdef0123456789abcdef ${'a' * 64} fedcba9876543210fedcba9876543210'));
    expect(find.text('Acme'), findsOneWidget);
    expect(find.text('You are an owner'), findsOneWidget);
    expect(find.byKey(const Key('org-request-00112233445566778899aabbccddeeff')), findsOneWidget);
    await t.scrollUntilVisible(find.byKey(const Key('org-member-Bob')), 200, scrollable: find.byType(Scrollable).first);
    expect(find.text('bob@acme.example · member'), findsOneWidget);
    await t.scrollUntilVisible(find.byKey(const Key('org-invite')), -200, scrollable: find.byType(Scrollable).first);
    await t.ensureVisible(find.byKey(const Key('org-invite')));
    await t.tap(find.byKey(const Key('org-invite')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('org-invite-ext')), 'erin@acme.example');
    await t.enterText(find.byKey(const Key('org-invite-name')), 'Erin');
    await t.tap(find.byKey(const Key('org-invite-ok')));
    await t.pump();
    await settle(t);
    expect(find.byKey(const Key('org-invite-code')), findsOneWidget);
    expect(find.text('fedcba9876543210fedcba9876543210'), findsOneWidget);
    // With the org id and founder from this device's enrolment: a link and its QR code.
    expect((t.widget(find.byKey(const Key('org-invite-qr'))) as QrView).data,
        'symbolon://org?o=0123456789abcdef0123456789abcdef&f=${'a' * 64}&c=fedcba9876543210fedcba9876543210');
    expect(agent.argsLog.readAsStringSync(), contains('device org invite ${settings.deviceDir} erin@acme.example Erin'));
    await t.tap(find.text('Done'));
    await t.pumpAndSettle();
    expect(find.text('policy max_offline_days 7'), findsOneWidget);
    await t.ensureVisible(find.byKey(const Key('org-approve-0123456789abcdef0123456789abcdef')));
    await t.tap(find.byKey(const Key('org-approve-0123456789abcdef0123456789abcdef')));
    await t.pump();
    await settle(t);
    expect(agent.argsLog.readAsStringSync(), contains('device org approve ${settings.deviceDir} 0123456789abcdef0123456789abcdef'));
    await t.tap(find.text('Close').last);
    await t.pumpAndSettle();
    await settle(t);
    if (find.byType(BackButton).evaluate().isNotEmpty) {
      await t.tap(find.byType(BackButton).first);
      await t.pumpAndSettle();
    }
    if (find.byKey(const Key('lock')).evaluate().isNotEmpty) await lock(t);
  });
}
