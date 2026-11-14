// The phone flow on a device or emulator, against a demo stack
// (tools/demo.sh --lan): set up through the wizard (one PIN entry), then
// register a passkey and make a test signature with the cosigner, without
// being asked for the PIN again (the unlocked session), and store and
// show a card in the vault. The real agent runs, bundled in the app.
//
//   flutter test integration_test/phone_demo_test.dart -d <device> \
//     --dart-define=DEMO_URL=http://<host>:47000

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:symbolon_ui/links.dart';
import 'package:symbolon_ui/main.dart';
import 'package:symbolon_ui/recovery_sheet.dart';

const demoUrl = String.fromEnvironment('DEMO_URL');

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  // Real time passes on a device: wait for [f] to appear, frame by frame.
  Future<void> waitFor(WidgetTester t, Finder f, {Duration limit = const Duration(minutes: 2)}) async {
    final end = DateTime.now().add(limit);
    while (DateTime.now().isBefore(end)) {
      await t.pump(const Duration(milliseconds: 500));
      if (f.evaluate().isNotEmpty) return;
    }
    final shown = find.byType(Text).hitTestable().evaluate().map((e) => (e.widget as Text).data).whereType<String>().take(12).join(' | ');
    throw TestFailure('timed out waiting for $f${shown.isEmpty ? '' : '; on screen: $shown'}');
  }

  // Taps a button after closing the keyboard, clear of snack bars, in view.
  // The recovery sheet's check: the two groups it asks for, read off the
  // sheet as a person would from their paper.
  Future<void> answerSheetCheck(WidgetTester t) async {
    final sheet = (t.widget(find.byType(SheetCheck)) as SheetCheck).sheet;
    for (final k in ['check-1', 'check-2']) {
      final label = (t.widget(find.byKey(Key(k))) as TextField).decoration!.labelText!;
      final m = RegExp(r'^Group (\d+) of \d+ of the (identity log|recovery kit)$').firstMatch(label)!;
      final groups = groupsOf(m.group(2) == 'identity log' ? sheet.log : sheet.kit);
      await t.enterText(find.byKey(Key(k)), groups[int.parse(m.group(1)!) - 1]);
      await t.pump();
    }
  }

  Future<void> press(WidgetTester t, Key k) async {
    FocusManager.instance.primaryFocus?.unfocus();
    await t.pump(const Duration(milliseconds: 600));
    final f = find.byKey(k);
    final scrollable = find.ancestor(of: f, matching: find.byType(Scrollable));
    if (scrollable.evaluate().isNotEmpty) await Scrollable.ensureVisible(t.element(f), alignment: 0.4);
    ScaffoldMessenger.of(t.element(f)).clearSnackBars();
    for (var i = 0; i < 20 && find.byType(SnackBar).evaluate().isNotEmpty; i++) {
      await t.pump(const Duration(milliseconds: 250));
    }
    await t.pump(const Duration(milliseconds: 400));
    await t.tap(f);
    await t.pump();
  }

  testWidgets('set up through the wizard, then a passkey and a signature in one session', (t) async {
    expect(demoUrl, isNotEmpty, reason: 'pass --dart-define=DEMO_URL=http://<host>:47000');
    final settings = await loadSettings();
    await t.pumpWidget(SymbolonApp(settings: settings));
    // A fresh install (the test uninstalls first) starts with the tutorial.
    await waitFor(t, find.byKey(const Key('tutorial-skip')));
    // The tap may land while the page is still sliding in: until it closes.
    for (var i = 0; i < 20 && find.byKey(const Key('tutorial-skip')).evaluate().isNotEmpty; i++) {
      await t.pump(const Duration(milliseconds: 500));
      if (find.byKey(const Key('tutorial-skip')).hitTestable().evaluate().isNotEmpty) await t.tap(find.byKey(const Key('tutorial-skip')));
      await t.pump(const Duration(milliseconds: 500));
    }
    expect(find.byKey(const Key('tutorial-skip')), findsNothing, reason: 'the tutorial does not close');
    await waitFor(t, find.byKey(const Key('start-setup')));
    await press(t, const Key('start-setup'));
    await waitFor(t, find.byKey(const Key('demo-url')));

    await t.enterText(find.byKey(const Key('demo-url')), demoUrl);
    await press(t, const Key('join-demo'));
    await waitFor(t, find.byKey(const Key('pin')));
    await t.enterText(find.byKey(const Key('pin')), '246813');
    await t.enterText(find.byKey(const Key('pin2')), '246813');
    await press(t, const Key('create'));
    await waitFor(t, find.byKey(const Key('setup-done')), limit: const Duration(minutes: 15));

    await press(t, const Key('kept-kit'));
    await answerSheetCheck(t);
    await press(t, const Key('setup-finish'));
    await waitFor(t, find.text('Your identity is verified'), limit: const Duration(minutes: 2));
    // A phone with the Android Keystore (Android 9+) uses it by default.
    if (settings.keystoreAvailable) {
      await t.drag(find.byType(Scrollable).first, const Offset(0, -600));
      await t.pump(const Duration(seconds: 1));
      expect(find.text('Protected by the Android Keystore and your PIN'), findsOneWidget);
    }

    await t.tap(find.text('Passkeys').last);
    await t.pump(const Duration(seconds: 1));
    await press(t, const Key('new-passkey'));
    await waitFor(t, find.byKey(const Key('rp')));
    await t.enterText(find.byKey(const Key('rp')), 'phone.example.com');
    await press(t, const Key('register'));
    // Unlocked since setup: no PIN prompt.
    await waitFor(t, find.byKey(const Key('passkey-phone.example.com')), limit: const Duration(minutes: 3));
    expect(find.byKey(const Key('secret-field')), findsNothing);

    await press(t, const Key('passkey-phone.example.com'));
    await waitFor(t, find.byKey(const Key('test-sign')));
    await press(t, const Key('test-sign'));
    await waitFor(t, find.byKey(const Key('signed')), limit: const Duration(minutes: 5));
    expect(find.byKey(const Key('secret-field')), findsNothing);
    await t.tap(find.text('Close'));
    await t.pump(const Duration(seconds: 1));

    // The vault, still in the session: a card, checked, stored and shown.
    await t.tap(find.text('Vault').last);
    await waitFor(t, find.byKey(const Key('vault-add')), limit: const Duration(minutes: 3));
    await press(t, const Key('vault-add'));
    await waitFor(t, find.byKey(const Key('add-card')));
    await press(t, const Key('add-card'));
    await waitFor(t, find.byKey(const Key('item-name')));
    await t.enterText(find.byKey(const Key('item-name')), 'phone card');
    await t.enterText(find.byKey(const Key('edit-number')), '4111 1111 1111 1111');
    await t.enterText(find.byKey(const Key('edit-expiry')), '08/29');
    await press(t, const Key('item-save'));
    await waitFor(t, find.byKey(const Key('item-phone card')), limit: const Duration(minutes: 3));
    await press(t, const Key('item-phone card'));
    await waitFor(t, find.text('4111111111111111'), limit: const Duration(minutes: 3));
    expect(find.byKey(const Key('secret-field')), findsNothing);
  }, timeout: const Timeout(Duration(minutes: 30)));
}
