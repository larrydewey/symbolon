// The phone flow against a Symbolon Home box, with real key generation
// (no fixture primes): paste the box's pairing link, choose a PIN, create
// the identity, then a passkey and a signature with the box's cosigner.
//
//   symbolon home init BOX 10.0.2.2 --bind 127.0.0.1 --ports 47200   (emulator)
//   symbolon home invite BOX tester; symbolon home serve BOX
//   flutter test integration_test/home_test.dart -d <device> --dart-define=HOME_LINK='symbolon://pair?...' 

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:symbolon_ui/main.dart';

const homeLink = String.fromEnvironment('HOME_LINK');

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

  testWidgets('set up with a Symbolon Home box (real key generation), then a passkey and a signature', (t) async {
    expect(homeLink, isNotEmpty, reason: 'pass --dart-define=HOME_LINK=symbolon://pair?...');
    final settings = await loadSettings();
    await t.pumpWidget(SymbolonApp(settings: settings));
    await waitFor(t, find.byKey(const Key('tutorial-skip')));
    for (var i = 0; i < 20 && find.byKey(const Key('tutorial-skip')).evaluate().isNotEmpty; i++) {
      await t.pump(const Duration(milliseconds: 500));
      if (find.byKey(const Key('tutorial-skip')).hitTestable().evaluate().isNotEmpty) await t.tap(find.byKey(const Key('tutorial-skip')));
      await t.pump(const Duration(milliseconds: 500));
    }
    await waitFor(t, find.byKey(const Key('start-setup')));
    await press(t, const Key('start-setup'));
    await waitFor(t, find.byKey(const Key('home-link')));
    await t.enterText(find.byKey(const Key('home-link')), homeLink);
    await press(t, const Key('join-home'));
    await waitFor(t, find.byKey(const Key('pin')));
    await t.enterText(find.byKey(const Key('pin')), '246813');
    await t.enterText(find.byKey(const Key('pin2')), '246813');
    final started = DateTime.now();
    await press(t, const Key('create'));
    await waitFor(t, find.byKey(const Key('setup-done')), limit: const Duration(minutes: 60));
    // ignore: avoid_print
    print('REAL KEY GENERATION ON THE DEVICE: ${DateTime.now().difference(started).inSeconds} s');
    await press(t, const Key('kept-kit'));
    await press(t, const Key('setup-finish'));
    await waitFor(t, find.text('Your identity is verified'), limit: const Duration(minutes: 2));

    await t.tap(find.text('Passkeys').last);
    await t.pump(const Duration(seconds: 1));
    await press(t, const Key('new-passkey'));
    await waitFor(t, find.byKey(const Key('rp')));
    await t.enterText(find.byKey(const Key('rp')), 'home.example.com');
    await press(t, const Key('register'));
    await waitFor(t, find.byKey(const Key('passkey-home.example.com')), limit: const Duration(minutes: 3));
    await press(t, const Key('passkey-home.example.com'));
    await waitFor(t, find.byKey(const Key('test-sign')));
    await press(t, const Key('test-sign'));
    await waitFor(t, find.byKey(const Key('signed')), limit: const Duration(minutes: 5));
  }, timeout: const Timeout(Duration(minutes: 75)));
}
