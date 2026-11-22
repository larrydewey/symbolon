import 'dart:io';

import 'package:material_ui/material_ui.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/applinks.dart';
import 'package:symbolon_ui/autofill_main.dart';
import 'package:symbolon_ui/pages/app_link.dart';
import 'package:symbolon_ui/pages/item_page.dart';
import 'package:symbolon_ui/app.dart';
import 'package:symbolon_ui/settings.dart';
import 'package:symbolon_ui/vault_types.dart';

import 'fake_agent.dart';

// Android autofill's screens (SPEC 22.6), with Android's side played by the
// test: the request it would give, and what the screen hands back.
void main() {
  final cert = 'ab' * 32, other = 'cd' * 32;
  const links = '[{"relation":["delegate_permission/common.get_login_creds"],"target":{"namespace":"android_app","package_name":"com.example.mailer",'
      '"sha256_cert_fingerprints":["AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB"]}}]';

  group('Digital Asset Links', () {
    test('only get_login_creds for the very package and certificate links an app', () {
      expect(allowsLogins(links, 'com.example.mailer', [cert]), isTrue);
      expect(allowsLogins(links, 'com.example.mailer', [other]), isFalse);
      expect(allowsLogins(links, 'com.example.mailer.fake', [cert]), isFalse);
      expect(allowsLogins(links.replaceAll('get_login_creds', 'handle_all_urls'), 'com.example.mailer', [cert]), isFalse);
      expect(allowsLogins('not json', 'com.example.mailer', [cert]), isFalse);
      expect(allowsLogins('{"relation":[]}', 'com.example.mailer', [cert]), isFalse);
    });

    test('answers are kept for a day, then asked again; a failed fetch is no link', () async {
      final d = await Directory.systemTemp.createTemp('applinks');
      addTearDown(() => d.delete(recursive: true));
      var fetched = 0;
      var now = DateTime(2026, 11, 14, 12);
      final l = AppLinks(File('${d.path}/applinks.json'), fetch: (h) async {
        fetched++;
        return h == 'mail.example.com' ? links : null;
      }, now: () => now);
      expect(await l.verified(['mail.example.com', 'down.example'], 'com.example.mailer', [cert]), ['mail.example.com']);
      expect(fetched, 2);
      expect(await l.linked('mail.example.com', 'com.example.mailer', [cert]), isTrue);
      expect(fetched, 2);   // from the cache
      now = now.add(const Duration(hours: 25));
      expect(await l.linked('mail.example.com', 'com.example.mailer', [cert]), isTrue);
      expect(fetched, 3);
    });
  });

  group('the fill screen', () {
    late FakeAgent agent;
    late Settings settings;
    final calls = <MethodCall>[];
    const channel = MethodChannel('symbolon/autofill');

    setUp(() async {
      agent = await FakeAgent.create();
      settings = Settings(File('${agent.dir.path}/settings.json'), binary: agent.path, deviceDir: '${agent.dir.path}/dev', tutorialSeen: true);
      calls.clear();
    });
    tearDown(() => agent.dispose());

    Future<void> settle(WidgetTester t) async {
      for (var i = 0; i < 20; i++) {
        await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
        await t.pump(const Duration(milliseconds: 50));
      }
    }

    Future<void> show(WidgetTester t, AutofillRequest rq, {Future<String?> Function(String)? fetch}) async {
      t.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, (c) async {
        calls.add(c);
        return null;
      });
      addTearDown(() => t.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, null));
      t.view.devicePixelRatio = 2;
      t.view.physicalSize = const Size(420, 1000) * 2;
      addTearDown(t.view.reset);
      final links = AppLinks(File('${agent.dir.path}/applinks.json'), fetch: fetch ?? (_) async => null);
      await t.pumpWidget(AutofillApp(settings: settings, request: rq, channel: channel, links: links));
      await settle(t);
    }

    Future<void> unlock(WidgetTester t) async {
      await t.enterText(find.byKey(const Key('af-pin')), '2468');
      await t.tap(find.byKey(const Key('af-unlock')));
      await t.pump();
      await settle(t);
    }

    Map<String, String> finished() {
      final f = calls.where((c) => c.method == 'finish').single;
      return Map<String, String>.from((f.arguments as Map)['values'] as Map);
    }

    testWidgets('a privileged browser\'s page: its own login, values only for the kinds asked', (t) async {
      await show(t, const AutofillRequest(package: 'com.android.chrome', label: 'Chrome', origin: 'https://mail.example.com', kinds: ['username', 'current-password']));
      expect(find.text('mail.example.com'), findsOneWidget);
      expect(find.text('The page at https://mail.example.com, in Chrome'), findsOneWidget);
      await unlock(t);
      expect(find.byKey(const Key('af-item-mail')), findsOneWidget);
      expect(find.byKey(const Key('af-item-visa')), findsNothing);
      await t.tap(find.byKey(const Key('af-fill')));
      await t.pump();
      await settle(t);
      expect(finished(), {'username': 'alice', 'current-password': 'hunter2'});
      final runs = (await t.runAsync(() => File('${agent.dir.path}/fill.log').readAsLines()))!;
      expect(runs.every((r) => r.endsWith('fill login https://mail.example.com current-password,username')), isTrue);
    });

    testWidgets('an app with a linked login: the app and its publisher shown first; the code too when asked', (t) async {
      await show(t, AutofillRequest(package: 'com.example.mail', label: 'Mail', certs: [cert], installer: 'com.android.vending', apkKeyHash: 'android:apk-key-hash:q6s',
          kinds: const ['username', 'current-password', 'one-time-code']));
      expect(find.text('Mail'), findsOneWidget);
      expect(find.text('Installed from Google Play'), findsOneWidget);
      await unlock(t);
      expect(find.byKey(const Key('af-item-mail')), findsOneWidget);
      await t.tap(find.byKey(const Key('af-fill')));
      await t.pump();
      await settle(t);
      expect(finished(), {'username': 'alice', 'current-password': 'hunter2', 'one-time-code': '287082'});
    });

    testWidgets('a lookalike app (same package, another key) is offered nothing, and nothing can be picked', (t) async {
      await show(t, AutofillRequest(package: 'com.example.mail', label: 'Mail', certs: [other], kinds: const ['username', 'current-password']));
      expect(find.text('Not installed from an app store'), findsOneWidget);
      await unlock(t);
      expect(find.byKey(const Key('af-none')), findsOneWidget);
      expect(find.byKey(const Key('af-item-mail')), findsNothing);
      expect(find.byKey(const Key('af-fill')), findsNothing);
      await t.tap(find.byKey(const Key('af-cancel')));
      await t.pump();
      expect(calls.map((c) => c.method), ['cancel']);
    });

    testWidgets('an app the login\'s site names in its Digital Asset Links', (t) async {
      final fetched = <String>[];
      await show(t, AutofillRequest(package: 'com.example.mailer', label: 'Mailer', certs: [cert], claimed: const ['mail.example.com'], kinds: const ['username', 'current-password']),
          fetch: (h) async {
        fetched.add(h);
        return links;
      });
      await unlock(t);
      expect(fetched, ['mail.example.com']);   // only the site the app claims
      expect(find.text('These sites say this app may use their logins'), findsOneWidget);
      expect(find.byKey(const Key('af-item-mail')), findsOneWidget);
    });

    testWidgets('a card field: the cards, with their kinds only', (t) async {
      await show(t, AutofillRequest(package: 'com.example.shop', label: 'Shop', certs: [other], installer: 'com.android.vending', kinds: const ['cc-number', 'cc-exp-month', 'cc-exp-year']));
      await unlock(t);
      expect(find.byKey(const Key('af-item-visa')), findsOneWidget);
      await t.tap(find.byKey(const Key('af-fill')));
      await t.pump();
      await settle(t);
      expect(finished().keys, containsAll(['cc-number']));
      expect(finished().containsKey('cc-csc'), isFalse);
    });

    testWidgets('saving from an app: a new login for that app, nothing replaced without a tap', (t) async {
      await show(t, AutofillRequest(save: true, package: 'com.example.mail', label: 'Mail', certs: [cert], saveUser: 'bob', savePassword: 's3cret'));
      await unlock(t);
      expect(find.byKey(const Key('af-item-mail')), findsOneWidget);   // offered to update
      expect(find.text('Save a new login'), findsOneWidget);           // but not chosen
      await t.tap(find.byKey(const Key('af-save')));
      await t.pump();
      await settle(t);
      expect(calls.map((c) => c.method), ['done']);
      final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
      expect(args, contains('device vault set ${agent.dir.path}/dev Mail login'));
      final input = (await t.runAsync(() => File('${agent.dir.path}/stdin.log').readAsString()))!;
      expect(input, contains('apps ${hexOf('com.example.mail $cert')}'));
      expect(input, contains('username ${hexOf('bob')}'));
      expect(input, contains('current ${hexOf('s3cret')}'));
    });
  });

  group('use in an app', () {
    testWidgets('a login is linked to a chosen app, with its publisher and installer shown, and the rest of the login kept', (t) async {
      // Real file work, outside the test's fake clock.
      final agent = (await t.runAsync(FakeAgent.create))!;
      addTearDown(() => t.runAsync(agent.dispose));
      final settings = Settings(File('${agent.dir.path}/settings.json'), binary: agent.path, deviceDir: '${agent.dir.path}/dev', tutorialSeen: true)..siteIcons = false;
      t.view.devicePixelRatio = 2;
      t.view.physicalSize = const Size(420, 1000) * 2;
      addTearDown(t.view.reset);
      final app = App(settings);
      await t.pumpWidget(MaterialApp(
          home: ItemPage(app: app, item: const VaultItem('mail', 'login'), offline: false, names: const {'mail'},
              apps: () async => [InstalledApp('com.sideload.mail', 'Mail Pro', [cert], ''), InstalledApp('com.example.mail', 'Mail', [cert], 'com.android.vending')])));
      await t.pump();
      await t.enterText(find.byKey(const Key('secret-field')), '2468');
      await t.tap(find.byKey(const Key('secret-ok')));
      for (var i = 0; i < 20; i++) {
        await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
        await t.pump(const Duration(milliseconds: 50));
      }
      await t.ensureVisible(find.byKey(const Key('item-app-add')));
      await t.tap(find.byKey(const Key('item-app-add')));
      await t.pump(const Duration(milliseconds: 600));
      await t.pump(const Duration(milliseconds: 100));
      await t.tap(find.byKey(const Key('app-com.sideload.mail')));
      await t.pump(const Duration(milliseconds: 600));
      await t.pump(const Duration(milliseconds: 100));
      expect(find.text('Not installed from an app store'), findsOneWidget);
      expect(find.text('Only link it if you know where this app came from.'), findsOneWidget);
      await t.tap(find.text('Cancel'));
      await t.pump(const Duration(milliseconds: 600));
      await t.pump(const Duration(milliseconds: 100));
      await t.tap(find.byKey(const Key('app-com.example.mail')));
      await t.pump(const Duration(milliseconds: 600));
      await t.pump(const Duration(milliseconds: 100));
      expect(find.text('Installed from Google Play'), findsOneWidget);
      await t.tap(find.byKey(const Key('link-ok')));
      await t.pump(const Duration(milliseconds: 600));
      await t.pump(const Duration(milliseconds: 100));
      for (var i = 0; i < 20; i++) {
        await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
        await t.pump(const Duration(milliseconds: 50));
      }
      final input = (await t.runAsync(() => File('${agent.dir.path}/stdin.log').readAsString()))!;
      final set = input.split('--\n').lastWhere((b) => b.contains('apps '));
      expect(set, contains('apps ${hexOf('com.example.mail $cert')}'));
      expect(set, contains('current ${hexOf('hunter2')}'));          // the rest of the login kept
      expect(set, contains('totp ${hexOf('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')}'));
      expect(find.byKey(const Key('item-app-com.example.mail')), findsOneWidget);
      app.session.lock();
    });
  });
}
