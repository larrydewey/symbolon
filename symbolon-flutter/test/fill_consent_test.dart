import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/fill_consent.dart';
import 'package:symbolon_ui/settings.dart';
import 'package:symbolon_ui/vault_types.dart';

import 'fake_agent.dart';

class FakeLink extends FillLink {
  final String? caller;
  final opened = <String>[], sent = <String>[];
  FakeLink({this.caller = '/usr/lib/chromium/chromium'});

  @override
  Future<String?> open(String token, int port) async {
    opened.add(token);
    return caller;
  }

  @override
  Future<void> send(String body) async => sent.add(body);
}

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

  // Shows the window for [request]; returns its link and whether it closed.
  Future<({FakeLink link, List<bool> closed})> open(WidgetTester t, String request, {FakeLink? link}) async {
    t.view.devicePixelRatio = 2;
    t.view.physicalSize = const Size(460, 900) * 2;
    addTearDown(t.view.reset);
    final l = link ?? FakeLink(), closed = <bool>[];
    await t.pumpWidget(const SizedBox());   // a fresh window each time
    await t.pumpWidget(FillConsentApp(settings: settings, request: FillRequest.parse(request), link: l, done: () => closed.add(true)));
    await t.pump();
    return (link: l, closed: closed);
  }

  Future<void> unlock(WidgetTester t) async {
    await t.enterText(find.byKey(const Key('fc-pin')), '2468');
    await t.tap(find.byKey(const Key('fc-unlock')));
    await t.pump();
    await settle(t);
  }

  const card = '{"top":"https://shop.example","want":"card","port":1,"token":"abc","frames":[{"origin":"https://shop.example","fields":["cc-name"]},{"origin":"https://js.stripe.com","fields":["cc-number","cc-csc"]}]}';
  const login = '{"top":"https://mail.example.com","want":"login","port":1,"token":"abc","frames":[{"origin":"https://mail.example.com","fields":["username","current-password"]}]}';

  testWidgets('a card: the page and the processor frame are shown; the chosen card is sent with the token, nothing more', (t) async {
    final w = await open(t, card);
    expect(find.text('shop.example'), findsOneWidget);
    expect(find.text('The page at https://shop.example'), findsOneWidget);
    expect(find.byKey(const Key('fc-frame-https://js.stripe.com')), findsOneWidget);
    expect(w.link.opened, ['abc']);
    expect(find.text('chromium'), findsOneWidget);
    expect(find.text('Asked by /usr/lib/chromium/chromium'), findsOneWidget);
    await unlock(t);
    expect(find.byKey(const Key('fc-item-visa')), findsOneWidget);
    expect(find.text('•••• 1111'), findsOneWidget);
    expect(find.byKey(const Key('fc-item-mail')), findsNothing);
    await t.tap(find.byKey(const Key('fc-fill')));
    await t.pump();
    await settle(t);
    expect(w.link.sent, ['ok card\nnumber ${hexOf('4111111111111111')}\ncvv ${hexOf('123')}\nend\n']);
    expect(w.closed, [true]);
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device vault show ${agent.dir.path}/dev visa'));
  });

  testWidgets('a login: only the site\'s own logins are offered', (t) async {
    final w = await open(t, login);
    await unlock(t);
    expect(find.byKey(const Key('fc-item-mail')), findsOneWidget);
    expect(find.byKey(const Key('fc-item-visa')), findsNothing);
    await t.tap(find.byKey(const Key('fc-fill')));
    await t.pump();
    await settle(t);
    expect(w.link.sent, ['ok login\norigin ${hexOf('https://mail.example.com')}\nusername ${hexOf('alice')}\ncurrent ${hexOf('hunter2')}\nend\n']);
  });

  testWidgets('a site with no saved login: nothing to choose, and cancel answers cancel', (t) async {
    final w = await open(t, login.replaceAll('mail.example.com', 'other.example'));
    await unlock(t);
    expect(find.byKey(const Key('fc-none')), findsOneWidget);
    expect(find.byKey(const Key('fc-fill')), findsNothing);
    await t.tap(find.byKey(const Key('fc-cancel')));
    await t.pump();
    expect(w.link.sent, ['cancel\n']);
    expect(w.closed, [true]);
  });

  testWidgets('a wrong PIN shows the error and sends nothing', (t) async {
    final w = await open(t, card);
    await t.enterText(find.byKey(const Key('fc-pin')), '1111');
    await t.tap(find.byKey(const Key('fc-unlock')));
    await t.pump();
    await settle(t);
    expect(find.byKey(const Key('fc-item-visa')), findsNothing);
    expect(w.link.sent, isEmpty);
    expect(w.closed, isEmpty);
  });

  testWidgets('a request that cannot be read only offers to close', (t) async {
    final w = await open(t, '{"top":');
    expect(find.byKey(const Key('fc-problem')), findsOneWidget);
    expect(find.byKey(const Key('fc-pin')), findsNothing);
    await t.tap(find.text('Close'));
    expect(w.link.sent, isEmpty);
    expect(w.closed, [true]);
  });

  testWidgets('a host run by a program that is not a browser: the window says so', (t) async {
    await open(t, card, link: FakeLink(caller: '/usr/bin/python3.14'));
    expect(find.text('python3.14'), findsOneWidget);
    expect(find.text('This is not a browser. Do not go on unless you started it yourself.'), findsOneWidget);
  });

  testWidgets('when the host is gone or gives up, nothing is offered or sent', (t) async {
    final gone = await open(t, card, link: FakeLink(caller: null));
    expect(find.byKey(const Key('fc-expired')), findsOneWidget);
    expect(find.byKey(const Key('fc-pin')), findsNothing);
    final w = await open(t, card);
    await unlock(t);
    w.link.lost!();
    await t.pump();
    expect(find.byKey(const Key('fc-expired')), findsOneWidget);
    expect(find.byKey(const Key('fc-fill')), findsNothing);
    await t.tap(find.text('Close'));
    expect(w.link.sent, isEmpty);
    expect(gone.link.sent, isEmpty);
    expect(w.closed, [true]);
  });

  test('a login saved for a site is offered on its subdomains, never on its parent or siblings', () {
    expect(siteCovers('https://proton.me', 'https://account.proton.me'), isTrue);
    expect(siteCovers('https://www.github.com', 'https://github.com'), isTrue);
    expect(siteCovers('https://www.github.com', 'https://gist.github.com'), isTrue);
    expect(siteCovers('https://shop.example:8443', 'https://pay.shop.example:8443'), isTrue);
    expect(siteCovers('https://login.example.com', 'https://example.com'), isFalse);
    expect(siteCovers('https://login.example.com', 'https://mail.example.com'), isFalse);
    expect(siteCovers('https://proton.me', 'https://notproton.me'), isFalse);
    expect(siteCovers('https://proton.me', 'https://proton.me.evil.example'), isFalse);
    expect(siteCovers('https://shop.example', 'https://pay.shop.example:8443'), isFalse);
    expect(siteCovers('https://2.3.4', 'https://1.2.3.4'), isFalse);
    expect(siteCovers('https://www.com', 'https://evil.com'), isFalse);
    expect(siteCovers('', 'https://shop.example'), isFalse);
  });

  test('the answer carries only the fields of the type, never a card PIN or notes', () {
    expect(fillAnswer('card', {'number': '4111', 'pin': '9999', 'notes': 'x', 'cvv': '1', 'type': 'card'}), 'ok card\nnumber ${hexOf('4111')}\ncvv ${hexOf('1')}\nend\n');
    expect(fillAnswer('login', {'current': 'p', 'totp': 'K', 'origin': 'https://a.example'}), 'ok login\norigin ${hexOf('https://a.example')}\ncurrent ${hexOf('p')}\nend\n');
    expect(fillAnswer(null, {'current': 'p'}), 'cancel\n');
    expect(isBrowserExe('/usr/lib/chromium/chromium'), isTrue);
    expect(isBrowserExe('/usr/lib/firefox/firefox'), isTrue);
    expect(isBrowserExe('/opt/google/chrome/chrome'), isTrue);
    expect(isBrowserExe('/usr/bin/python3'), isFalse);
    expect(isBrowserExe('/home/u/chromium-fake/evil'), isFalse);
  });
}
