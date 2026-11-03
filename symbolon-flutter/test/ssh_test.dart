import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/app.dart';
import 'package:symbolon_ui/pages/ssh_page.dart';
import 'package:symbolon_ui/settings.dart';
import 'package:symbolon_ui/ssh_consent.dart';

import 'fake_agent.dart';

class FakeSshLink extends SshLink {
  final bool up;
  final opened = <String>[], sent = <String>[];
  FakeSshLink({this.up = true});

  @override
  Future<bool> open(String socket, String token) async {
    opened.add('$socket $token');
    return up;
  }

  @override
  Future<void> send(String line) async => sent.add(line);
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

  void sized(WidgetTester t) {
    t.view.devicePixelRatio = 2;
    t.view.physicalSize = const Size(460, 1000) * 2;
    addTearDown(t.view.reset);
  }

  const auth = '{"key":"github","fingerprint":"SHA256:abc","what":{"kind":"auth","user":"git"},"host":{"key":"AAAAhostkey","fingerprint":"SHA256:host","forwarding":false},"pid":4242,"data":"0a0b","socket":"/run/x.sock","token":"tok"}';

  Future<({FakeSshLink link, List<bool> closed})> open(WidgetTester t, String req, {FakeSshLink? link, String known = '', String exe = '/usr/bin/ssh', String cmd = 'ssh git@github.com'}) async {
    sized(t);
    final l = link ?? FakeSshLink(), closed = <bool>[];
    await t.pumpWidget(const SizedBox());
    await t.pumpWidget(SshConsentApp(settings: settings, request: SshRequest.parse(req), link: l, knownHosts: known, caller: (exe: exe, cmdline: cmd), done: () => closed.add(true)));
    await t.pump();
    return (link: l, closed: closed);
  }

  testWidgets('a sign-in: the key, the program, the user and the server are shown; the signature goes back after the token', (t) async {
    final w = await open(t, auth, known: 'github.com,140.82.112.3 ssh-ed25519 AAAAhostkey\nother.example ssh-ed25519 AAAAzzz\n');
    expect(find.text('Sign in as git'), findsOneWidget);
    expect(find.text('github'), findsOneWidget);
    expect(find.text('ssh'), findsOneWidget);
    expect(find.text('ssh git@github.com'), findsOneWidget);
    expect(find.text('github.com, 140.82.112.3'), findsOneWidget);
    expect(find.text('Server key SHA256:host'), findsOneWidget);
    expect(w.link.opened, ['/run/x.sock tok']);
    await t.enterText(find.byKey(const Key('sc-pin')), '2468');
    await t.tap(find.byKey(const Key('sc-sign')));
    await t.pump();
    await settle(t);
    expect(w.link.sent, ['ok 0000000b7373682d6564323535313900000040aa\n']);
    expect(w.closed, [true]);
    final input = (await t.runAsync(() => agent.stdinLog.readAsString()))!;
    expect(input, contains('2468\n0a0b'));
  });

  testWidgets('an RSA key is signed with the algorithm the agent names', (t) async {
    final w = await open(t, auth.replaceAll('"data":"0a0b"', '"data":"0a0b","alg":"rsa-sha2-512"'));
    await t.enterText(find.byKey(const Key('sc-pin')), '2468');
    await t.tap(find.byKey(const Key('sc-sign')));
    await t.pump();
    await settle(t);
    expect(w.link.sent, hasLength(1));
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device ssh sign ${agent.dir.path}/dev github rsa-sha2-512'));
  });

  testWidgets('a git signature, a forwarded request and unknown data are worded and warned', (t) async {
    await open(t, auth.replaceAll('{"kind":"auth","user":"git"}', '{"kind":"sshsig","namespace":"git"}'));
    expect(find.text('Sign a git commit or tag'), findsOneWidget);
    await open(t, auth.replaceAll('"forwarding":false', '"forwarding":true'));
    expect(find.byKey(const Key('sc-forwarded')), findsOneWidget);
    await open(t, auth.replaceAll('{"kind":"auth","user":"git"}', '{"kind":"unknown"}').replaceAll('{"key":"AAAAhostkey","fingerprint":"SHA256:host","forwarding":false}', 'null'));
    expect(find.text('Sign data Symbolon does not recognize'), findsOneWidget);
    expect(find.byKey(const Key('sc-unknown')), findsOneWidget);
    expect(find.byKey(const Key('sc-host')), findsNothing);
  });

  testWidgets('a wrong PIN sends nothing; cancel sends cancel; a gone agent offers only Close', (t) async {
    var w = await open(t, auth);
    await t.enterText(find.byKey(const Key('sc-pin')), '1111');
    await t.tap(find.byKey(const Key('sc-sign')));
    await t.pump();
    await settle(t);
    expect(w.link.sent, isEmpty);
    expect(w.closed, isEmpty);
    await t.tap(find.byKey(const Key('sc-cancel')));
    await t.pump();
    expect(w.link.sent, ['cancel\n']);
    w = await open(t, auth, link: FakeSshLink(up: false));
    await t.pump();
    expect(find.byKey(const Key('sc-expired')), findsOneWidget);
    expect(find.byKey(const Key('sc-pin')), findsNothing);
    expect(w.link.sent, isEmpty);
  });

  test('hashed known_hosts entries are matched against host names in the command line', () {
    // |1|salt|hash for "github.com" with the salt below (HMAC-SHA1, as ssh-keygen -H writes).
    const entry = '|1|tLVHxaHBnZ5VhDoumZr0fXrHoNM=|7xEZBuRcSHKvG4hnCDh48wgAEgQ= ssh-ed25519 AAAAhostkey';
    expect(knownNames('AAAAhostkey', entry, hostCandidates('ssh -p 22 git@github.com')), ['github.com']);
    expect(knownNames('AAAAhostkey', entry, hostCandidates('ssh git@gitlab.com')), isEmpty);
    expect(knownNames('AAAAother', entry, hostCandidates('ssh git@github.com')), isEmpty);
  });

  testWidgets('the SSH keys page lists keys without the PIN and makes a threshold key', (t) async {
    sized(t);
    String? unit;
    final app = App(settings);
    await t.pumpWidget(MaterialApp(home: SshPage(app: app, installAgent: (u) async {
      unit = u;
      return null;
    })));
    await settle(t);
    expect(find.byKey(const Key('ssh-key-github')), findsOneWidget);
    expect(find.byKey(const Key('ssh-key-quorum')), findsOneWidget);
    expect(find.text('Imported · ssh-ed25519'), findsOneWidget);
    expect(find.text('Held by your quorum · ecdsa-sha2-nistp256'), findsOneWidget);
    await t.tap(find.byKey(const Key('ssh-agent-setup')));
    await t.pump();
    expect(unit, contains('ExecStart=${agent.path} ssh-agent ${agent.dir.path}/dev'));
    expect(unit, contains('Environment=SYMBOLON_CONSENT='));
    await t.tap(find.byKey(const Key('ssh-new')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('ssh-name')), 'work');
    await t.tap(find.byKey(const Key('ssh-name-ok')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('secret-field')), '2468');
    await t.tap(find.byKey(const Key('secret-ok')));
    await t.pump();
    await settle(t);
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device ssh new ${agent.dir.path}/dev work'));
    app.session.lock();
  });
}
