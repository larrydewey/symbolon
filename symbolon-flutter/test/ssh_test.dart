import 'dart:io';

import 'package:material_ui/material_ui.dart';
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

  testWidgets('an app on the phone: named by its signature, no process line, the server named neutrally', (t) async {
    const app = '{"key":"github","fingerprint":"SHA256:abc","what":{"kind":"auth","user":"git"},"host":{"key":"AAAAhostkey","fingerprint":"SHA256:host","forwarding":false},"pid":0,"peer":"Pylon (dev.pylon.app)","data":"0a0b","socket":"/run/x.sock","token":"tok"}';
    await open(t, app, exe: 'Pylon (dev.pylon.app)', cmd: '');
    expect(SshRequest.parse(app)!.peer, 'Pylon (dev.pylon.app)');
    expect(find.text('An app on this phone, identified by its signature'), findsOneWidget);
    expect(find.textContaining('Asked by process'), findsNothing);
    expect(find.text('Server'), findsOneWidget);
    expect(find.textContaining('Server key SHA256:host. It should match'), findsOneWidget);
    expect(find.textContaining('known_hosts'), findsNothing);
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
    await t.scrollUntilVisible(find.byKey(const Key('ssh-agent-setup')), 300, scrollable: find.byType(Scrollable).first);
    await t.tap(find.byKey(const Key('ssh-agent-setup')));
    await t.pump();
    expect(unit, contains('ExecStart=${agent.path} ssh-agent ${agent.dir.path}/dev'));
    expect(unit, contains('Environment=SYMBOLON_CONSENT='));
    await t.scrollUntilVisible(find.byKey(const Key('ssh-new')), -300, scrollable: find.byType(Scrollable).first);
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

  testWidgets('a certificate is shown with its authority, user names and end, and when it is renewed', (t) async {
    final vb = DateTime(2026, 12, 1, 14, 5).millisecondsSinceEpoch ~/ 1000;
    final cert = auth.replaceAll('"data":"0a0b"', '"data":"0a0b","certificate":{"ca":"myca","principals":["alice","deploy"],"valid_before":$vb,"renews":false}');
    expect(SshRequest.parse(cert)!.certPrincipals, ['alice', 'deploy']);
    var w = await open(t, cert);
    expect(find.text('Certificate from myca'), findsOneWidget);
    expect(find.text('For alice, deploy, valid until 2026-12-01 14:05.'), findsOneWidget);
    expect(find.textContaining('renews it'), findsNothing);
    w = await open(t, cert.replaceAll('"renews":false', '"renews":true'));
    expect(find.textContaining('Symbolon renews it after this signature'), findsOneWidget);
    // The signature goes back at once; the window closes when the run ends.
    await t.enterText(find.byKey(const Key('sc-pin')), '2468');
    await t.tap(find.byKey(const Key('sc-sign')));
    await t.pump();
    await settle(t);
    expect(w.link.sent, ['ok 0000000b7373682d6564323535313900000040aa\n']);
    expect(w.closed, [true]);
    await open(t, auth);
    expect(find.byKey(const Key('sc-cert')), findsNothing);
  });

  test('server commands: the line quoted for the shell, the CA for one user or the whole server', () {
    expect(authorizeCommand('larry@box', 'ssh-ed25519 AAAA my key'), "pylon authorize larry@box 'ssh-ed25519 AAAA my key'");
    expect(authorizeCommand('larry@box', "ssh-ed25519 AAAA it's", ca: true), "pylon authorize --ca larry@box 'ssh-ed25519 AAAA it'\\''s'");
    final root = trustCaAsRoot('ecdsa-sha2-nistp256 AAAA myca');
    expect(root, contains("echo 'ecdsa-sha2-nistp256 AAAA myca' | sudo tee /etc/ssh/symbolon_user_ca.pub"));
    expect(root, contains('TrustedUserCAKeys /etc/ssh/symbolon_user_ca.pub'));
    expect(root, contains('sshd -t'));
    final c = SshCert.parse('71756f72756d 6d796361 7 alice,deploy 1000 1604800 ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA quorum')!;
    expect(c.key, 'quorum');
    expect(c.ca, 'myca');
    expect(c.principals, ['alice', 'deploy']);
    expect(c.line, 'ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA quorum');
    expect(c.current(1000), isTrue);
    expect(c.current(1604800), isFalse);
    // A third of 1603800 s is 534600 s: due from 1070200 on.
    expect(c.due(1070199), isFalse);
    expect(c.due(1070200), isTrue);
    expect(SshCert.parse('nonsense'), isNull);
    expect(principalPattern.hasMatch('deploy'), isTrue);
    expect(principalPattern.hasMatch('a,b'), isFalse);
  });

  Future<void> pin(WidgetTester t) async {
    // Not pumpAndSettle: a task's progress spinner never settles.
    for (var i = 0; i < 5; i++) {
      await t.pump(const Duration(milliseconds: 100));
    }
    if (find.byKey(const Key('secret-field')).evaluate().isNotEmpty) {
      await t.enterText(find.byKey(const Key('secret-field')), '2468');
      await t.tap(find.byKey(const Key('secret-ok')));
    }
    await t.pump();
    await settle(t);
  }

  testWidgets('the SSH page explains the setup, gives each key its server command, and makes a certificate authority', (t) async {
    sized(t);
    final app = App(settings);
    await t.pumpWidget(MaterialApp(home: SshPage(app: app, installAgent: (u) async => null)));
    await settle(t);
    // With keys already there, how servers are set up is a tap away.
    expect(find.byKey(const Key('ssh-howto')), findsOneWidget);
    expect(find.textContaining('one setup per server covers every device'), findsNothing);
    await t.tap(find.text('How a server learns to trust you'));
    await t.pumpAndSettle();
    expect(find.textContaining('one setup per server covers every device'), findsOneWidget);
    await t.tap(find.text('How a server learns to trust you'));
    await t.pumpAndSettle();
    // Per key: the authorized_keys line and Pylon's command for a server typed in.
    await t.scrollUntilVisible(find.byKey(const Key('ssh-setup-github')), 300, scrollable: find.byType(Scrollable).first);
    await t.tap(find.byKey(const Key('ssh-setup-github')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('ssh-target')), 'larry@box');
    await t.pump();
    expect(find.text("pylon authorize larry@box 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOxx github@laptop'"), findsOneWidget);
    await t.tapAt(const Offset(5, 5));
    await t.pumpAndSettle();
    // No authority yet: no certificate buttons, a button to make one.
    expect(find.byKey(const Key('ssh-certify-github')), findsNothing);
    await t.scrollUntilVisible(find.byKey(const Key('ssh-ca-new')), 300, scrollable: find.byType(Scrollable).first);
    await t.tap(find.byKey(const Key('ssh-ca-new')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('ssh-name')), 'myca');
    await t.tap(find.byKey(const Key('ssh-name-ok')));
    await pin(t);
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device ssh ca-new ${agent.dir.path}/dev myca'));
    expect(find.byKey(const Key('ssh-ca-myca')), findsOneWidget);
    // The authority trusted for one user, through Pylon.
    await t.scrollUntilVisible(find.byKey(const Key('ssh-trust-myca')), 300, scrollable: find.byType(Scrollable).first);
    await t.tap(find.byKey(const Key('ssh-trust-myca')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('ssh-trust-user')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('ssh-target')), 'deploy@box');
    await t.pump();
    expect(find.text("pylon authorize --ca deploy@box 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCa myca'"), findsOneWidget);
    await t.tapAt(const Offset(5, 5));
    await t.pumpAndSettle();
    // A certificate for a key: user names and days.
    await t.scrollUntilVisible(find.byKey(const Key('ssh-certify-github')), 300, scrollable: find.byType(Scrollable).first);
    await t.tap(find.byKey(const Key('ssh-certify-github')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('ssh-principals')), 'larry, deploy');
    await t.enterText(find.byKey(const Key('ssh-days')), '7');
    await t.tap(find.byKey(const Key('ssh-certify-ok')));
    await pin(t);
    final args2 = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args2, contains('device ssh certify ${agent.dir.path}/dev github myca --principal larry --principal deploy --days 7'));
    app.session.lock();
  });

  testWidgets('a key with a certificate shows it and renews it', (t) async {
    sized(t);
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    File('${agent.dir.path}/ssh-cas').writeAsStringSync('6d796361 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCa myca\n');
    File('${agent.dir.path}/ssh-certs').writeAsStringSync('71756f72756d 6d796361 30 larry,deploy ${now - 300} ${now + 86400} ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA quorum\n'
        '676974687562 6d796361 30 larry ${now - 90000} ${now - 100} ssh-ed25519-cert-v01@openssh.com BBBB github\n');
    final app = App(settings);
    await t.pumpWidget(MaterialApp(home: SshPage(app: app, installAgent: (u) async => null)));
    await settle(t);
    expect(find.textContaining('Certificate from myca for larry, deploy, valid until'), findsOneWidget);
    expect(find.textContaining('Certificate from myca expired'), findsOneWidget);
    await t.scrollUntilVisible(find.byKey(const Key('ssh-renew-quorum')), 300, scrollable: find.byType(Scrollable).first);
    await t.tap(find.byKey(const Key('ssh-renew-quorum')));
    await pin(t);
    await t.tap(find.byKey(const Key('ssh-refresh')));
    await pin(t);
    final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
    expect(args, contains('device ssh renew ${agent.dir.path}/dev quorum'));
    expect(args, contains('device ssh refresh ${agent.dir.path}/dev'));
    app.session.lock();
  });
}
