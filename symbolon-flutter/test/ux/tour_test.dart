// A screenshot tour of the app, for reviewing how it looks and reads: every
// main screen and flow, against the fake agent, in light, dark and large
// text. Off unless asked for:
//
//   flutter test test/ux --dart-define=UX_OUT=/some/dir
//
// writes <scenario>-<step>-<variant>.png there. Not a test of behaviour.

import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/fill_consent.dart';
import 'package:symbolon_ui/main.dart';
import 'package:symbolon_ui/pages/join_page.dart';
import 'package:symbolon_ui/pages/tutorial_page.dart';
import 'package:symbolon_ui/app.dart';
import 'package:symbolon_ui/brand.dart';
import 'package:symbolon_ui/hardware.dart';
import 'package:symbolon_ui/passkey_main.dart';
import 'package:symbolon_ui/ssh_consent.dart';
import 'package:symbolon_ui/settings.dart';

import '../fake_agent.dart';

class _FillLink extends FillLink {
  @override
  Future<String?> open(String token, int port) async => '/usr/lib/chromium/chromium';
  @override
  Future<void> send(String body) async {}
}

class _SshLink extends SshLink {
  @override
  Future<bool> open(String socket, String token) async => true;
  @override
  Future<void> send(String line) async {}
}

const out = String.fromEnvironment('UX_OUT');

Future<void> _fonts() async {
  final sdk = Platform.environment['FLUTTER_ROOT'] ?? '/opt/flutter-sdk/flutter';
  final d = '$sdk/bin/cache/artifacts/material_fonts';
  Future<ByteData> f(String p) async => ByteData.sublistView(await File(p).readAsBytes());
  final roboto = FontLoader('Roboto');
  for (final n in ['Regular', 'Medium', 'Bold', 'Light']) {
    roboto.addFont(f('$d/Roboto-$n.ttf'));
  }
  await roboto.load();
  await (FontLoader('MaterialIcons')..addFont(f('$d/MaterialIcons-Regular.otf'))).load();
  const mono = '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf';
  if (File(mono).existsSync()) await (FontLoader('monospace')..addFont(f(mono))).load();
}

enum Variant { light, dark, large }

typedef Snap = Future<void> Function(String step);

class Tour {
  final WidgetTester t;
  final FakeAgent agent;
  final String scenario;
  final Variant v;
  Tour(this.t, this.agent, this.scenario, this.v);

  Future<void> settle([int n = 20]) async {
    for (var i = 0; i < n; i++) {
      await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 40)));
      await t.pump(const Duration(milliseconds: 40));
    }
  }

  Future<void> snap(String step) async {
    await t.pump(const Duration(milliseconds: 400));
    await t.runAsync(() async {
      final layer = t.binding.renderViews.first.debugLayer! as OffsetLayer;
      final img = await layer.toImage(Offset.zero & t.view.physicalSize, pixelRatio: 1);
      final b = await img.toByteData(format: ui.ImageByteFormat.png);
      File('$out/$scenario-$step-${v.name}.png').writeAsBytesSync(b!.buffer.asUint8List());
    });
  }

  Future<void> tap(Finder f) async {
    if (f.evaluate().isEmpty) {
      final list = find.byType(Scrollable).hitTestable().first;
      for (final d in [400.0, -400.0]) {
        for (var i = 0; i < 12 && f.evaluate().isEmpty; i++) {
          await t.drag(list, Offset(0, d));
          await t.pump(const Duration(milliseconds: 200));
        }
      }
    }
    await t.ensureVisible(f.first);
    await t.pump();
    await t.tap(f.first);
    await t.pump(const Duration(milliseconds: 350));
  }

  Future<void> key(String k) => tap(find.byKey(Key(k)));
  Future<void> text(String s) => tap(find.text(s));
  Future<void> pin([String p = '2468']) async {
    await t.enterText(find.byKey(const Key('secret-field')), p);
    await t.tap(find.byKey(const Key('secret-ok')));
    await t.pump();
    await settle();
  }

  Future<void> back() async {
    await t.pageBack();
    await t.pump(const Duration(milliseconds: 500));
  }
}

void scenario(String name, Future<void> Function(Tour u) body, {bool setUp = true, Size size = const Size(400, 840), Settings Function(FakeAgent a)? settings, Widget Function(Settings s)? root}) {
  for (final v in Variant.values) {
    testWidgets('$name ${v.name}', (t) async {
      final agent = await t.runAsync(FakeAgent.create);
      addTearDown(() => agent!.dispose());
      await t.runAsync(_fonts);
      debugDisableShadows = false;
      t.view.devicePixelRatio = 2;
      t.view.physicalSize = size * 2;
      t.platformDispatcher.platformBrightnessTestValue = v == Variant.dark ? Brightness.dark : Brightness.light;
      if (v == Variant.large) t.platformDispatcher.textScaleFactorTestValue = 1.6;
      addTearDown(() {
        t.view.reset();
        t.platformDispatcher.clearAllTestValues();
      });
      final a = agent!;
      final s = settings?.call(a) ??
          (Settings(File('${a.dir.path}/settings.json'), binary: setUp ? a.path : '/nonexistent', deviceDir: '${a.dir.path}/dev', tutorialSeen: true)..siteIcons = false);
      t.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, (c) async => null);
      await t.pumpWidget(root?.call(s) ?? SymbolonApp(settings: s));
      final u = Tour(t, a, name, v);
      await u.settle();
      await body(u);
      // Leave nothing running: lock, which drops the session's timer.
      await t.pumpWidget(const SizedBox());
      await t.pump(const Duration(minutes: 30));
      debugDisableShadows = true;
    }, skip: out.isEmpty);   // set UX_OUT to write the tour
  }
}

void main() {
  scenario('welcome', (u) async {
    await u.snap('home');
    await u.key('start-setup');
    await u.settle(6);
    await u.snap('setup-connect');
    await u.text('Other ways to connect');
    await u.snap('setup-other');
    await u.text('Enter the details by hand');
    await u.snap('setup-manual');
  }, setUp: false);

  scenario('home', (u) async {
    await u.snap('verified');
    await u.t.drag(find.byType(Scrollable).first, const Offset(0, -500));
    await u.snap('scrolled');
    await u.text('Review in Recovery');
    await u.settle(4);
    await u.snap('review');
  });

  scenario('passkeys', (u) async {
    await u.tap(find.text('Passkeys').last);
    await u.snap('empty');
    await u.key('new-passkey');
    await u.snap('new');
    await u.t.enterText(find.byKey(const Key('rp')), 'bank.example.org');
    await u.key('register');
    await u.snap('pin');
    await u.pin();
    await u.snap('list');
    await u.key('passkey-bank.example.org');
    await u.snap('details');
  });

  scenario('vault', (u) async {
    await u.tap(find.text('Vault').last);
    await u.t.pump(const Duration(milliseconds: 300));
    await u.snap('pin');
    await u.pin();
    await u.snap('list');
    await u.key('vault-add');
    await u.snap('add');
    await u.key('add-login');
    await u.settle(4);
    await u.snap('editor');
    await u.back();
    await u.key('item-mail');
    await u.settle();
    await u.snap('login');
    await u.back();
    await u.key('item-visa');
    await u.settle();
    await u.snap('card');
  });

  scenario('more', (u) async {
    await u.tap(find.text('More').last);
    await u.snap('list');
    for (final (k, n) in [
      ('Devices', 'devices'),
      ('open-sharing', 'sharing'),
      ('open-org', 'org'),
      ('open-ssh', 'ssh'),
      ('open-import', 'import'),
      ('Recovery', 'recovery'),
      ('open-keys', 'keys'),
      ('open-hardware', 'hardware'),
      ('open-settings', 'settings'),
    ]) {
      await (k.startsWith('open-') ? u.key(k) : u.text(k));
      await u.settle(8);
      if (find.byKey(const Key('secret-field')).evaluate().isNotEmpty) await u.pin();
      await u.snap(n);
      await u.back();
      await u.settle(4);
    }
  });

  scenario('wide', (u) async {
    await u.snap('home');
    await u.tap(find.text('Vault').last);
    await u.t.pump(const Duration(milliseconds: 300));
    await u.pin();
    await u.snap('vault');
  }, size: const Size(1100, 720));

  scenario('tour', (u) async {
    for (var i = 0; i < 3; i++) {
      await u.snap('page$i');
      await u.key('tutorial-next');
      await u.t.pump(const Duration(milliseconds: 400));
    }
  }, root: (s) => MaterialApp(debugShowCheckedModeBanner: false, theme: Brand.theme(Brightness.light), darkTheme: Brand.theme(Brightness.dark), home: const TutorialPage()));

  scenario('setup', (u) async {
    await u.tap(find.text('More').last);
    await u.text('Set up this device');
    await u.settle(4);
    await u.text('Other ways to connect');
    await u.text('Enter the details by hand');
    final fields = find.descendant(of: find.byType(Card).last, matching: find.byType(TextFormField));
    final values = ['relay.example.org', '47000', '', 'ab' * 40, 'w1.example.org:47001:${'cd' * 32}', 'w2.example.org:47002:${'cd' * 32}', 'w3.example.org:47003:${'cd' * 32}'];
    for (var i = 0; i < values.length; i++) {
      if (values[i].isNotEmpty) await u.t.enterText(fields.at(i), values[i]);
    }
    await u.tap(find.widgetWithText(FilledButton, 'Next'));
    await u.settle(6);
    await u.snap('pin');
    await u.t.enterText(find.byKey(const Key('pin')), '246813');
    await u.t.enterText(find.byKey(const Key('pin2')), '246813');
    await u.t.drag(find.byType(Scrollable).last, const Offset(0, -400));
    await u.snap('pin-filled');
    await u.key('create');
    await u.t.pump(const Duration(milliseconds: 200));
    await u.snap('working');
    await u.settle(30);
    await u.snap('kit');
  });

  scenario('join', (u) async {
    await u.snap('pin');
    await u.t.enterText(find.byKey(const Key('join-pin')), '2468');
    await u.t.enterText(find.byKey(const Key('join-pin2')), '2468');
    await u.key('join-start');
    await u.settle(8);
    await u.snap('code');
    await u.settle(60);
    await u.snap('done');
  }, root: (s) => MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: Brand.theme(Brightness.light),
      darkTheme: Brand.theme(Brightness.dark),
      home: JoinPage(app: App(s), hardware: ({bool keystore = false}) async => HardwareState.ready, addresses: () async => ['192.168.1.20'])));

  scenario('fill', (u) async {
    await u.snap('ask');
    await u.t.enterText(find.byKey(const Key('fc-pin')), '2468');
    await u.key('fc-unlock');
    await u.settle();
    await u.snap('choose');
  }, size: const Size(460, 700), root: (s) => FillConsentApp(settings: s, request: FillRequest.parse('{"top":"https://mail.example.com","want":"login","port":1,"token":"abc","frames":[{"origin":"https://mail.example.com","fields":["username","current-password"]}]}')!, link: _FillLink(), done: () {}));

  scenario('ssh', (u) async {
    await u.snap('ask');
  }, size: const Size(460, 700), root: (s) => SshConsentApp(
      settings: s,
      request: SshRequest.parse('{"key":"github","fingerprint":"SHA256:abc","what":{"kind":"auth","user":"git"},"host":{"key":"AAAAhostkey","fingerprint":"SHA256:host","forwarding":false},"pid":4242,"data":"0a0b","socket":"/run/x.sock","token":"tok"}')!,
      link: _SshLink(),
      knownHosts: '',
      caller: (exe: '/usr/bin/ssh', cmdline: 'ssh git@github.com'),
      done: () {}));

  scenario('passkey', (u) async {
    await u.snap('create');
  }, size: const Size(420, 760), root: (s) => PasskeyApp(settings: s, channel: const MethodChannel('symbolon/passkey'), request: {
        'kind': 'create',
        'origin': 'https://login.example.com',
        'browser': true,
        'callingPackage': 'com.android.chrome',
        'clientDataHash': '00' * 32,
        'clientDataJSON': null,
        'requestJson': '{"rp":{"id":"example.com"},"user":{"id":"Bwc","name":"alice","displayName":"Alice"},"challenge":"AAAA","pubKeyCredParams":[{"type":"public-key","alg":-7}]}',
      }));
}
