import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/passkey_main.dart';
import 'package:symbolon_ui/settings.dart';
import 'package:symbolon_ui/webauthn.dart';

import 'fake_agent.dart';

void main() {
  test('registration requests are read and checked', () {
    final r = CreateRequest.parse(
        jsonEncode({
          'rp': {'id': 'example.com', 'name': 'Example'},
          'user': {'id': b64u([1, 2, 3]), 'name': 'alice@example.com', 'displayName': 'Alice'},
          'challenge': 'AAAA',
          'pubKeyCredParams': [
            {'type': 'public-key', 'alg': -8},
            {'type': 'public-key', 'alg': -7},
          ],
          'excludeCredentials': [
            {'type': 'public-key', 'id': 'zz'},
          ],
        }),
        'https://login.example.com');
    expect(r.rpId, 'example.com');
    expect(r.userId, [1, 2, 3]);
    expect(r.userName, 'alice@example.com');
    expect(r.es256, isTrue);
    expect(r.exclude, {'zz'});
    expect(CreateRequest.parse(jsonEncode({'pubKeyCredParams': [{'alg': -257}]}), 'https://a.example').es256, isFalse);
    expect(CreateRequest.parse('{}', 'https://a.example').rpId, 'a.example');
  });

  test('a page may use passkeys of its own site or a parent, over HTTPS', () {
    expect(originMayUse('https://login.example.com', 'example.com'), isTrue);
    expect(originMayUse('https://example.com', 'example.com'), isTrue);
    expect(originMayUse('https://evilexample.com', 'example.com'), isFalse);
    expect(originMayUse('http://example.com', 'example.com'), isFalse);
    expect(originMayUse('http://localhost', 'localhost'), isTrue);
    expect(originMayUse('android:apk-key-hash:abc', 'example.com'), isTrue);
  });

  test('responses carry the agent output in base64url', () {
    final reg = jsonDecode(registrationResponse(cidHex: '0a0b', publicKeyHex: '04${'11' * 64}', authDataHex: '0102', attestationHex: 'a3', clientDataJSON: '{"x":1}'));
    expect(reg['id'], 'Cgs');
    expect(reg['response']['attestationObject'], 'ow');
    expect(reg['response']['publicKeyAlgorithm'], -7);
    expect(unb64u(reg['response']['publicKey'] as String).length, 91);
    expect(utf8.decode(unb64u(reg['response']['clientDataJSON'] as String)), '{"x":1}');
    final get = jsonDecode(assertionResponse(cidHex: '0a0b', authDataHex: '0304', signatureDerHex: '3006', userHandleHex: '010203'));
    expect(get['response']['signature'], 'MAY');
    expect(get['response']['userHandle'], 'AQID');
  });

  group('the passkey screen', () {
    late FakeAgent agent;
    late Settings settings;
    final finished = <String>[];
    var cancelled = 0;
    const channel = MethodChannel('symbolon/passkey');

    setUp(() async {
      agent = await FakeAgent.create();
      settings = Settings(File('${agent.dir.path}/settings.json'), binary: agent.path, deviceDir: '${agent.dir.path}/dev', tutorialSeen: true);
      finished.clear();
      cancelled = 0;
    });
    tearDown(() => agent.dispose());

    Future<void> show(WidgetTester t, Map<String, dynamic> rq) async {
      t.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'finish') finished.add((call.arguments as Map)['json'] as String);
        if (call.method == 'cancel') cancelled++;
        return null;
      });
      t.view.devicePixelRatio = 3;
      t.view.physicalSize = const Size(420, 900) * 3;
      addTearDown(t.view.reset);
      await t.pumpWidget(PasskeyApp(settings: settings, request: rq, channel: channel));
    }

    Future<void> settle(WidgetTester t) async {
      for (var i = 0; i < 20; i++) {
        await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
        await t.pump(const Duration(milliseconds: 50));
      }
    }

    final createRq = {
      'kind': 'create',
      'origin': 'https://login.example.com',
      'browser': true,
      'callingPackage': 'com.android.chrome',
      'clientDataHash': '00' * 32,
      'clientDataJSON': null,
      'requestJson': jsonEncode({
        'rp': {'id': 'example.com'},
        'user': {'id': b64u([7, 7]), 'name': 'alice', 'displayName': 'Alice'},
        'challenge': 'AAAA',
        'pubKeyCredParams': [
          {'type': 'public-key', 'alg': -7},
        ],
      }),
    };

    testWidgets('creating shows the site and the asker, takes the PIN, keeps the passkey and answers', (t) async {
      await show(t, createRq);
      expect(find.text('example.com'), findsOneWidget);
      expect(find.text('https://login.example.com'), findsOneWidget);
      expect(find.text('alice'), findsOneWidget);
      await t.enterText(find.byKey(const Key('pk-pin')), '2468');
      await t.tap(find.byKey(const Key('pk-go')));
      await t.pump();
      await settle(t);
      expect(finished, hasLength(1));
      final j = jsonDecode(finished.single);
      expect(j['response']['attestationObject'], 'ow');
      expect(settings.credentials.single.userHandle, '0707');
      expect(settings.credentials.single.userName, 'alice');
      final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
      expect(args, contains('device webauthn register ${agent.dir.path}/dev example.com --uv'));
    });

    testWidgets('a wrong PIN is reported and nothing is answered', (t) async {
      await show(t, createRq);
      await t.enterText(find.byKey(const Key('pk-pin')), '0000');
      await t.tap(find.byKey(const Key('pk-go')));
      await t.pump();
      await settle(t);
      expect(finished, isEmpty);
      expect(find.text('Wrong PIN.'), findsWidgets);
    });

    testWidgets('a page of another site is refused before the PIN', (t) async {
      await show(t, {...createRq, 'origin': 'https://evil.example.net'});
      expect(find.byKey(const Key('pk-problem')), findsOneWidget);
      expect(find.byKey(const Key('pk-pin')), findsNothing);
      await t.tap(find.text('Close'));
      await t.pump();
      expect(cancelled, 1);
    });

    testWidgets('signing in uses the chosen passkey with the client data hash and returns the user handle', (t) async {
      settings.credentials = [const Credential('example.com', 'cc', '04dd', userName: 'alice', userHandle: '0707')];
      await show(t, {
        'kind': 'get',
        'origin': 'android:apk-key-hash:abc',
        'browser': false,
        'callingPackage': 'com.example.app',
        'clientDataHash': '11' * 32,
        'clientDataJSON': '{"type":"webauthn.get"}',
        'requestJson': '{}',
        'rp': 'example.com',
        'cid': 'cc',
      });
      expect(find.text('the app com.example.app'), findsOneWidget);
      await t.enterText(find.byKey(const Key('pk-pin')), '2468');
      await t.tap(find.byKey(const Key('pk-go')));
      await t.pump();
      await settle(t);
      final j = jsonDecode(finished.single);
      expect(j['response']['signature'], b64u(fromHex('3006020101020101')));
      expect(j['response']['userHandle'], 'Bwc');
      expect(utf8.decode(unb64u(j['response']['clientDataJSON'] as String)), '{"type":"webauthn.get"}');
      final args = (await t.runAsync(() => agent.argsLog.readAsString()))!;
      expect(args, contains('device webauthn assert ${agent.dir.path}/dev example.com cc ${'11' * 32} --uv'));
    });
  });
}
