import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app.dart';
import '../biometric.dart';
import '../validate.dart' as v;
import '../widgets.dart';

class SettingsPage extends StatefulWidget {
  final App app;
  const SettingsPage({super.key, required this.app});

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  late final binary = TextEditingController(text: widget.app.settings.binary);
  late final deviceDir = TextEditingController(text: widget.app.settings.deviceDir);
  late final chromium = TextEditingController(text: widget.app.settings.chromium);
  late int keep = widget.app.settings.keepUnlockedMinutes;
  BioState bio = BioState.none;

  @override
  void initState() {
    super.initState();
    Bio.state().then((b) {
      if (mounted) setState(() => bio = b);
    });
  }

  // Turning fingerprint unlock on keeps the PIN under a biometric-bound key;
  // the PIN is asked once and checked by the agent first.
  Future<void> setBio(bool on) async {
    if (!on) {
      await Bio.forget();
    } else {
      final pin = await askSecret(context, note: 'Your PIN, once, to keep it for fingerprint unlock.');
      if (pin == null || !mounted) return;
      final r = await runTask(context, 'Checking your PIN', () => widget.app.cli.vaultList(widget.app.dir, pin), usually: 'a few seconds');
      if (!r.ok) return;
      await Bio.enroll(pin);
    }
    final b = await Bio.state();
    if (mounted) setState(() => bio = b);
  }

  @override
  void dispose() {
    binary.dispose();
    deviceDir.dispose();
    chromium.dispose();
    super.dispose();
  }

  Future<void> setKeep(int v) async {
    setState(() => keep = v);
    widget.app.session.keepMinutes = v;
    widget.app.session.lock();
    await widget.app.settings.update(keepUnlockedMinutes: v);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: PageBody(children: [
        if (bio.supported && bio.biometric)
          Section('Fingerprint unlock', children: [
            SwitchListTile(
              key: const Key('bio-unlock'),
              contentPadding: EdgeInsets.zero,
              title: const Text('Unlock with your fingerprint or face'),
              subtitle: const Text('Instead of typing your PIN. A new fingerprint on the phone turns this off until you type the PIN again.'),
              value: bio.enrolled,
              onChanged: setBio,
            ),
          ]),
        Section('Stay unlocked', subtitle: 'After you enter your PIN, the app keeps it in memory for a while so that you are not asked for every action. '
            'It always locks when you leave the app.', children: [
          RadioGroup<int>(
            groupValue: keep,
            onChanged: (v) => setKeep(v ?? 5),
            child: const Column(children: [
              RadioListTile(value: 0, title: Text('Ask every time'), contentPadding: EdgeInsets.zero),
              RadioListTile(value: 1, title: Text('1 minute'), contentPadding: EdgeInsets.zero),
              RadioListTile(value: 5, title: Text('5 minutes'), contentPadding: EdgeInsets.zero),
              RadioListTile(value: 15, title: Text('15 minutes'), contentPadding: EdgeInsets.zero),
              RadioListTile(value: -1, title: Text('Until I lock it'), contentPadding: EdgeInsets.zero),
            ]),
          ),
        ]),
        Section('Site icons', children: [
          SwitchListTile(
            key: const Key('site-icons'),
            contentPadding: EdgeInsets.zero,
            title: const Text('Show logins\' site icons'),
            subtitle: const Text('Fetched straight from each site and kept on this device. The site, and anyone watching your network, '
                'can see that the app asked for its icon.'),
            value: widget.app.settings.siteIcons,
            onChanged: (x) async {
              await widget.app.settings.update(siteIcons: x);
              setState(() {});
            },
          ),
        ]),
        Section('Agent', children: [
          Field(binary, 'symbolon binary', fieldKey: const Key('binary'), check: (s) => v.required(s, 'The agent')),
          Field(deviceDir, 'Device directory', fieldKey: const Key('device-dir'), check: (s) => v.required(s, 'The device directory')),
          Field(chromium, 'Chromium (password changes)', action: TextInputAction.done),
          WideButton('Save', key: const Key('save-settings'), onPressed: () async {
            if (binary.text.trim().isEmpty || deviceDir.text.trim().isEmpty) return toast(context, 'The agent and the device directory are required.');
            await widget.app.settings.update(binary: binary.text.trim(), deviceDir: deviceDir.text.trim(), chromium: chromium.text.trim());
            if (context.mounted) toast(context, 'Saved');
          }),
        ]),
        if (kDebugMode && Platform.isAndroid) _SystemPasskeyTest(dir: widget.app.settings.file.parent.path),
        Section('What this app stores', subtitle: widget.app.settings.file.path, children: const [
          Text('The settings above and the public part of your passkeys. Your PIN and secrets are never stored by the app: they go '
              'to the agent and are dropped.'),
        ]),
      ]),
    );
  }
}

/// Debug builds on Android: this app asks the system for a passkey, as a
/// site's app would, so the provider can be tried end to end without a
/// browser. Each response is also written to the app's files directory
/// (selftest-create.json, selftest-get.json).
class _SystemPasskeyTest extends StatelessWidget {
  final String dir;
  const _SystemPasskeyTest({required this.dir});

  static const _ch = MethodChannel('symbolon/platform');
  static String _b64(List<int> b) => base64Url.encode(b).replaceAll('=', '');
  static String _challenge() => _b64(List.generate(32, (_) => Random.secure().nextInt(256)));

  Future<void> _run(BuildContext context, String method, Map<String, dynamic> rq, String file) async {
    try {
      await File('$dir/$file.request.json').writeAsString(jsonEncode(rq));
      final r = await _ch.invokeMethod<String>(method, jsonEncode(rq));
      await File('$dir/$file.json').writeAsString(r ?? '');
      if (context.mounted) await showOutput(context, 'System passkey: $method', r ?? '');
    } on PlatformException catch (e) {
      if (context.mounted) toast(context, '${e.code}: ${e.message}');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Section('Developer: system passkeys', subtitle: 'Debug builds only. Asks Android for a passkey as an app would.', children: [
      WideButton('Create through the system', key: const Key('selftest-create'), tonal: true, onPressed: () => _run(context, 'testCreate', {
            'rp': {'id': 'selftest.symbolon.dev', 'name': 'Symbolon self-test'},
            'user': {'id': _b64(utf8.encode('selftest-user')), 'name': 'selftest@symbolon.dev', 'displayName': 'Self-test'},
            'challenge': _challenge(),
            'pubKeyCredParams': [
              {'type': 'public-key', 'alg': -7},
            ],
            'authenticatorSelection': {'residentKey': 'required', 'userVerification': 'required'},
          }, 'selftest-create')),
      const SizedBox(height: 8),
      WideButton('Sign in through the system', key: const Key('selftest-get'), tonal: true, onPressed: () => _run(context, 'testGet', {
            'rpId': 'selftest.symbolon.dev',
            'challenge': _challenge(),
            'userVerification': 'required',
          }, 'selftest-get')),
    ]);
  }
}
