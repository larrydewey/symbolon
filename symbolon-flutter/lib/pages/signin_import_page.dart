import 'package:material_ui/material_ui.dart';

import '../app.dart';
import '../breach.dart';
import '../cli.dart';
import '../settings.dart';
import '../vault_types.dart';
import '../widgets.dart';
import 'import_page.dart';

/// Moving in from Bitwarden or Vaultwarden (or, experimentally, LastPass)
/// by signing in, with no export file (`symbolon device vault
/// signin-bitwarden`, `signin-lastpass`): the agent signs in,
/// downloads the encrypted vault and opens it on this device; nothing of it
/// is written down unencrypted. Pops true when items were imported.
class SignInImportPage extends StatefulWidget {
  final App app;
  final String share;
  final bool lastpass;
  const SignInImportPage({super.key, required this.app, this.share = '', this.lastpass = false});

  @override
  State<SignInImportPage> createState() => _SignInImportPageState();
}

enum _Step { form, busy, code, preview, done }

// Two-step methods the agent can answer, by Bitwarden's provider number.
const _methods = {
  '0': 'Authenticator app',
  '1': 'Email',
  '3': 'YubiKey (OTP)',
  '8': 'Recovery code',
};

class _SignInImportPageState extends State<SignInImportPage> {
  final url = TextEditingController();
  final email = TextEditingController();
  final password = TextEditingController();
  final code = TextEditingController();
  String server = 'bitwarden.com';
  _Step step = _Step.form;
  String busy = '';
  String? error;
  List<String> methods = [];
  String method = '0';
  bool newDevice = false;
  String lpKind = '';            // LastPass: the authenticator a code is from
  ImportPreview? preview;
  int imported = 0;
  AgentConversation? conv;

  App get app => widget.app;

  @override
  void dispose() {
    final c = conv;
    if (c != null) {
      c.send('cancel');
      c.close();
    }
    for (final t in [url, email, password, code]) {
      t.dispose();
    }
    super.dispose();
  }

  String get _server => server == 'self' ? url.text.trim() : server;

  Future<void> start() async {
    if (email.text.trim().isEmpty || password.text.isEmpty) {
      return setState(() => error = 'Enter your email and master password.');
    }
    if (!widget.lastpass && server == 'self' && !url.text.trim().startsWith('https://')) {
      return setState(
        () => error = 'Enter your server\'s address, starting with https://',
      );
    }
    setState(() {
      error = null;
      step = _Step.busy;
      busy = 'Signing in';
    });
    final Map<String, String> env;
    try {
      env = await breachEnv(app.settings);
    } on StateError catch (e) {
      return _stop(e.message);
    }
    final c = widget.lastpass ? await app.cli.signinLastpass(app.dir, share: widget.share, extraEnv: env) : await app.cli.signinBitwarden(
      app.dir,
      _server,
      share: widget.share,
      extraEnv: env,
    );
    if (c == null) return _stop('Symbolon\'s agent did not start.');
    conv = c;
    c.send(email.text.trim());
    c.send(password.text);
    password.clear();
    await _pump();
  }

  // Reads what the agent says until it needs something or is ready.
  Future<void> _pump() async {
    final c = conv;
    if (c == null) return;
    final lines = <String>[];
    while (true) {
      final l = await c.next();
      if (!mounted) return;
      if (l == null) {
        final why = c.errors.trim().split('\n').last;
        return _stop(
          why.isEmpty
              ? 'The sign-in stopped.'
              : why.replaceFirst('device: ', ''),
        );
      }
      final f = l.trim().split(' ');
      if (f.length >= 3 && f[0] == 'need' && f[1] == '2fa') {
        final offered = f[2].split(',').where(_methods.containsKey).toList();
        if (offered.isEmpty) {
          return _stop(
            'Your account\'s two-step login (Duo or a security key) cannot be used here yet. '
            'Add an authenticator app or email as a second method in Bitwarden, or import an export file.',
          );
        }
        return setState(() {
          methods = offered;
          if (!offered.contains(method)) method = offered.first;
          newDevice = false;
          step = _Step.code;
        });
      }
      // LastPass: a code from the named authenticator, or an approval on
      // another device that the agent waits for itself.
      if (f.length >= 3 && f[0] == 'need' && f[1] == 'code') {
        return setState(() {
          lpKind = f[2];
          newDevice = false;
          step = _Step.code;
        });
      }
      if (f.length >= 3 && f[0] == 'wait' && f[1] == 'push') {
        final who = f[2] == '-' ? 'your authenticator app' : _unhexOr(f[2]);
        setState(() {
          step = _Step.busy;
          busy = 'Approve the sign-in in $who on your phone';
        });
        continue;
      }
      if (f.length >= 2 && f[0] == 'need' && f[1] == 'newdevice') {
        return setState(() {
          newDevice = true;
          step = _Step.code;
        });
      }
      if (f.length >= 2 && f[0] == 'fail') return _stop(_unhexOr(f[1]));
      if (f[0] == 'ready') {
        return setState(() {
          preview = ImportPreview.parse(lines);
          step = _Step.preview;
        });
      }
      lines.add(l);
      if (lines.length == 1) {
        setState(() => busy = 'Opening your vault on this device');
      }
    }
  }

  String _unhexOr(String h) {
    try {
      return unhex(h);
    } on FormatException {
      return h;
    }
  }

  Future<void> _stop(String why) async {
    final c = conv;
    conv = null;
    if (c != null) await c.close();
    if (!mounted) return;
    setState(() {
      error = why;
      step = _Step.form;
    });
  }

  Future<void> sendCode() async {
    final v = code.text.replaceAll(' ', '');
    if (v.isEmpty) return;
    code.clear();
    setState(() {
      step = _Step.busy;
      busy = 'Checking the code';
    });
    conv?.send(lpKind.isNotEmpty ? 'code $lpKind $v' : newDevice ? 'code 0 $v' : 'code $method $v');
    await _pump();
  }

  Future<void> emailMe() async {
    setState(() {
      step = _Step.busy;
      busy = 'Asking for an email';
    });
    conv?.send('send-email');
    await _pump();
  }

  Future<void> importNow() async {
    final p = preview;
    if (p == null || p.items.isEmpty) return;
    final passkeys =
        widget.share.isEmpty && p.items.any((i) => i.type == 'passkey');
    var sent = false;
    final r = await app.withPin(
      context,
      (pin) => runTask(context, 'Importing ${p.items.length} items', () async {
        final c = conv;
        // The agent reads the PIN once; a second try needs a new sign-in.
        if (c == null || sent) {
          return const CliResult(
            1,
            '',
            'device: the sign-in ended: sign in again',
          );
        }
        sent = true;
        c.send('import');
        c.send(pin);
        final out = <String>[];
        for (
          String? l = await c.next(timeout: const Duration(minutes: 15));
          l != null;
          l = await c.next(timeout: const Duration(minutes: 15))
        ) {
          out.add(l);
        }
        final code = await c.close();
        conv = null;
        final res = CliResult(code, out.join('\n'), c.errors);
        if (res.ok && passkeys) {
          final s = await app.cli.waSynced(app.dir, pin);
          if (s.ok) {
            await app.settings.setSynced(Credential.syncedFrom(s.lines));
          }
        }
        return res;
      }, usually: 'under a minute'),
    );
    if (!mounted || r == null) return;
    if (!r.ok) return _stop(friendlyError(r));
    final total =
        r.lines
            .map((l) => l.trim())
            .where((l) => l.startsWith('total '))
            .map((l) => int.tryParse(l.substring(6)) ?? 0)
            .firstOrNull ??
        p.items.length;
    setState(() {
      imported = total;
      step = _Step.done;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.lastpass ? 'Sign in to LastPass' : 'Sign in to Bitwarden')),
      body: PageBody(
        children: switch (step) {
          _Step.form => _form(),
          _Step.busy => [
            Section(
              busy,
              children: const [
                LinearProgressIndicator(),
                SizedBox(height: 12),
                Text('Keep Symbolon open; this takes a few seconds.'),
              ],
            ),
          ],
          _Step.code => _code(),
          _Step.preview => [
            ...importPreviewView(context, preview!),
            if (preview!.items.isNotEmpty)
              WideButton(
                'Import ${preview!.items.length} item${preview!.items.length == 1 ? '' : 's'}',
                key: const Key('signin-import-go'),
                icon: Icons.move_to_inbox,
                onPressed: importNow,
              ),
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('Cancel'),
            ),
          ],
          _Step.done => [
            Section(
              '$imported item${imported == 1 ? '' : 's'} imported',
              key: const Key('signin-import-done'),
              children: [
                const ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(Icons.check_circle, color: Colors.green),
                  title: Text('Your vault has them now, on every device.'),
                ),
                const SizedBox(height: 8),
                const Text(
                  'Nothing was saved unencrypted. Once you have checked your vault, you can close the old account.',
                ),
                const SizedBox(height: 16),
                WideButton(
                  'Done',
                  icon: Icons.check,
                  onPressed: () => Navigator.of(context).pop(true),
                ),
              ],
            ),
          ],
        },
      ),
    );
  }

  List<Widget> _form() => [
    Section(
      widget.lastpass ? 'Your LastPass account' : 'Your Bitwarden account',
      children: [
        const Text(
          'Symbolon signs in, downloads your encrypted vault and opens it on this device. Your master password is used '
          'once and not kept; nothing is saved unencrypted.',
        ),
        if (widget.lastpass) ...[
          const SizedBox(height: 12),
          const ImportWarning(
            'Experimental: LastPass offers no supported way for other apps to sign in, so Symbolon speaks the protocol of '
            'LastPass\'s own command-line tool. If it stops working, export a CSV from LastPass instead.',
          ),
        ],
        const SizedBox(height: 12),
        if (!widget.lastpass) SegmentedButton<String>(
          key: const Key('signin-server'),
          segments: const [
            ButtonSegment(value: 'bitwarden.com', label: Text('bitwarden.com')),
            ButtonSegment(value: 'bitwarden.eu', label: Text('bitwarden.eu')),
            ButtonSegment(value: 'self', label: Text('Self-hosted')),
          ],
          selected: {server},
          onSelectionChanged: (s) => setState(() => server = s.first),
        ),
        const SizedBox(height: 12),
        if (!widget.lastpass && server == 'self')
          Field(
            url,
            'Server address',
            hint: 'https://vault.example.com',
            url: true,
            fieldKey: const Key('signin-url'),
          ),
        Field(email, 'Email', fieldKey: const Key('signin-email')),
        Field(
          password,
          'Master password',
          obscure: true,
          fieldKey: const Key('signin-password'),
          action: TextInputAction.done,
          onSubmitted: (_) => start(),
        ),
        if (error != null) ImportWarning(error!),
        WideButton(
          'Sign in',
          key: const Key('signin-go'),
          icon: Icons.login,
          onPressed: start,
        ),
      ],
    ),
  ];

  List<Widget> _code() => [
    Section(
      newDevice ? 'Check your email' : 'Two-step login',
      children: [
        Text(
          lpKind.isNotEmpty
              ? 'Enter the code from ${const {'google': 'Google Authenticator', 'microsoft': 'Microsoft Authenticator', 'yubikey': 'your YubiKey', 'sesame': 'LastPass Sesame'}[lpKind] ?? 'your authenticator app'}.'
              : newDevice
              ? 'Bitwarden emailed a code to confirm this new device. Enter it here.'
              : method == '1'
              ? 'Enter the code Bitwarden emailed you.'
              : method == '8'
              ? 'Enter your recovery code. Bitwarden turns off two-step login when it is used.'
              : 'Enter the code from your ${_methods[method]?.toLowerCase()}.',
        ),
        const SizedBox(height: 12),
        if (lpKind.isEmpty && !newDevice && methods.length > 1)
          Wrap(
            spacing: 8,
            children: [
              for (final m in methods)
                ChoiceChip(
                  label: Text(_methods[m]!),
                  selected: m == method,
                  onSelected: (_) => setState(() => method = m),
                ),
            ],
          ),
        const SizedBox(height: 8),
        Field(
          code,
          'Code',
          fieldKey: const Key('signin-code'),
          action: TextInputAction.done,
          onSubmitted: (_) => sendCode(),
        ),
        WideButton(
          'Continue',
          key: const Key('signin-code-go'),
          icon: Icons.arrow_forward,
          onPressed: sendCode,
        ),
        if (lpKind.isEmpty && !newDevice && method == '1')
          TextButton(onPressed: emailMe, child: const Text('Email me a code')),
      ],
    ),
  ];
}
