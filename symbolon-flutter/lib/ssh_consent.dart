// The window the SSH agent opens for each signature (SPEC 16.1):
// `symbolon_ui --ssh-consent REQUEST`. It shows the key, the program asking
// (from the pid the agent read with SO_PEERCRED), what is being signed and
// the server the session is bound to, takes the PIN, signs with `symbolon
// device ssh sign`, and sends back only the signature, on the agent's
// per-request Unix socket after the request's one-time token. The agent
// checks the signature against the key before the client gets it.

import 'brand.dart';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';

import 'cli.dart';
import 'fill_consent.dart' show isBrowserExe;
import 'main.dart' show loadSettings;
import 'settings.dart';
import 'widgets.dart';

class SshRequest {
  final String key, fingerprint, data, socket, token;
  final String alg;                 // rsa-sha2-256 or rsa-sha2-512 for an RSA key, else ''
  final String what;                // auth, sshsig or unknown
  final String user, namespace;
  final String hostKey, hostFingerprint;    // "" when the session is not bound
  final bool forwarding;
  final int pid;
  const SshRequest({required this.key, required this.fingerprint, required this.data, required this.socket, required this.token, required this.what, this.alg = '',
      this.user = '', this.namespace = '', this.hostKey = '', this.hostFingerprint = '', this.forwarding = false, this.pid = 0});

  static SshRequest? parse(String text) {
    try {
      final j = jsonDecode(text) as Map<String, dynamic>;
      final w = j['what'] as Map<String, dynamic>;
      final h = j['host'] as Map<String, dynamic>?;
      return SshRequest(
        key: j['key'] as String, fingerprint: j['fingerprint'] as String, data: j['data'] as String, socket: j['socket'] as String, token: j['token'] as String,
        what: w['kind'] as String, alg: (j['alg'] as String?) ?? '', user: (w['user'] as String?) ?? '', namespace: (w['namespace'] as String?) ?? '',
        hostKey: (h?['key'] as String?) ?? '', hostFingerprint: (h?['fingerprint'] as String?) ?? '', forwarding: h?['forwarding'] == true,
        pid: (j['pid'] as int?) ?? 0,
      );
    } catch (_) {
      return null;
    }
  }

  /// What is being signed, in words.
  String get action => switch (what) {
        'auth' => 'Sign in as $user',
        'sshsig' => switch (namespace) {
            'git' => 'Sign a git commit or tag',
            'file' => 'Sign a file',
            _ => 'Sign data for "$namespace"',
          },
        _ => 'Sign data Symbolon does not recognize',
      };
}

/// The program that connected: its executable and command line, from /proc.
({String exe, String cmdline}) callerOfPid(int pid) {
  if (pid <= 0) return (exe: '', cmdline: '');
  String exe = '', cmd = '';
  try {
    exe = Link('/proc/$pid/exe').targetSync();
  } catch (_) {}
  try {
    cmd = File('/proc/$pid/cmdline').readAsBytesSync().map((b) => b == 0 ? 32 : b).toList().let((b) => utf8.decode(b, allowMalformed: true).trim());
  } catch (_) {}
  return (exe: exe, cmdline: cmd);
}

extension _Let<T> on T {
  R let<R>(R Function(T) f) => f(this);
}

/// The names ~/.ssh/known_hosts gives [keyB64]: plain entries by name;
/// hashed ones (|1|salt|hash) when one of [candidates] matches.
List<String> knownNames(String keyB64, String knownHosts, List<String> candidates) {
  final out = <String>[];
  for (final l in knownHosts.split('\n')) {
    final p = l.trim().split(RegExp(r'\s+'));
    if (p.length < 3 || p[0].startsWith('#') || p[0].startsWith('@')) continue;
    if (p[2] != keyB64) continue;
    for (final n in p[0].split(',')) {
      if (n.startsWith('|1|')) {
        final h = n.split('|');
        if (h.length != 4) continue;
        try {
          final mac = Hmac(sha1, base64.decode(h[2]));
          for (final c in candidates) {
            if (base64.encode(mac.convert(utf8.encode(c)).bytes) == h[3]) out.add(c);
          }
        } catch (_) {}
      } else {
        out.add(n);
      }
    }
  }
  return {...out}.toList();
}

/// Words of a command line that could be host names (for hashed entries).
List<String> hostCandidates(String cmdline) {
  final out = <String>[];
  for (final w in cmdline.split(' ')) {
    final h = w.contains('@') ? w.substring(w.lastIndexOf('@') + 1) : w;
    if (RegExp(r'^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$').hasMatch(h) || RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(h)) out.add(h);
  }
  return out;
}

abstract class SshLink {
  void Function()? lost;
  Future<bool> open(String socket, String token);
  Future<void> send(String line);
}

class UnixSshLink extends SshLink {
  Socket? _s;

  @override
  Future<bool> open(String socket, String token) async {
    try {
      final s = await Socket.connect(InternetAddress(socket, type: InternetAddressType.unix), 0, timeout: const Duration(seconds: 5));
      _s = s;
      s.write('$token\n');
      await s.flush();
      s.listen((_) {}, onDone: () => lost?.call(), onError: (_) => lost?.call(), cancelOnError: true);
      return true;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<void> send(String line) async {
    final s = _s;
    if (s == null) return;
    s.write(line);
    await s.flush();
    await s.close();
  }
}

Future<void> runSshConsent(String path) async {
  WidgetsFlutterBinding.ensureInitialized();
  final settings = await loadSettings();
  String text = '';
  try {
    text = await File(path).readAsString();
  } catch (_) {}
  String known = '';
  try {
    known = await File('${Platform.environment['HOME']}/.ssh/known_hosts').readAsString();
  } catch (_) {}
  final req = SshRequest.parse(text);
  runApp(SshConsentApp(settings: settings, request: req, link: UnixSshLink(), knownHosts: known, caller: callerOfPid(req?.pid ?? 0), done: () => exit(0)));
}

class SshConsentApp extends StatelessWidget {
  final Settings settings;
  final SshRequest? request;
  final SshLink link;
  final String knownHosts;
  final ({String exe, String cmdline}) caller;
  final void Function() done;
  const SshConsentApp({super.key, required this.settings, required this.request, required this.link, required this.knownHosts, required this.caller, required this.done});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Symbolon: SSH signature',
      debugShowCheckedModeBanner: false,
      theme: Brand.theme(Brightness.light),
      darkTheme: Brand.theme(Brightness.dark),
      home: SshConsentPage(app: this),
    );
  }
}

class SshConsentPage extends StatefulWidget {
  final SshConsentApp app;
  const SshConsentPage({super.key, required this.app});

  @override
  State<SshConsentPage> createState() => _SshConsentPageState();
}

class _SshConsentPageState extends State<SshConsentPage> {
  final pin = TextEditingController();
  String? error;
  bool busy = false;
  bool connected = false;
  bool expired = false;

  SshConsentApp get a => widget.app;
  SshRequest? get rq => a.request;
  SymbolonCli get cli => SymbolonCli(a.settings.binary, env: a.settings.agentEnv);

  @override
  void initState() {
    super.initState();
    final r = rq;
    if (r == null) return;
    a.link.lost = () {
      if (mounted) setState(() => expired = true);
    };
    a.link.open(r.socket, r.token).then((ok) {
      if (mounted) setState(() => ok ? connected = true : expired = true);
    });
  }

  @override
  void dispose() {
    pin.dispose();
    super.dispose();
  }

  Future<void> sign() async {
    final r = rq;
    if (r == null || pin.text.isEmpty || busy || expired) return;
    setState(() {
      busy = true;
      error = null;
    });
    final res = await cli.sshSign(a.settings.deviceDir, r.key, r.data, pin.text, alg: r.alg);
    pin.clear();
    if (!mounted) return;
    final sig = res.lines.where((l) => l.startsWith('signature ')).map((l) => l.substring(10).trim()).firstOrNull;
    if (!res.ok || sig == null) {
      setState(() {
        busy = false;
        error = friendlyError(res);
      });
      return;
    }
    await _answer('ok $sig\n');
  }

  Future<void> cancel() => _answer('cancel\n');

  Future<void> _answer(String line) async {
    if (rq != null && !expired) {
      try {
        await a.link.send(line);
      } catch (_) {}
    }
    a.done();
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final scheme = Theme.of(context).colorScheme;
    final r = rq;
    final c = a.caller;
    final names = r == null || r.hostKey.isEmpty ? <String>[] : knownNames(r.hostKey, a.knownHosts, hostCandidates(c.cmdline));
    final exeName = c.exe.isEmpty ? 'An unknown program' : c.exe.split('/').last;
    return Scaffold(
      body: PageBody(children: [
        const SizedBox(height: 16),
        Icon(Icons.key, size: 48, color: scheme.primary),
        const SizedBox(height: 12),
        Text(r == null ? 'SSH signature' : r.action, key: const Key('sc-action'), style: t.headlineSmall, textAlign: TextAlign.center),
        const SizedBox(height: 16),
        if (r == null) ...[
          const Text('The request could not be read.', key: Key('sc-problem')),
          const SizedBox(height: 16),
          WideButton('Close', onPressed: a.done),
        ] else ...[
          Card(
            child: Column(children: [
              ListTile(key: const Key('sc-key'), leading: const Icon(Icons.vpn_key_outlined), title: Text(r.key), subtitle: Text(r.fingerprint)),
              ListTile(
                key: const Key('sc-caller'),
                leading: const Icon(Icons.terminal),
                title: Text(exeName),
                subtitle: Text(c.cmdline.isEmpty ? 'Asked by process ${r.pid}' : c.cmdline, maxLines: 3, overflow: TextOverflow.ellipsis),
              ),
              if (r.hostFingerprint.isNotEmpty)
                ListTile(
                  key: const Key('sc-host'),
                  // A server ssh has not met before: the moment a stranger in the
                  // middle would show up, so it is marked.
                  leading: Icon(names.isEmpty ? Icons.gpp_maybe_outlined : Icons.dns_outlined, color: names.isEmpty ? Colors.orange : null),
                  title: Text(names.isEmpty ? 'A server not in your known_hosts' : names.join(', ')),
                  subtitle: Text(names.isEmpty
                      ? 'First connection to this server, or its key changed. Check the key before you sign: ${r.hostFingerprint}'
                      : 'Server key ${r.hostFingerprint}'),
                ),
              if (r.what == 'auth' && r.hostFingerprint.isEmpty)
                const ListTile(key: Key('sc-unbound'), leading: Icon(Icons.help_outline), title: Text('Server not identified'), subtitle: Text('This SSH client did not tell the agent which server it is talking to.')),
            ]),
          ),
          if (r.forwarding)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text('This request comes through a forwarded agent: a server you are logged in to is asking. Approve only if you started this.',
                  key: const Key('sc-forwarded'), style: TextStyle(color: scheme.error)),
            ),
          if (r.what == 'unknown')
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text('Symbolon cannot tell what this signature is for.', key: const Key('sc-unknown'), style: TextStyle(color: scheme.error)),
            ),
          if (c.exe.isNotEmpty && isBrowserExe(c.exe))
            Padding(padding: const EdgeInsets.only(top: 8), child: Text('A web browser is asking for an SSH signature.', style: TextStyle(color: scheme.error))),
          const SizedBox(height: 16),
          if (error != null) Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(error!, style: TextStyle(color: scheme.error))),
          if (expired) ...[
            Text('This request has expired.', key: const Key('sc-expired'), style: TextStyle(color: scheme.error)),
            const SizedBox(height: 16),
            WideButton('Close', onPressed: a.done),
          ] else ...[
            Field(pin, 'Your Symbolon PIN', obscure: true, numeric: true, fieldKey: const Key('sc-pin'), action: TextInputAction.done),
            WideButton('Sign', key: const Key('sc-sign'), icon: Icons.check, onPressed: busy || !connected ? null : sign),
            const SizedBox(height: 8),
            TextButton(key: const Key('sc-cancel'), onPressed: busy ? null : cancel, child: const Text('Cancel')),
          ],
        ],
      ]),
    );
  }
}
