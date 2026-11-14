// The window the agent opens when the browser extension asks for a fill
// (SPEC 22.2, 22.5): `symbolon_ui --fill-consent REQUEST`. It is outside the
// page, so a page cannot draw over it or click it. It shows the page's
// origin as the browser reported it and every other frame that would
// receive a field, takes the PIN, lets the person choose a login for that
// site or a card, and sends that item's fields to the agent's native
// messaging host over the loopback connection named in the request (the
// answer opens with the request's one-time token). The host checks the
// item against the page again before anything reaches the browser.

import 'brand.dart';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

import 'cli.dart';
import 'main.dart' show loadSettings;
import 'settings.dart';
import 'vault_types.dart';
import 'widgets.dart';

/// The fields each type may send; the host filters again.
const _sent = {
  'login': ['origin', 'username', 'current'],
  'card': ['cardholder', 'number', 'expiry', 'cvv'],
};

/// Whether a login saved for [saved] may fill the page at [top], as the
/// agent decides (SPEC 22.5 step 6): the same origin, or a subdomain of the
/// saved host with the same scheme and port; a leading "www." of the saved
/// host is dropped first. A saved host with no dot, or an IP address,
/// matches only itself.
bool siteCovers(String saved, String top) {
  if (saved == top) return true;
  final a = Uri.tryParse(saved), b = Uri.tryParse(top);
  if (a == null || b == null || a.scheme != b.scheme || a.port != b.port) return false;
  if (a.hasPort != b.hasPort || a.path.isNotEmpty || b.path.isNotEmpty) return false;
  final s = a.host.startsWith('www.') ? a.host.substring(4) : a.host;
  if (!s.contains('.') || RegExp(r'^[0-9.]+$').hasMatch(s)) return false;
  return b.host == s || b.host.endsWith('.$s');
}

class FillRequest {
  final String top;
  final String want;            // "login" or "card"
  final int port;
  final String token;
  final List<({String origin, List<String> fields})> frames;
  const FillRequest(this.top, this.want, this.port, this.token, this.frames);

  static FillRequest? parse(String text) {
    try {
      final j = jsonDecode(text) as Map<String, dynamic>;
      return FillRequest(j['top'] as String, j['want'] as String, j['port'] as int, j['token'] as String, [
        for (final f in j['frames'] as List)
          (origin: (f as Map)['origin'] as String, fields: [for (final k in f['fields'] as List) k as String]),
      ]);
    } catch (_) {
      return null;
    }
  }

  String get host => Uri.tryParse(top)?.host ?? top;

  /// Frames of another origin (a payment processor's card fields).
  List<String> get otherOrigins => {for (final f in frames) if (f.origin != top) f.origin}.toList();
}

/// What follows the token line (sent when the window opened): "cancel" or
/// "ok TYPE", the fields as "NAME HEX", and "end".
String fillAnswer(String? type, Map<String, String> fields) {
  if (type == null) return 'cancel\n';
  final keep = _sent[type] ?? const [];
  final b = StringBuffer('ok $type\n');
  for (final k in keep) {
    final v = fields[k];
    if (v != null && v.isNotEmpty) b.write('$k ${hexOf(v)}\n');
  }
  b.write('end\n');
  return b.toString();
}

/// The connection to the agent's host. [open] connects and sends the token
/// as the window opens; it returns the program that started the host, ""
/// when that is not known, or null when the host is gone. [lost] is called
/// if the host gives up (then nothing may be sent).
abstract class FillLink {
  void Function()? lost;
  Future<String?> open(String token, int port);
  Future<void> send(String body);
}

class SocketLink extends FillLink {
  Socket? _s;

  @override
  Future<String?> open(String token, int port) async {
    try {
      final s = await Socket.connect(InternetAddress.loopbackIPv4, port, timeout: const Duration(seconds: 5));
      _s = s;
      s.write('$token\n');
      await s.flush();
      s.listen((_) {}, onDone: () => lost?.call(), onError: (_) => lost?.call(), cancelOnError: true);
    } catch (_) {
      return null;
    }
    return callerOf(port) ?? '';
  }

  @override
  Future<void> send(String body) async {
    final s = _s;
    if (s == null) return;
    s.write(body);
    await s.flush();
    await s.close();
  }
}

/// The executable of the process that started the one listening on
/// 127.0.0.1:[port] (the host): normally the browser. Read from /proc, so
/// whoever ran the host cannot choose what is shown. Null if not found.
String? callerOf(int port) {
  try {
    final want = '0100007F:${port.toRadixString(16).toUpperCase().padLeft(4, '0')}';
    String? inode;
    for (final l in File('/proc/net/tcp').readAsLinesSync().skip(1)) {
      final f = l.trim().split(RegExp(r'\s+'));
      if (f.length > 9 && f[1] == want && f[3] == '0A') inode = f[9];
    }
    if (inode == null) return null;
    final target = 'socket:[$inode]';
    for (final p in Directory('/proc').listSync()) {
      final pid = p.path.split('/').last;
      if (int.tryParse(pid) == null) continue;
      try {
        for (final fd in Directory('${p.path}/fd').listSync()) {
          if (fd is Link && fd.targetSync() == target) {
            final stat = File('${p.path}/stat').readAsStringSync();
            final ppid = stat.substring(stat.lastIndexOf(')') + 2).split(' ')[1];
            return Link('/proc/$ppid/exe').targetSync();
          }
        }
      } catch (_) {}
    }
  } catch (_) {}
  return null;
}

/// Whether [exe] is one of the browsers the extension runs in.
bool isBrowserExe(String exe) => RegExp(r'(chromium|chrome|brave|firefox|msedge|vivaldi|opera)[^/]*$').hasMatch(exe);

Future<void> runFillConsent(String path) async {
  WidgetsFlutterBinding.ensureInitialized();
  final settings = await loadSettings();
  String text = '';
  try {
    text = await File(path).readAsString();
  } catch (_) {}
  final req = FillRequest.parse(text);
  runApp(FillConsentApp(settings: settings, request: req, link: SocketLink(), done: () => exit(0)));
}

class FillConsentApp extends StatelessWidget {
  final Settings settings;
  final FillRequest? request;
  final FillLink link;
  final void Function() done;
  const FillConsentApp({super.key, required this.settings, required this.request, required this.link, required this.done});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Symbolon: fill request',
      debugShowCheckedModeBanner: false,
      theme: Brand.theme(Brightness.light),
      darkTheme: Brand.theme(Brightness.dark),
      home: FillConsentPage(settings: settings, request: request, link: link, done: done),
    );
  }
}

class FillConsentPage extends StatefulWidget {
  final Settings settings;
  final FillRequest? request;
  final FillLink link;
  final void Function() done;
  const FillConsentPage({super.key, required this.settings, required this.request, required this.link, required this.done});

  @override
  State<FillConsentPage> createState() => _FillConsentPageState();
}

class _FillConsentPageState extends State<FillConsentPage> {
  final pin = TextEditingController();
  String? error;
  bool busy = false;
  String? unlocked;             // the PIN, once the vault opened with it
  List<VaultItem>? items;
  String? chosen;
  String? caller;               // the program that asked; null until connected
  bool expired = false;         // the host is gone: nothing may be sent

  @override
  void initState() {
    super.initState();
    final r = widget.request;
    if (r == null) return;
    widget.link.lost = () {
      if (mounted) setState(() => expired = true);
    };
    widget.link.open(r.token, r.port).then((c) {
      if (!mounted) return;
      setState(() => c == null ? expired = true : caller = c);
    });
  }

  FillRequest? get rq => widget.request;
  SymbolonCli get cli => SymbolonCli(widget.settings.binary, env: widget.settings.agentEnv);
  String get dir => widget.settings.deviceDir;

  @override
  void dispose() {
    pin.dispose();
    super.dispose();
  }

  bool _fits(VaultItem it) {
    final r = rq!;
    if (it.type != r.want) return false;
    return r.want == 'card' || siteCovers(it.detail, r.top);
  }

  Future<void> unlock() async {
    if (pin.text.isEmpty || busy) return;
    setState(() {
      busy = true;
      error = null;
    });
    final p = pin.text;
    final r = await cli.vaultList(dir, p);
    if (!mounted) return;
    if (!r.ok) {
      setState(() {
        busy = false;
        error = friendlyError(r);
      });
      return;
    }
    final found = [for (final l in r.lines) VaultItem.parse(l)].whereType<VaultItem>().where(_fits).toList()..sort((a, b) => a.name.compareTo(b.name));
    pin.clear();
    setState(() {
      busy = false;
      unlocked = p;
      items = found;
      chosen = found.length == 1 ? found.first.name : null;
    });
  }

  Future<void> fill() async {
    final name = chosen, p = unlocked;
    if (name == null || p == null || busy || expired) return;
    setState(() {
      busy = true;
      error = null;
    });
    final r = await cli.vaultShow(dir, name, p);
    if (!mounted) return;
    if (!r.ok) {
      setState(() {
        busy = false;
        error = friendlyError(r);
      });
      return;
    }
    final fields = {
      for (final l in r.lines)
        if (l.contains(' ')) l.substring(0, l.indexOf(' ')): unhex(l.substring(l.indexOf(' ') + 1).trim()),
    };
    unlocked = null;
    await _answer(rq!.want, fields);
  }

  Future<void> cancel() => _answer(null, const {});

  Future<void> _answer(String? type, Map<String, String> fields) async {
    if (rq != null && !expired) {
      try {
        await widget.link.send(fillAnswer(type, fields));
      } catch (_) {}
    }
    widget.done();
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final r = rq;
    final scheme = Theme.of(context).colorScheme;
    return Scaffold(
      body: PageBody(children: [
        const SizedBox(height: 16),
        Icon(Icons.shield_outlined, size: 48, color: scheme.primary),
        const SizedBox(height: 12),
        Text(r == null ? 'Fill request' : (r.want == 'card' ? 'Fill a card' : 'Fill a login'), style: t.headlineSmall, textAlign: TextAlign.center),
        const SizedBox(height: 16),
        if (r == null) ...[
          const Text('The request could not be read.', key: Key('fc-problem')),
          const SizedBox(height: 16),
          WideButton('Close', onPressed: widget.done),
        ] else ...[
          Card(
            child: Column(children: [
              ListTile(
                key: const Key('fc-site'),
                leading: const Icon(Icons.language),
                title: Text(r.host, style: const TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text('The page at ${r.top}'),
              ),
              if (caller != null)
                ListTile(
                  key: const Key('fc-caller'),
                  leading: Icon(isBrowserExe(caller!) ? Icons.web : Icons.warning_amber, color: isBrowserExe(caller!) ? null : scheme.error),
                  title: Text(caller!.isEmpty ? 'An unknown program' : caller!.split('/').last),
                  subtitle: Text(isBrowserExe(caller!) ? 'Asked by $caller' : 'This is not a browser. Do not go on unless you started it yourself.',
                      style: isBrowserExe(caller!) ? null : TextStyle(color: scheme.error)),
                ),
              for (final o in r.otherOrigins)
                ListTile(
                  key: Key('fc-frame-$o'),
                  leading: const Icon(Icons.credit_card),
                  title: Text(Uri.tryParse(o)?.host ?? o),
                  subtitle: const Text('Card fields in a payment processor\'s frame on that page'),
                ),
            ]),
          ),
          const SizedBox(height: 8),
          Text('Check the site before you go on. Only fields on this page and its payment frame are filled.', style: t.bodySmall),
          const SizedBox(height: 16),
          if (error != null) Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(error!, style: TextStyle(color: scheme.error))),
          if (expired) ...[
            Text('This request has expired. Ask again from the browser.', key: const Key('fc-expired'), style: TextStyle(color: scheme.error)),
            const SizedBox(height: 16),
            WideButton('Close', onPressed: widget.done),
          ] else if (items == null) ...[
            Field(pin, 'Your Symbolon PIN', obscure: true, numeric: true, fieldKey: const Key('fc-pin'), action: TextInputAction.done),
            WideButton('Unlock', key: const Key('fc-unlock'), icon: Icons.lock_open, onPressed: busy ? null : unlock),
          ] else if (items!.isEmpty) ...[
            Text(r.want == 'card' ? 'There is no card in your vault.' : 'There is no login for ${r.top} in your vault.', key: const Key('fc-none')),
          ] else ...[
            for (final it in items!) _choice(it),
            const SizedBox(height: 8),
            WideButton('Fill', key: const Key('fc-fill'), icon: Icons.check, onPressed: busy || chosen == null ? null : fill),
          ],
          if (!expired) ...[
            const SizedBox(height: 8),
            TextButton(key: const Key('fc-cancel'), onPressed: busy ? null : cancel, child: const Text('Cancel')),
          ],
        ],
      ]),
    );
  }

  Widget _choice(VaultItem it) {
    final selected = chosen == it.name;
    final card = it.type == 'card';
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: InkWell(
        key: Key('fc-item-${it.name}'),
        borderRadius: BorderRadius.circular(16),
        onTap: () => setState(() => chosen = it.name),
        child: Container(
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: selected ? Theme.of(context).colorScheme.primary : Colors.transparent, width: 3),
          ),
          padding: const EdgeInsets.all(3),
          child: ListTile(
            leading: Icon(card ? Icons.credit_card : Icons.person_outline),
            title: Text(it.name),
            subtitle: Text(card ? (it.detail.isEmpty ? 'Card' : '•••• ${it.detail}') : it.detail),
          ),
        ),
      ),
    );
  }
}
