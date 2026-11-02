import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app.dart';
import '../vault_types.dart';
import '../widgets.dart';
import 'vault_page.dart' show TypeAvatar;

/// One SSH key as the agent lists it (no PIN): its name and public line.
class SshKey {
  final String name;
  final String line;
  const SshKey(this.name, this.line);

  /// "NAME-HEX PUBLIC-LINE"; null for anything else.
  static SshKey? parse(String l) {
    final i = l.indexOf(' ');
    if (i <= 0) return null;
    try {
      return SshKey(unhex(l.substring(0, i)), l.substring(i + 1).trim());
    } catch (_) {
      return null;
    }
  }

  String get algorithm => line.split(' ').first;
  bool get threshold => algorithm == 'ecdsa-sha2-nistp256' && line.split(' ').length >= 3 && line.split(' ')[2] == name;
}

/// The systemd user unit that runs the agent at login (SPEC 16.1).
String sshAgentUnit(String agent, String dir, String app) => '''[Unit]
Description=Symbolon SSH agent

[Service]
Environment=SYMBOLON_CONSENT=$app
ExecStart=$agent ssh-agent $dir
Restart=on-failure

[Install]
WantedBy=default.target
''';

const sshAuthSock = r'export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/symbolon/ssh-agent.sock"';

/// SSH keys: threshold keys made by the quorum and keys imported from
/// OpenSSH files, used through the Symbolon SSH agent.
class SshPage extends StatefulWidget {
  final App app;
  /// Installs and starts the agent's unit; replaced in tests.
  final Future<String?> Function(String unit)? installAgent;
  const SshPage({super.key, required this.app, this.installAgent});

  @override
  State<SshPage> createState() => _SshPageState();
}

class _SshPageState extends State<SshPage> {
  List<SshKey>? keys;
  App get app => widget.app;

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    final r = await app.cli.sshList(app.dir);
    if (!mounted) return;
    setState(() => keys = r.ok ? [for (final l in r.lines) SshKey.parse(l)].whereType<SshKey>().toList() : []);
  }

  Future<String?> askName(String title) {
    final c = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: TextField(key: const Key('ssh-name'), controller: c, autofocus: true, decoration: const InputDecoration(labelText: 'Name', hintText: 'github', border: OutlineInputBorder())),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Cancel')),
          FilledButton(key: const Key('ssh-name-ok'), onPressed: () => Navigator.of(ctx).pop(c.text.trim()), child: const Text('OK')),
        ],
      ),
    );
  }

  bool _taken(String n) => keys?.any((k) => k.name == n) ?? false;

  Future<void> create() async {
    final n = await askName('New SSH key');
    if (n == null || n.isEmpty || !mounted) return;
    if (_taken(n)) return toast(context, 'You already have a key named $n');
    final r = await app.withPin(context, (p) => runTask(context, 'Making the key $n', () => app.cli.sshNew(app.dir, n, p),
        detail: 'Its private key is split between this device and the cosigner.', usually: 'a few seconds'));
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    await load();
  }

  Future<void> import() async {
    final f = await FilePicker.pickFiles(dialogTitle: 'The private key file (for example ~/.ssh/id_ed25519)', type: FileType.any);
    final path = f.isEmpty ? null : f.single.path;
    if (path == null || !mounted) return;
    final n = await askName('Name for this key');
    if (n == null || n.isEmpty || !mounted) return;
    if (_taken(n)) return toast(context, 'You already have a key named $n');
    // A key with a passphrase: asked for once the agent says so.
    final encrypted = _hasPassphrase(path);
    final phrase = encrypted ? await askSecret(context, title: 'The key\'s passphrase', label: 'Passphrase', numeric: false) : '';
    if (phrase == null || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Importing $n', () => app.cli.sshImport(app.dir, n, path, p, passphrase: phrase), usually: 'a few seconds'));
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    toast(context, '$n imported. Delete $path once you have checked that the key works through Symbolon.');
    await load();
  }

  /// Whether an OpenSSH key file is sealed (its cipher is not "none").
  static bool _hasPassphrase(String path) {
    try {
      final body = File(path).readAsLinesSync().where((l) => !l.startsWith('-----')).join();
      final b = base64.decode(body);
      const magic = 'openssh-key-v1';
      if (b.length < 20 || String.fromCharCodes(b.sublist(0, magic.length)) != magic) return false;
      final n = (b[15] << 24) | (b[16] << 16) | (b[17] << 8) | b[18];
      return String.fromCharCodes(b.sublist(19, 19 + n)) != 'none';
    } catch (_) {
      return false;
    }
  }

  Future<void> delete(SshKey k) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Delete ${k.name}?'),
        content: Text(k.threshold
            ? 'No one holds this key in full, so it cannot be brought back. Remove it from the servers that accept it.'
            : 'Symbolon forgets this key. Keep the original file if you still need it.'),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(key: const Key('ssh-delete-ok'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Delete')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    final r = await app.withPin(context, (p) => app.cli.sshDelete(app.dir, k.name, p));
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    await load();
  }

  Future<void> setUpAgent() async {
    final unit = sshAgentUnit(app.settings.binary, app.dir, Platform.resolvedExecutable);
    final install = widget.installAgent ?? _installUnit;
    final err = await install(unit);
    if (!mounted) return;
    toast(context, err ?? 'The agent starts at login. Add to your shell profile: $sshAuthSock');
  }

  static Future<String?> _installUnit(String unit) async {
    try {
      final d = Directory('${Platform.environment['HOME']}/.config/systemd/user');
      await d.create(recursive: true);
      await File('${d.path}/symbolon-ssh-agent.service').writeAsString(unit);
      final r = await Process.run('systemctl', ['--user', 'enable', '--now', 'symbolon-ssh-agent.service']);
      return r.exitCode == 0 ? null : 'systemctl: ${r.stderr}'.trim();
    } catch (e) {
      return 'Could not set up the agent: $e';
    }
  }

  @override
  Widget build(BuildContext context) {
    final ks = keys;
    return Scaffold(
      appBar: AppBar(title: const Text('SSH keys')),
      body: ks == null
          ? const Center(child: CircularProgressIndicator())
          : PageBody(children: [
              const Text('Use these keys with ssh and git through the Symbolon SSH agent. Each signature asks you first, '
                  'showing which program asks and for which server.'),
              const SizedBox(height: 12),
              if (ks.isEmpty) const Card(child: ListTile(key: Key('ssh-none'), title: Text('No SSH keys yet'))),
              for (final k in ks)
                Card(
                  child: ListTile(
                    key: Key('ssh-key-${k.name}'),
                    leading: TypeAvatar(typeOf('ssh')),
                    title: Text(k.name),
                    subtitle: Text('${k.threshold ? 'Held by your quorum' : 'Imported'} · ${k.algorithm}'),
                    trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                      IconButton(
                        tooltip: 'Copy the public key',
                        icon: const Icon(Icons.copy),
                        onPressed: () {
                          Clipboard.setData(ClipboardData(text: k.line));
                          toast(context, 'Public key copied: add it to the server or code host.');
                        },
                      ),
                      IconButton(key: Key('ssh-delete-${k.name}'), tooltip: 'Delete', icon: const Icon(Icons.delete_outline), onPressed: () => delete(k)),
                    ]),
                  ),
                ),
              const SizedBox(height: 12),
              WideButton('New key held by your quorum', key: const Key('ssh-new'), icon: Icons.add, onPressed: create),
              const SizedBox(height: 8),
              WideButton('Import a key file', key: const Key('ssh-import'), icon: Icons.file_open_outlined, tonal: true, onPressed: import),
              if (!Platform.isAndroid) ...[
                const SizedBox(height: 8),
                WideButton('Start the agent at login', key: const Key('ssh-agent-setup'), icon: Icons.play_circle_outline, tonal: true, onPressed: setUpAgent),
                const SizedBox(height: 8),
                SelectableText(sshAuthSock, style: const TextStyle(fontFamily: 'monospace')),
              ],
            ]),
    );
  }
}
