import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter/services.dart';

import '../app.dart';
import '../ssh_consent.dart' show sshDate;
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

/// A certificate authority (SPEC 16.1.2), as `device ssh cas` lists it:
/// the same form as a key.
typedef SshCa = SshKey;

/// A key's certificate, as `device ssh certs` lists it.
class SshCert {
  final String key, ca, line;
  final int days, validAfter, validBefore;
  final List<String> principals;
  const SshCert(this.key, this.ca, this.days, this.principals, this.validAfter, this.validBefore, this.line);

  /// "KEY-HEX CA-HEX DAYS PRINCIPALS VALID-AFTER VALID-BEFORE CERT-LINE"; null for anything else.
  static SshCert? parse(String l) {
    final p = l.trim().split(' ');
    if (p.length < 8) return null;
    try {
      return SshCert(unhex(p[0]), unhex(p[1]), int.parse(p[2]), p[3].split(','), int.parse(p[4]), int.parse(p[5]), p.sublist(6).join(' '));
    } catch (_) {
      return null;
    }
  }

  bool current(int now) => validAfter <= now && now < validBefore;

  /// Renewed after the next signature: less than a third of its time left.
  bool due(int now) => now >= validBefore - (validBefore - validAfter) ~/ 3;
}

/// A principal: a user name on the servers, as the agent takes it.
final principalPattern = RegExp(r'^[A-Za-z0-9._@+-]{1,64}$');

/// [s] quoted for a POSIX shell.
String shellQuote(String s) => "'${s.replaceAll("'", "'\\''")}'";

/// Pylon's command that adds [line] to the server's authorized_keys, run
/// from a device that can already log in to [target] (USER@HOST). With
/// [ca] it adds `cert-authority,principals="USER"` before the CA's line.
String authorizeCommand(String target, String line, {bool ca = false}) => 'pylon authorize ${ca ? '--ca ' : ''}$target ${shellQuote(line)}';

/// The same trust for the whole server, as root: the CA's line in its own
/// file, named first in sshd_config (above any Match block), checked, and
/// sshd reloaded (the unit is "ssh" on Debian and Ubuntu).
String trustCaAsRoot(String caLine) => [
  'echo ${shellQuote(caLine)} | sudo tee /etc/ssh/symbolon_user_ca.pub',
  "sudo sed -i '1i TrustedUserCAKeys /etc/ssh/symbolon_user_ca.pub' /etc/ssh/sshd_config",
  'sudo sshd -t && (sudo systemctl reload sshd || sudo systemctl reload ssh)',
].join('\n');

int _now() => DateTime.now().millisecondsSinceEpoch ~/ 1000;

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
  List<SshCa> cas = [];
  List<SshCert> certs = [];

  /// The last server typed (USER@HOST), offered again.
  String target = '';
  App get app => widget.app;

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    final r = await app.cli.sshList(app.dir);
    final c = await app.cli.sshCas(app.dir);
    final t = await app.cli.sshCerts(app.dir);
    if (!mounted) return;
    setState(() {
      keys = r.ok ? [for (final l in r.lines) SshKey.parse(l)].whereType<SshKey>().toList() : [];
      cas = c.ok ? [for (final l in c.lines) SshKey.parse(l)].whereType<SshCa>().toList() : [];
      certs = t.ok ? [for (final l in t.lines) SshCert.parse(l)].whereType<SshCert>().toList() : [];
    });
  }

  SshCert? certOf(SshKey k) => certs.where((c) => c.key == k.name).firstOrNull;

  Future<String?> askName(String title) {
    final c = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: TextField(
          key: const Key('ssh-name'),
          controller: c,
          autofocus: true,
          decoration: const InputDecoration(labelText: 'Name', hintText: 'github', border: OutlineInputBorder()),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Cancel')),
          FilledButton(key: const Key('ssh-name-ok'), onPressed: () => Navigator.of(ctx).pop(c.text.trim()), child: const Text('OK')),
        ],
      ),
    );
  }

  bool _taken(String n) => (keys?.any((k) => k.name == n) ?? false) || cas.any((c) => c.name == n);

  Future<void> create() async {
    final n = await askName('New SSH key');
    if (n == null || n.isEmpty || !mounted) return;
    if (_taken(n)) return toast(context, 'You already have a key named $n');
    final r = await app.withPin(
      context,
      (p) => runTask(context, 'Making the key $n', () => app.cli.sshNew(app.dir, n, p), detail: 'Its private key is split between this device and the cosigner.', usually: 'a few seconds'),
    );
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
    final phrase = encrypted ? await askSecret(context, title: 'The key\'s passphrase', label: 'Passphrase', numeric: false, action: 'Import') : '';
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

  Future<void> delete(SshKey k, {bool ca = false}) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Delete ${k.name}?'),
        content: Text(
          ca
              ? 'No one holds this certificate authority in full, so it cannot be brought back, and its certificates are dropped here. '
                    'Servers that trust it accept the certificates it already issued until they expire: remove its line from those servers.'
              : k.threshold
            ? 'No one holds this key in full, so it cannot be brought back. Remove it from the servers that accept it.'
              : 'Symbolon forgets this key. Keep the original file if you still need it.',
        ),
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

  // ─── Servers ────────────────────────────────────────────────────────

  /// The command that sets up a server for [line], for a USER@HOST the
  /// person types: copy it, or the line itself.
  Future<void> serverSetup(String title, String line, {bool ca = false}) async {
    final c = TextEditingController(text: target);
    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, set) {
          final t = c.text.trim().isEmpty ? 'USER@HOST' : c.text.trim();
          final cmd = authorizeCommand(t, line, ca: ca);
          final user = t.contains('@') ? t.substring(0, t.indexOf('@')) : 'USER';
          return AlertDialog(
            title: Text(title),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    ca
                        ? 'Run this from a device that can already log in to the server. Pylon adds the authority to the user\'s ~/.ssh/authorized_keys, '
                              'limited to that user name (cert-authority,principals="$user"), and fixes the file\'s permissions. No root needed. '
                              'From then on, any of your keys with a certificate that names $user logs in.'
                        : 'Run this from a device that can already log in to the server. Pylon adds the line to ~/.ssh/authorized_keys '
                              'without touching what is there, and fixes the file\'s permissions. Or paste the line into that file yourself.',
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    key: const Key('ssh-target'),
                    controller: c,
                    autocorrect: false,
                    enableSuggestions: false,
                    decoration: const InputDecoration(labelText: 'User and server', hintText: 'larry@server.example', border: OutlineInputBorder()),
                    onChanged: (_) => set(() {}),
                  ),
                  const SizedBox(height: 12),
                  SelectableText(
                    cmd,
                    key: const Key('ssh-command'),
                    style: const TextStyle(fontFamily: 'monospace'),
                  ),
                ],
              ),
            ),
            actions: [
              TextButton(
                key: const Key('ssh-copy-line'),
                onPressed: () => copyText(context, ca ? 'Certificate authority line' : 'Key line', ca ? 'cert-authority,principals="$user" $line' : line),
                child: const Text('Copy the line'),
              ),
              FilledButton(key: const Key('ssh-copy-command'), onPressed: () => copyText(context, 'Command', cmd), child: const Text('Copy the command')),
            ],
          );
        },
      ),
    );
    target = c.text.trim();
  }

  /// Both ways for a server to trust a certificate authority.
  Future<void> trustCa(SshCa a) async {
    final how = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Trust ${a.name} on a server'),
        content: const Text(
          'Once per server. Then any of your keys with a certificate from this authority logs in as the user names the certificate lists, '
          'with no change on the server for new keys.',
        ),
        actions: [
          TextButton(key: const Key('ssh-trust-root'), onPressed: () => Navigator.of(ctx).pop('root'), child: const Text('Whole server (root)')),
          FilledButton(key: const Key('ssh-trust-user'), onPressed: () => Navigator.of(ctx).pop('user'), child: const Text('One user (no root)')),
        ],
      ),
    );
    if (!mounted || how == null) return;
    if (how == 'user') return serverSetup('Trust ${a.name} for one user', a.line, ca: true);
    final cmd = trustCaAsRoot(a.line);
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Trust ${a.name} on the whole server'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'As root on the server: put the authority\'s line in /etc/ssh/symbolon_user_ca.pub, add '
                '"TrustedUserCAKeys /etc/ssh/symbolon_user_ca.pub" to /etc/ssh/sshd_config (above any Match block), and reload sshd. '
                'These commands do that, and check the configuration first:',
              ),
              const SizedBox(height: 12),
              SelectableText(
                cmd,
                key: const Key('ssh-root-command'),
                style: const TextStyle(fontFamily: 'monospace'),
              ),
              const SizedBox(height: 12),
              const Text('Each user then logs in with a certificate that names their user name.'),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => copyText(context, 'Certificate authority line', a.line), child: const Text('Copy the line')),
          FilledButton(onPressed: () => copyText(context, 'Commands', cmd), child: const Text('Copy the commands')),
        ],
      ),
    );
  }

  // ─── The certificate authority ──────────────────────────────────────

  Future<void> createCa() async {
    final n = await askName('New certificate authority');
    if (n == null || n.isEmpty || !mounted) return;
    if (_taken(n)) return toast(context, 'You already have a key or an authority named $n');
    final r = await app.withPin(
      context,
      (p) => runTask(
        context,
        'Making the certificate authority $n',
        () => app.cli.sshCaNew(app.dir, n, p),
        detail: 'Like your keys, its private key is split between this device and the cosigner.',
        usually: 'a few seconds',
      ),
    );
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    await load();
  }

  /// A certificate for [k]: the authority, the user names and the days.
  Future<void> certify(SshKey k) async {
    if (cas.isEmpty) return toast(context, 'Create a certificate authority first');
    final old = certOf(k);
    final names = TextEditingController(text: old?.principals.join(', ') ?? '');
    final days = TextEditingController(text: '${old?.days ?? 30}');
    var ca = old != null && cas.any((c) => c.name == old.ca) ? old.ca : cas.first.name;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, set) => AlertDialog(
          title: Text('Certificate for ${k.name}'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text(
                  'The certificate lets this key log in, as the user names below, to every server that trusts the authority. '
                  'Symbolon renews it when you log in with less than a third of its time left.',
                ),
                const SizedBox(height: 12),
                if (cas.length > 1) ...[
                  DropdownButtonFormField<String>(
                    initialValue: ca,
                    decoration: const InputDecoration(labelText: 'Certificate authority', border: OutlineInputBorder()),
                    items: [for (final c in cas) DropdownMenuItem(value: c.name, child: Text(c.name))],
                    onChanged: (v) => set(() => ca = v ?? ca),
                  ),
                  const SizedBox(height: 12),
                ],
                TextField(
                  key: const Key('ssh-principals'),
                  controller: names,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: const InputDecoration(labelText: 'User names on the servers', hintText: 'larry, deploy', border: OutlineInputBorder()),
                ),
                const SizedBox(height: 12),
                TextField(
                  key: const Key('ssh-days'),
                  controller: days,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(labelText: 'Valid for (days, 1 to 366)', border: OutlineInputBorder()),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
            FilledButton(key: const Key('ssh-certify-ok'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Issue')),
          ],
        ),
      ),
    );
    if (ok != true || !mounted) return;
    final ps = names.text.split(RegExp(r'[\s,]+')).where((p) => p.isNotEmpty).toSet().toList();
    final d = int.tryParse(days.text.trim()) ?? 0;
    if (ps.isEmpty || !ps.every(principalPattern.hasMatch)) {
      return toast(context, 'User names are letters, digits and . _ - @ +, separated by commas or spaces');
    }
    if (d < 1 || d > 366) return toast(context, 'A certificate lasts 1 to 366 days');
    final r = await app.withPin(
      context,
      (p) => runTask(
        context,
        'Issuing a certificate for ${k.name}',
        () => app.cli.sshCertify(app.dir, k.name, ca, ps, d, p),
        detail: 'Your quorum signs it with the certificate authority.',
        usually: 'a few seconds',
      ),
    );
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    await load();
  }

  Future<void> renew(SshKey k) async {
    final r = await app.withPin(
      context,
      (p) =>
          runTask(context, 'Renewing the certificate of ${k.name}', () => app.cli.sshRenew(app.dir, k.name, p), detail: 'With the same authority, user names and lifetime.', usually: 'a few seconds'),
    );
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    await load();
  }

  /// Keys, authorities and certificates made on another device of the quorum.
  Future<void> refresh() async {
    final r = await app.withPin(context, (p) => runTask(context, 'Reading your SSH keys from the vault', () => app.cli.sshRefresh(app.dir, p), usually: 'a few seconds'));
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    toast(context, r.lines.isEmpty ? 'Up to date' : r.lines.last);
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

  Widget _certLine(SshKey k) {
    final c = certOf(k);
    final now = _now();
    final scheme = Theme.of(context).colorScheme;
    if (c == null) {
      return cas.isEmpty
          ? const SizedBox.shrink()
          : Padding(
              padding: const EdgeInsets.fromLTRB(8, 0, 8, 4),
              child: Align(
                alignment: Alignment.centerLeft,
                child: TextButton.icon(key: Key('ssh-certify-${k.name}'), onPressed: () => certify(k), icon: const Icon(Icons.verified_user_outlined), label: const Text('Issue a certificate')),
              ),
            );
    }
    final live = c.current(now);
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 0, 8, 4),
      child: Row(
        children: [
          Icon(live ? Icons.verified_user : Icons.gpp_bad_outlined, size: 18, color: live ? scheme.primary : scheme.error),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              key: Key('ssh-cert-${k.name}'),
              live ? 'Certificate from ${c.ca} for ${c.principals.join(', ')}, valid until ${sshDate(c.validBefore)}' : 'Certificate from ${c.ca} expired ${sshDate(c.validBefore)}',
              style: TextStyle(color: live ? null : scheme.error),
            ),
          ),
          TextButton(key: Key('ssh-renew-${k.name}'), onPressed: () => renew(k), child: const Text('Renew')),
          IconButton(tooltip: 'Change', icon: const Icon(Icons.edit_outlined, size: 20), onPressed: () => certify(k)),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final ks = keys;
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(
        title: const Text('SSH keys'),
        actions: [IconButton(key: const Key('ssh-refresh'), tooltip: 'Bring in keys made on your other devices', icon: const Icon(Icons.sync), onPressed: refresh)],
      ),
      body: ks == null
          ? const Center(child: CircularProgressIndicator())
          : PageBody(
              children: [
                const Text(
                  'Use these keys with ssh and git through the Symbolon SSH agent. Each signature asks you first, '
                  'showing which program asks and for which server.',
                ),
              const SizedBox(height: 12),
                // Open until there is a key or an authority; then a tap away.
                Card(
                  margin: const EdgeInsets.only(bottom: 16),
                  child: ExpansionTile(
                    key: const Key('ssh-howto'),
                    initiallyExpanded: ks.isEmpty && cas.isEmpty,
                    leading: const Icon(Icons.help_outline),
                    title: const Text('How a server learns to trust you'),
                    childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                    expandedCrossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('A server lets you in when it trusts one of your keys. You tell each server once, in one of two ways:'),
                      const SizedBox(height: 8),
                      Text('One key at a time', style: t.titleSmall),
                      const Text(
                        'Add the key\'s line to ~/.ssh/authorized_keys on the server. Each key below has its line and a ready-made '
                        'command (Set up a server) that does it from a device that can already log in.',
                      ),
                      const SizedBox(height: 8),
                      Text('With a certificate authority', style: t.titleSmall),
                      const Text(
                        'The server trusts your Symbolon certificate authority, once. Then every key with a certificate from it logs in, '
                        'as the user names the certificate lists, and a new key needs no change on any server. Certificates expire on their own '
                        'and Symbolon renews them when you log in.',
                      ),
                      const SizedBox(height: 8),
                      const Text(
                        'All devices in your quorum share these keys and the certificate authority, so one setup per server covers every device. '
                        'On another device, tap the sync button above to bring them in.',
                      ),
                    ],
                  ),
                ),
                Text('Your keys', style: t.titleMedium),
                const SizedBox(height: 8),
                if (ks.isEmpty)
                  const Card(
                    child: ListTile(key: Key('ssh-none'), title: Text('No SSH keys yet')),
                  ),
              for (final k in ks)
                Card(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        ListTile(
                    key: Key('ssh-key-${k.name}'),
                    leading: TypeAvatar(typeOf('ssh')),
                    title: Text(k.name),
                    subtitle: Text('${k.threshold ? 'Held by your quorum' : 'Imported'} · ${k.algorithm}'),
                          trailing: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                      IconButton(
                        tooltip: 'Copy the public key',
                        icon: const Icon(Icons.copy),
                        onPressed: () {
                          Clipboard.setData(ClipboardData(text: k.line));
                                  toast(context, 'Public key copied: add it to the server\'s ~/.ssh/authorized_keys, or to your code host.');
                        },
                      ),
                      IconButton(key: Key('ssh-delete-${k.name}'), tooltip: 'Delete', icon: const Icon(Icons.delete_outline), onPressed: () => delete(k)),
                            ],
                          ),
                        ),
                        Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 8),
                          child: Wrap(
                            spacing: 4,
                            children: [
                              TextButton.icon(
                                key: Key('ssh-setup-${k.name}'),
                                onPressed: () => serverSetup('Let ${k.name} into a server', k.line),
                                icon: const Icon(Icons.dns_outlined),
                                label: const Text('Set up a server'),
                              ),
                            ],
                          ),
                        ),
                        _certLine(k),
                      ],
                  ),
                ),
              const SizedBox(height: 12),
              WideButton('New key held by your quorum', key: const Key('ssh-new'), icon: Icons.add, onPressed: create),
              const SizedBox(height: 8),
              WideButton('Import a key file', key: const Key('ssh-import'), icon: Icons.file_open_outlined, tonal: true, onPressed: import),
                const SizedBox(height: 20),
                Section(
                  'Certificate authority',
                  key: const Key('ssh-ca-section'),
                  subtitle: 'Your quorum holds it like your keys. It signs only certificates, never logins.',
                  children: [
                    if (cas.isEmpty)
                      const Text(
                        'With a certificate authority, each server is told once to trust it, and your keys log in with certificates '
                        'it issues: first create it, then trust it on your servers, then issue each key a certificate naming the user names '
                        'you log in as.',
                      ),
                    for (final a in cas)
                      ListTile(
                        key: Key('ssh-ca-${a.name}'),
                        contentPadding: EdgeInsets.zero,
                        leading: const Icon(Icons.verified_outlined),
                        title: Text(a.name),
                        subtitle: Text(
                          a.line,
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                        ),
                        trailing: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            IconButton(tooltip: 'Copy its line', icon: const Icon(Icons.copy), onPressed: () => copyText(context, 'Certificate authority line', a.line)),
                            IconButton(key: Key('ssh-ca-delete-${a.name}'), tooltip: 'Delete', icon: const Icon(Icons.delete_outline), onPressed: () => delete(a, ca: true)),
                          ],
                        ),
                      ),
                    for (final a in cas)
                      Align(
                        alignment: Alignment.centerLeft,
                        child: TextButton.icon(key: Key('ssh-trust-${a.name}'), onPressed: () => trustCa(a), icon: const Icon(Icons.dns_outlined), label: Text('Trust ${a.name} on a server')),
                      ),
                    const SizedBox(height: 8),
                    if (cas.isEmpty)
                      WideButton('Create a certificate authority', key: const Key('ssh-ca-new'), icon: Icons.add_moderator_outlined, tonal: true, onPressed: createCa)
                    else
                      Text('Issue a certificate from each key above. It lasts 30 days unless you choose otherwise (at most 366).', style: t.bodySmall),
                  ],
                ),
              if (!Platform.isAndroid) ...[
                const SizedBox(height: 8),
                WideButton('Start the agent at login', key: const Key('ssh-agent-setup'), icon: Icons.play_circle_outline, tonal: true, onPressed: setUpAgent),
                const SizedBox(height: 8),
                SelectableText(sshAuthSock, style: const TextStyle(fontFamily: 'monospace')),
              ],
              ],
            ),
    );
  }
}
