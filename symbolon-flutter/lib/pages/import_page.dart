import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

import 'package:file_picker/file_picker.dart';
import 'package:material_ui/material_ui.dart';

import '../app.dart';
import '../cli.dart';
import '../onepassword.dart';
import '../settings.dart';
import '../vault_types.dart';
import '../widgets.dart';
import 'signin_import_page.dart';

/// Moving in from another password manager: how to export from it, the
/// file, what will come across (checked by the agent without the PIN), and
/// then everything at once as one new vault version
/// (`symbolon device vault import`). Pops true when items were imported.
class ImportPage extends StatefulWidget {
  final App app;
  final String share;                  // into this shared folder, "" for the own vault
  const ImportPage({super.key, required this.app, this.share = ''});

  @override
  State<ImportPage> createState() => _ImportPageState();
}

class _Source {
  final String name;
  final String steps;
  const _Source(this.name, this.steps);
}

const _sources = [
  _Source('Bitwarden or Vaultwarden', 'In the web vault or the desktop app: Tools, then Export vault. Choose the file format ".json" '
      '(not the encrypted one), confirm with your master password, and save the file.'),
  _Source('LastPass', 'In the web vault: Advanced options, then Export. Confirm with your master password; LastPass saves a .csv file.'),
  _Source('1Password', 'In the 1Password desktop app: File, then Export, then the account. Choose CSV and save the file.'),
  _Source('Chrome, Edge or Brave', 'Open the browser\'s password manager (chrome://password-manager/settings in Chrome), choose Export '
      'passwords and save the .csv file.'),
  _Source('Firefox', 'Open about:logins, then the ••• menu, then Export passwords, and save the .csv file.'),
  _Source('Safari or Apple Passwords', 'On a Mac: in Safari, File, then Export, then Passwords (or in the Passwords app, File, then Export). '
      'Save the .csv file.'),
  _Source('KeePassXC', 'Database, then Export, then CSV file.'),
  _Source('Proton Pass', 'Settings, then Export. Choose CSV.'),
  _Source('Dashlane', 'Settings, then Export data, then CSV.'),
  _Source('Another CSV file', 'Any CSV with a header row: Symbolon finds the name, address, username, password, notes and folder '
      'columns by their names.'),
];

/// What the agent said it would import.
class ImportPreview {
  final List<VaultItem> items = [];
  final List<(String, String)> skipped = [];   // name, why
  final List<String> warnings = [];

  static ImportPreview parse(List<String> lines) {
    final p = ImportPreview();
    for (final l in lines) {
      final f = l.trim().split(' ');
      try {
        if (f[0] == 'item' && f.length == 4) p.items.add(VaultItem(unhex(f[2]), f[1], folder: f[3] == '-' ? '' : unhex(f[3])));
        if (f[0] == 'skip' && f.length == 3) p.skipped.add((unhex(f[1]), unhex(f[2])));
        if (f[0] == 'warn' && f.length == 2) p.warnings.add(unhex(f[1]));
      } on FormatException {
        continue;
      }
    }
    return p;
  }

  Map<String, int> get byType {
    final m = <String, int>{};
    for (final i in items) {
      m[i.type] = (m[i.type] ?? 0) + 1;
    }
    return m;
  }

  int get folders => {for (final i in items) if (i.folder.isNotEmpty) i.folder}.length;
}

class _ImportPageState extends State<ImportPage> {
  _Source? source;
  String? file;
  String? opLine;                      // another app's items (1Password's CLI, or Credential Exchange), until imported
  String opFormat = '1password-op';
  ImportPreview? preview;
  int? imported;

  App get app => widget.app;

  Future<void> pick() async {
    final r = await FilePicker.pickFiles(dialogTitle: 'The export file', type: FileType.any);
    final path = r.isEmpty ? null : r.single.path;
    if (path == null || !mounted) return;
    final res = await runTask(context, 'Reading the export', () => app.cli.vaultImportPreview(app.dir, path), usually: 'a few seconds');
    if (!mounted) return;
    if (!res.ok) {
      await _forgetCopy();
      return;
    }
    setState(() {
      file = path;
      preview = ImportPreview.parse(res.lines);
    });
  }

  // Another app on this phone (Android's Credential Exchange): the person
  // picks it and confirms there; its items arrive as CXF JSON.
  Future<void> _exchange() async {
    String? json;
    try {
      json = await const MethodChannel('symbolon/platform').invokeMethod<String>('importCredentials');
    } on PlatformException catch (e) {
      if (!mounted || e.code == 'cancelled') return;
      final why = switch (e.code) {
        'none' => 'No app on this phone offered its passwords. Update the other app, or use its export file.',
        'unavailable' => 'This phone cannot hand passwords between apps yet (it needs a current Google Play services).',
        _ => 'The other app did not hand its passwords over${e.message == null ? '' : ': ${e.message}'}.',
      };
      ScaffoldMessenger.of(context).showSnackBar(errorBar(why));
      return;
    }
    if (json == null || !mounted) return;
    // One line for the agent's standard input.
    final line = jsonEncode(jsonDecode(json));
    final res = await runTask(context, 'Reading what came across', () => app.cli.vaultImportLinePreview(app.dir, line, 'cxf'), usually: 'a few seconds');
    if (!mounted || !res.ok) return;
    setState(() {
      opLine = line;
      opFormat = 'cxf';
      file = null;
      preview = ImportPreview.parse(res.lines);
    });
  }

  // 1Password on Linux: its CLI reads the items (1Password asks to be
  // unlocked); they go to the agent on standard input.
  Future<void> _onePassword() async {
    final res = await runTask(context, 'Reading 1Password', () async {
      try {
        final line = await readOnePassword();
        opLine = line;
        opFormat = '1password-op';
        return await app.cli.vaultImportLinePreview(app.dir, line, '1password-op');
      } on OpProblem catch (e) {
        return CliResult(1, '', 'device: ${e.message}');
      }
    }, usually: 'under a minute');
    if (!mounted) return;
    if (!res.ok) {
      opLine = null;
      return;
    }
    setState(() {
      file = null;
      preview = ImportPreview.parse(res.lines);
    });
  }

  Future<void> go() async {
    final f = file;
    final op = opLine;
    final p = preview;
    if ((f == null && op == null) || p == null || p.items.isEmpty) return;
    final passkeys = widget.share.isEmpty && p.items.any((i) => i.type == 'passkey');
    final r = await app.withPin(context, (pin) => runTask(context, 'Importing ${p.items.length} items', () async {
          final r = op != null ? await app.cli.vaultImportLine(app.dir, op, opFormat, pin, share: widget.share) : await app.cli.vaultImport(app.dir, f!, pin, share: widget.share);
          // Imported passkeys are offered at sign-in, and listed to be
          // replaced, from the same list as Symbolon's own.
          if (r.ok && passkeys) {
            final s = await app.cli.waSynced(app.dir, pin);
            if (s.ok) await app.settings.setSynced(Credential.syncedFrom(s.lines));
          }
          return r;
        }, usually: 'under a minute'));
    if (!mounted || r == null || !r.ok) return;
    opLine = null;
    await _forgetCopy();
    final total = r.lines.map((l) => l.trim()).where((l) => l.startsWith('total ')).map((l) => int.tryParse(l.substring(6)) ?? 0).firstOrNull ?? p.items.length;
    setState(() => imported = total);
  }

  // On a phone the picker hands over a copy in the app's cache: removed
  // once it has been read, as it holds every password unencrypted.
  Future<void> _forgetCopy() async {
    if (!Platform.isAndroid && !Platform.isIOS) return;
    try {
      await FilePicker.clearTemporaryFiles();
    } catch (_) {}
  }

  @override
  void dispose() {
    _forgetCopy();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Import')),
      body: PageBody(children: [
        if (imported != null) ..._done() else if (preview != null) ..._preview() else if (source != null) ..._steps() else ..._pickSource(),
      ]),
    );
  }

  Future<void> _signIn({bool lastpass = false}) async {
    final ok = await Navigator.of(context).push<bool>(MaterialPageRoute(builder: (_) => SignInImportPage(app: app, share: widget.share, lastpass: lastpass)));
    if (ok == true && mounted) Navigator.of(context).pop(true);
  }

  List<Widget> _pickSource() => [
        const Section('Sign in instead', children: [
          Text('No export file: Symbolon signs in to your old password manager and opens its vault on this device.'),
        ]),
        Card(
          child: ListTile(
            key: const Key('source-signin-bitwarden'),
            leading: const Icon(Icons.login),
            title: const Text('Bitwarden or Vaultwarden'),
            subtitle: const Text('Sign in with your email and master password'),
            trailing: const Icon(Icons.chevron_right),
            onTap: _signIn,
          ),
        ),
        Card(
          child: ListTile(
            key: const Key('source-signin-lastpass'),
            leading: const Icon(Icons.login),
            title: const Text('LastPass'),
            subtitle: const Text('Sign in with your email and master password (experimental)'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _signIn(lastpass: true),
          ),
        ),
        if (Platform.isAndroid)
          Card(
            child: ListTile(
              key: const Key('source-exchange'),
              leading: const Icon(Icons.swap_horiz),
              title: const Text('Another app on this phone'),
              subtitle: const Text('Google Password Manager, 1Password, Bitwarden, Dashlane...: the app hands its passwords and passkeys over after you confirm'),
              trailing: const Icon(Icons.chevron_right),
              onTap: _exchange,
            ),
          ),
        if (Platform.isLinux)
          Card(
            child: ListTile(
              key: const Key('source-onepassword-cli'),
              leading: const Icon(Icons.login),
              title: const Text('1Password'),
              subtitle: const Text('Through the 1Password app on this computer (it asks you to unlock it)'),
              trailing: const Icon(Icons.chevron_right),
              onTap: _onePassword,
            ),
          ),
        const SizedBox(height: 8),
        const Section('Or import an export file', children: [
          Text('Symbolon reads the export file your password manager makes. Everything comes across in one go: logins, cards, '
              'identities, notes, folders and custom fields.'),
        ]),
        Card(
          child: Column(children: [
            for (final s in _sources)
              ListTile(
                key: Key('source-${s.name}'),
                title: Text(s.name),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => setState(() => source = s),
              ),
          ]),
        ),
      ];

  List<Widget> _steps() => [
        Section('Export from ${source!.name}', children: [
          Text(source!.steps),
          const SizedBox(height: 12),
          const ImportWarning('The export holds your passwords unencrypted. Save it on this device, not in a cloud folder, and delete it '
              'once the import is done.'),
          const SizedBox(height: 16),
          WideButton('Choose the export file', key: const Key('import-pick'), icon: Icons.file_open, onPressed: pick),
          TextButton(onPressed: () => setState(() => source = null), child: const Text('Another password manager')),
        ]),
      ];

  List<Widget> _preview() {
    final p = preview!;
    return [
      ...importPreviewView(context, p),
      if (p.items.isNotEmpty) WideButton('Import ${p.items.length} item${p.items.length == 1 ? '' : 's'}', key: const Key('import-go'), icon: Icons.move_to_inbox, onPressed: go),
      TextButton(
          onPressed: () => setState(() {
                preview = null;
                opLine = null;
              }),
          child: const Text('Choose another source')),
    ];
  }

  List<Widget> _done() => [
        Section('$imported item${imported == 1 ? '' : 's'} imported', key: const Key('import-done'), children: [
          const ListTile(contentPadding: EdgeInsets.zero, leading: Icon(Icons.check_circle, color: Colors.green), title: Text('Your vault has them now, on every device.')),
          const SizedBox(height: 8),
          const ImportWarning('Now delete the export file (and empty the trash): anyone who finds it can read every password in it. '
              'Then, once you have checked your vault, you can close the old account.'),
          const SizedBox(height: 16),
          WideButton('Done', key: const Key('import-finish'), icon: Icons.check, onPressed: () => Navigator.of(context).pop(true)),
        ]),
      ];
}

/// What an import will bring in: counts by type, warnings, what is left
/// out and the items (the file import and the sign-in import share it).
List<Widget> importPreviewView(BuildContext context, ImportPreview p) {
  final t = Theme.of(context).textTheme;
  final types = p.byType.entries.toList()..sort((a, b) => b.value.compareTo(a.value));
  return [
      Section(p.items.isEmpty ? 'Nothing to import' : 'Ready to import ${p.items.length} item${p.items.length == 1 ? '' : 's'}', children: [
        Wrap(spacing: 8, runSpacing: 8, children: [
          for (final e in types) Chip(avatar: Icon(typeOf(e.key).icon, size: 18, color: typeOf(e.key).color), label: Text('${e.value} ${(e.value == 1 ? typeOf(e.key).label : typeOf(e.key).plural).toLowerCase()}')),
          if (p.folders > 0) Chip(avatar: const Icon(Icons.folder_outlined, size: 18), label: Text('${p.folders} folder${p.folders == 1 ? '' : 's'}')),
        ]),
        const SizedBox(height: 12),
        const Text('They are added to your vault; nothing in it is replaced. A name already in use gets a number, as "Email (2)".'),
      ]),
      for (final w in p.warnings) ImportWarning(w),
      if (p.skipped.isNotEmpty)
        Section('Left out (${p.skipped.length})', children: [
          for (final s in p.skipped) ListTile(contentPadding: EdgeInsets.zero, dense: true, title: Text(s.$1), subtitle: Text(s.$2)),
        ]),
      if (p.items.isNotEmpty)
        Section('What will come in', children: [
          for (final i in p.items.take(200))
            ListTile(
              contentPadding: EdgeInsets.zero,
              dense: true,
              leading: Icon(i.kind.icon, color: i.kind.color),
              title: Text(i.name),
              subtitle: i.folder.isEmpty ? null : Text(i.folder.replaceAll('/', ' › '), style: t.bodySmall),
            ),
          if (p.items.length > 200) Text('and ${p.items.length - 200} more', style: t.bodySmall),
        ]),
    ];
}

class ImportWarning extends StatelessWidget {
  final String text;
  const ImportWarning(this.text, {super.key});

  @override
  Widget build(BuildContext context) => Card(
        color: Colors.orange.withValues(alpha: 0.15),
        margin: const EdgeInsets.only(bottom: 12),
        child: ListTile(leading: const Icon(Icons.warning_amber, color: Colors.orange), title: Text(text)),
      );
}
