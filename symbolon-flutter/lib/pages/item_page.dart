import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app.dart';
import '../card_face.dart';
import '../favicons.dart';
import '../validate.dart' show cardBrand;
import '../vault_types.dart';
import '../widgets.dart';
import 'item_editor.dart';
import 'sharing_page.dart' show SharedFolder;
import 'vault_page.dart' show TypeAvatar;

/// What happened to an item on its page: replaced by [saved] (perhaps
/// under a new name), or deleted (saved null).
class ItemChange {
  final VaultItem? saved;
  const ItemChange(this.saved);
}

/// One vault item: its fields, hidden ones masked until asked, each with a
/// copy button; edit, delete, move between the own vault and shared
/// folders, and for a login a password change at the site.
class ItemPage extends StatefulWidget {
  final App app;
  final VaultItem item;
  final bool offline;
  final Set<String> names;
  final Set<String> folders;
  final String share;                  // the shared folder it is in, "" for the own vault
  const ItemPage({super.key, required this.app, required this.item, required this.offline, required this.names, this.folders = const {}, this.share = ''});

  @override
  State<ItemPage> createState() => _ItemPageState();
}

class _ItemPageState extends State<ItemPage> {
  Map<String, String>? fields;
  final shown = <String>{};

  App get app => widget.app;
  ItemType get type => typeOf(fields?['type'] ?? widget.item.type);

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => load());
  }

  Future<void> load() async {
    final r = await app.withPin(context, (p) => app.cli.vaultShow(app.dir, widget.item.name, p, share: widget.share));
    if (!mounted) return;
    if (r == null || !r.ok) {
      if (r != null) toast(context, friendlyError(r));
      Navigator.of(context).pop();
      return;
    }
    setState(() => fields = {
          for (final l in r.lines)
            if (l.contains(' ')) l.substring(0, l.indexOf(' ')): unhex(l.substring(l.indexOf(' ') + 1).trim()),
        });
  }

  void copy(String label, String value) {
    Clipboard.setData(ClipboardData(text: value));
    toast(context, '$label copied. Clear your clipboard when you are done.');
  }

  Future<void> edit() async {
    if (widget.offline) return toast(context, 'Changes need a connection to your relay.');
    final saved = await Navigator.of(context).push<VaultItem>(MaterialPageRoute(
        builder: (_) => ItemEditor(app: app, type: type, names: widget.names, name: widget.item.name, fields: fields, folders: widget.folders, share: widget.share)));
    if (saved != null && mounted) Navigator.of(context).pop(ItemChange(saved));
  }

  Future<void> delete() async {
    if (widget.offline) return toast(context, 'Changes need a connection to your relay.');
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Delete ${widget.item.name}?'),
        content: const Text('It is removed from the vault on every device. This cannot be undone.'),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(key: const Key('confirm-delete'), style: FilledButton.styleFrom(backgroundColor: Colors.red), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Delete')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Deleting ${widget.item.name}', () => app.cli.vaultDelete(app.dir, widget.item.name, p, share: widget.share), usually: 'a few seconds'));
    if (r != null && r.ok && mounted) {
      toast(context, '${widget.item.name} deleted');
      Navigator.of(context).pop(const ItemChange(null));
    }
  }

  Future<void> move() async {
    if (widget.offline) return toast(context, 'Changes need a connection to your relay.');
    final name = widget.item.name;
    final r = await app.withPin(context, (p) => app.cli.shareList(app.dir, p));
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    final folders = r.lines.map(SharedFolder.parse).whereType<SharedFolder>().where((f) => f.waiting.isEmpty && f.id != widget.share).toList();
    if (widget.share.isEmpty && folders.isEmpty) {
      await showOutput(context, 'No shared folders', 'Make a shared folder under More, then Sharing, to move items into it.');
      return;
    }
    if (!mounted) return;
    final to = await showModalBottomSheet<SharedFolder>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          ListTile(title: Text('Move $name to', style: Theme.of(ctx).textTheme.titleLarge)),
          if (widget.share.isNotEmpty)
            ListTile(key: const Key('move-own'), leading: const Icon(Icons.lock_outline), title: const Text('Your vault'),
                onTap: () => Navigator.of(ctx).pop(const SharedFolder('', 'your vault'))),
          for (final f in folders)
            ListTile(key: Key('move-${f.name}'), leading: const Icon(Icons.folder_shared), title: Text(f.name), subtitle: Text('${f.people} ${f.people == 1 ? 'person' : 'people'}'),
                onTap: () => Navigator.of(ctx).pop(f)),
        ]),
      ),
    );
    if (to == null || !mounted) return;
    final m = await app.withPin(context, (p) => runTask(context, 'Moving $name', () => app.cli.vaultMove(app.dir, name, to.id, p, from: widget.share), usually: 'a few seconds'));
    if (m != null && m.ok && mounted) {
      toast(context, '$name moved to ${to.name}');
      Navigator.of(context).pop(const ItemChange(null));
    }
  }

  Future<void> rotate() async {
    if (widget.offline) return toast(context, 'Changes need a connection to your relay.');
    final name = widget.item.name;
    final bundle = TextEditingController();
    final repo = TextEditingController();
    final ok = await showModalBottomSheet<bool>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.fromLTRB(16, 16, 16, 16 + MediaQuery.viewInsetsOf(ctx).bottom),
        child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text('Change the password of $name', style: Theme.of(ctx).textTheme.titleLarge),
          const SizedBox(height: 8),
          const Text('Symbolon changes it at the site with the site\'s signed recipe, in a hidden browser. Your vault keeps a password '
              'the site accepts at every step.'),
          const SizedBox(height: 12),
          Field(bundle, 'Recipe bundle (file)'),
          Field(repo, 'Recipe repository (file)', action: TextInputAction.done),
          WideButton('Change password', onPressed: () => Navigator.of(ctx).pop(bundle.text.trim().isNotEmpty && repo.text.trim().isNotEmpty)),
        ]),
      ),
    );
    if (ok != true || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Changing the password of $name',
        () => app.cli.rotate(app.dir, name, bundle.text.trim(), repo.text.trim(), p, chromium: app.settings.chromium, share: widget.share), usually: '1-2 minutes'));
    if (r != null && (r.ok || r.code == 2 || r.code == 3) && mounted) {
      await showOutput(context, name, r.out.trim());
      load();
    }
  }

  @override
  Widget build(BuildContext context) {
    final fs = fields;
    final t = type;
    final it = widget.item;
    final known = [for (final f in t.fields) if ((fs?[f.name] ?? '').isNotEmpty) f];
    final custom = fs == null
        ? <MapEntry<String, CustomField>>[]
        : (fs.entries.where((e) => CustomField.isCustom(e.key)).map((e) => MapEntry(e.key, CustomField.decode(e.value))).toList()
          ..sort((a, b) => int.parse(a.key.substring(7)).compareTo(int.parse(b.key.substring(7)))));
    return Scaffold(
      appBar: AppBar(title: Text(it.name), actions: [
        if (fs != null && type.editable) IconButton(key: const Key('item-move'), tooltip: 'Move', icon: const Icon(Icons.drive_file_move_outline), onPressed: move),
        if (fs != null && type.editable) IconButton(key: const Key('item-edit'), tooltip: 'Edit', icon: const Icon(Icons.edit), onPressed: edit),
        if (fs != null && type.editable) IconButton(key: const Key('item-delete'), tooltip: 'Delete', icon: const Icon(Icons.delete_outline), onPressed: delete),
      ]),
      body: fs == null
          ? const Center(child: CircularProgressIndicator())
          : PageBody(children: [
              Row(children: [
                t.id == 'login' ? SiteIcon(favicons: app.favicons, origin: fs['origin'] ?? '', fallback: TypeAvatar(t)) : TypeAvatar(t),
                const SizedBox(width: 12),
                Expanded(child: Text(it.name, style: Theme.of(context).textTheme.titleLarge)),
                KindTag(t.label, t.color),
              ]),
              if ((fs['folder'] ?? '').isNotEmpty)
                Padding(
                  padding: const EdgeInsets.only(top: 8),
                  child: Row(children: [
                    const Icon(Icons.folder_outlined, size: 18),
                    const SizedBox(width: 6),
                    Text(fs['folder']!.replaceAll('/', ' › '), key: const Key('item-folder-shown')),
                  ]),
                ),
              if (t.id == 'card' && (fs['number'] ?? '').isNotEmpty) ...[
                const SizedBox(height: 16),
                Center(
                  child: CardFace(
                    number: fs['number']!,
                    holder: fs['cardholder'] ?? '',
                    expiry: fs['expiry'] ?? '',
                    revealed: shown.contains('card-face'),
                    onTap: () => setState(() => shown.contains('card-face') ? shown.remove('card-face') : shown.add('card-face')),
                  ),
                ),
              ],
              const SizedBox(height: 16),
              Card(
                child: Column(children: [
                  for (final f in known) _row(f.name, f.name == 'number' ? '${f.label}${_brand(fs[f.name]!)}' : f.label, fs[f.name]!, f.hidden, multiline: f.input == Input.multiline),
                  for (final c in custom) _row(c.key, c.value.label, c.value.value, c.value.hidden, multiline: !c.value.hidden && c.value.value.contains('\n')),
                  if (known.isEmpty && custom.isEmpty) const ListTile(title: Text('No fields')),
                ]),
              ),
              if (t.id == 'login') ...[
                const SizedBox(height: 8),
                WideButton('Change password at the site…', icon: Icons.autorenew, tonal: true, onPressed: rotate),
              ],
            ]),
    );
  }

  static String _brand(String n) {
    final b = cardBrand(n);
    return b.isEmpty ? '' : ' · $b';
  }

  Widget _row(String key, String label, String value, bool hidden, {bool multiline = false}) {
    final masked = hidden && !shown.contains(key);
    return ListTile(
      key: Key('field-$key'),
      title: Text(label, style: Theme.of(context).textTheme.labelMedium),
      subtitle: SelectableText(masked ? '•' * 10 : value,
          style: TextStyle(fontFamily: hidden || key == 'number' ? 'monospace' : null, fontSize: 16), maxLines: multiline ? null : 3),
      trailing: Row(mainAxisSize: MainAxisSize.min, children: [
        if (hidden)
          IconButton(
            tooltip: masked ? 'Show' : 'Hide',
            icon: Icon(masked ? Icons.visibility : Icons.visibility_off),
            onPressed: () => setState(() => masked ? shown.add(key) : shown.remove(key)),
          ),
        IconButton(tooltip: 'Copy', icon: const Icon(Icons.copy, size: 20), onPressed: () => copy(label, value)),
      ]),
    );
  }
}
