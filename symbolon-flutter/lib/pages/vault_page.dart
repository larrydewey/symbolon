import 'package:flutter/material.dart';

import '../app.dart';
import '../favicons.dart';
import '../vault_types.dart';
import '../widgets.dart';
import 'import_page.dart';
import 'item_editor.dart';
import 'item_page.dart';

/// The vault: logins, cards, identities, notes and more, sealed on this
/// device and kept at the relay, which cannot read them. Offline it shows
/// this device's verified copy, read-only. With [share], a shared folder's
/// items instead (read from the relay only).
class VaultPage extends StatefulWidget {
  final App app;
  final String share;
  const VaultPage({super.key, required this.app, this.share = ''});

  @override
  State<VaultPage> createState() => _VaultPageState();
}

class _VaultPageState extends State<VaultPage> {
  List<VaultItem>? items;
  String? localCopy;      // why the list is this device's copy, when it is
  bool loading = false;
  final query = TextEditingController();
  String filter = '';     // a type, or every type
  String? folder;         // a folder (and those in it), "" for no folder, null for all

  App get app => widget.app;
  String get share => widget.share;

  @override
  void initState() {
    super.initState();
    app.session.addListener(_session);
    query.addListener(() => setState(() {}));
  }

  @override
  void dispose() {
    app.session.removeListener(_session);
    query.dispose();
    super.dispose();
  }

  // Locking hides the names; unlocking elsewhere shows them.
  void _session() {
    if (!app.session.unlocked && items != null) setState(() => items = null);
  }

  void _keep(List<VaultItem> xs) => items = xs..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));

  Future<void> open() async {
    setState(() => loading = true);
    final r = await app.withPin(context, (p) => app.cli.vaultList(app.dir, p, share: share), note: share.isEmpty ? 'Unlock to see your vault.' : 'Unlock to see the shared folder.');
    if (!mounted) return;
    setState(() {
      loading = false;
      if (r != null && r.ok) {
        _keep(r.lines.map(VaultItem.parse).whereType<VaultItem>().toList());
        localCopy = r.localCopy;
      }
    });
    if (r != null && !r.ok) toast(context, friendlyError(r));
  }

  bool get offline => localCopy != null;

  /// Every folder the vault uses, with the folders above each.
  Set<String> get folders {
    final out = <String>{};
    for (final i in items ?? <VaultItem>[]) {
      final p = i.folder.split('/');
      for (var k = 1; k <= p.length && i.folder.isNotEmpty; k++) {
        out.add(p.sublist(0, k).join('/'));
      }
    }
    return out;
  }

  bool _inFolder(VaultItem x) => folder == null || (folder!.isEmpty ? x.folder.isEmpty : (x.folder == folder || x.folder.startsWith('$folder/')));

  Future<void> importFrom() async {
    if (offline) return _needsConnection();
    final done = await Navigator.of(context).push<bool>(MaterialPageRoute(builder: (_) => ImportPage(app: app, share: share)));
    if (done == true && mounted) open();
  }

  void _needsConnection() => toast(context, 'Changes need a connection to your relay. You can still view everything.');

  Future<void> add() async {
    if (offline) return _needsConnection();
    final t = await showModalBottomSheet<ItemType>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => SafeArea(
        child: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            ListTile(title: Text(share.isEmpty ? 'Add to your vault' : 'Add to the shared folder', style: Theme.of(ctx).textTheme.titleLarge)),
            for (final t in itemTypes)
              ListTile(
                key: Key('add-${t.id}'),
                leading: TypeAvatar(t),
                title: Text(t.label),
                onTap: () => Navigator.of(ctx).pop(t),
              ),
          ]),
        ),
      ),
    );
    if (t == null || !mounted) return;
    final saved = await Navigator.of(context).push<VaultItem>(
        MaterialPageRoute(builder: (_) => ItemEditor(app: app, type: t, names: {for (final i in items ?? <VaultItem>[]) i.name}, folders: folders, folder: folder ?? '', share: share)));
    if (saved != null && mounted) setState(() => _keep([...?items?.where((x) => x.name != saved.name), saved]));
  }

  Future<void> show(VaultItem it) async {
    final change = await Navigator.of(context).push<ItemChange>(
        MaterialPageRoute(builder: (_) => ItemPage(app: app, item: it, offline: offline, names: {for (final i in items ?? <VaultItem>[]) i.name}, folders: folders, share: share)));
    if (change == null || !mounted) return;
    setState(() => _keep([...?items?.where((x) => x.name != it.name && x.name != change.saved?.name), ?change.saved]));
  }

  @override
  Widget build(BuildContext context) {
    final all = items;
    if (all == null && app.session.unlocked && !loading) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted && items == null && !loading) open();
      });
    }
    final q = query.text.trim().toLowerCase();
    final present = itemTypes.where((t) => all?.any((i) => i.type == t.id) ?? false).toList();
    final shown = all
        ?.where((x) => (filter.isEmpty || x.type == filter) && _inFolder(x) && (x.name.toLowerCase().contains(q) || x.detail.toLowerCase().contains(q) || x.folder.toLowerCase().contains(q)))
        .toList();
    return Scaffold(
      floatingActionButton: all == null ? null : FloatingActionButton.extended(heroTag: null, key: const Key('vault-add'), onPressed: add, icon: const Icon(Icons.add), label: const Text('Add')),
      body: RefreshIndicator(
        onRefresh: all == null ? () async {} : open,
        child: PageBody(children: [
          if (all == null || shown == null)
            Section(share.isEmpty ? 'Your vault is locked' : 'Locked', children: [
              Text(share.isEmpty
                  ? 'Logins, cards, identities and notes, sealed on this device. The relay keeps a copy it cannot read, and this '
                      'device keeps one for when you are offline.'
                  : 'Everything here is sealed under the folder\'s own key, which only the devices of the people in it have.'),
              const SizedBox(height: 16),
              if (loading) const Center(child: CircularProgressIndicator()) else WideButton('Unlock', key: const Key('open-vault'), icon: Icons.lock_open, onPressed: open),
            ])
          else ...[
            if (offline) _OfflineBanner(reason: localCopy!, onRetry: open),
            if (all.isEmpty)
              Section('Empty', children: [
                Text(share.isEmpty
                    ? 'Add a login, a card, an identity, a note and more with the button below.'
                    : 'Add what the people in this folder share: the Wi-Fi, streaming logins, the alarm code. Everyone in it can see and change it.'),
                if (share.isEmpty) ...[
                  const SizedBox(height: 12),
                  const Text('Moving from another password manager? Bring everything across in one go.'),
                  const SizedBox(height: 12),
                  WideButton('Import from another password manager', key: const Key('vault-import'), icon: Icons.move_to_inbox, tonal: true, onPressed: importFrom),
                ],
              ])
            else ...[
              FilterBar(
                query: query,
                hint: 'Search ${all.length} item${all.length == 1 ? '' : 's'}',
                filters: ['All', for (final t in present) t.plural],
                selected: filter.isEmpty ? 0 : present.indexWhere((t) => t.id == filter) + 1,
                onSelected: (i) => setState(() => filter = i == 0 ? '' : present[i - 1].id),
              ),
              if (folders.isNotEmpty) _FolderPicker(folders: folders, selected: folder, onSelected: (f) => setState(() => folder = f)),
              if (shown.isEmpty) const Padding(padding: EdgeInsets.all(24), child: Center(child: Text('Nothing matches.'))),
            ],
            for (final it in shown)
              Card(
                child: ListTile(
                  key: Key('item-${it.name}'),
                  leading: it.type == 'login'
                      ? SiteIcon(favicons: app.favicons, origin: it.detail, fallback: TypeAvatar(it.kind))
                      : TypeAvatar(it.kind),
                  title: Text(it.name),
                  subtitle: Wrap(spacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
                    KindTag(it.kind.label, it.kind.color),
                    if (it.type == 'login' || it.type == 'card') Text(it.subtitle, style: Theme.of(context).textTheme.bodySmall),
                    if (it.folder.isNotEmpty && folder != it.folder)
                      Row(mainAxisSize: MainAxisSize.min, children: [
                        const Icon(Icons.folder_outlined, size: 14),
                        const SizedBox(width: 2),
                        Text(it.folder.replaceAll('/', ' › '), style: Theme.of(context).textTheme.bodySmall),
                      ]),
                  ]),
                  trailing: const Icon(Icons.chevron_right),
                  onTap: () => show(it),
                ),
              ),
            const SizedBox(height: 72),
          ],
        ]),
      ),
    );
  }
}

/// Which folder the list shows: all, those without one, or a folder and the
/// folders inside it.
class _FolderPicker extends StatelessWidget {
  final Set<String> folders;
  final String? selected;
  final ValueChanged<String?> onSelected;
  const _FolderPicker({required this.folders, required this.selected, required this.onSelected});

  @override
  Widget build(BuildContext context) {
    final sorted = folders.toList()..sort((a, b) => a.toLowerCase().compareTo(b.toLowerCase()));
    String label(String? f) => f == null ? 'All folders' : (f.isEmpty ? 'No folder' : f.replaceAll('/', ' › '));
    return Align(
      alignment: Alignment.centerLeft,
      child: Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: MenuAnchor(
          builder: (context, c, _) => ActionChip(
            key: const Key('folder-picker'),
            avatar: const Icon(Icons.folder_outlined, size: 18),
            label: Text(label(selected)),
            onPressed: () => c.isOpen ? c.close() : c.open(),
          ),
          menuChildren: [
            for (final f in <String?>[null, '', ...sorted])
              MenuItemButton(
                key: Key('folder-${f ?? '*'}'),
                leadingIcon: Icon(f == selected ? Icons.check : (f == null ? Icons.folder_copy_outlined : Icons.folder_outlined), size: 18),
                onPressed: () => onSelected(f),
                child: Padding(padding: EdgeInsets.only(left: f == null || f.isEmpty ? 0 : 12.0 * (f.split('/').length - 1)), child: Text(f == null || f.isEmpty ? label(f) : f.split('/').last)),
              ),
          ],
        ),
      ),
    );
  }
}

/// A type's icon in a tinted circle.
class TypeAvatar extends StatelessWidget {
  final ItemType type;
  const TypeAvatar(this.type, {super.key});

  @override
  Widget build(BuildContext context) => CircleAvatar(
        backgroundColor: type.color.withValues(alpha: 0.15),
        foregroundColor: type.color,
        child: Icon(type.icon),
      );
}

class _OfflineBanner extends StatelessWidget {
  final String reason;
  final VoidCallback onRetry;
  const _OfflineBanner({required this.reason, required this.onRetry});

  static bool isOffline(String r) {
    final l = r.toLowerCase();
    return l.contains('no log at the relay') || l.contains('connect') || l.contains('unreachable') || l.contains('has no vault');
  }

  @override
  Widget build(BuildContext context) {
    final net = isOffline(reason);
    return Card(
      key: const Key('offline-banner'),
      color: net ? Colors.blueGrey.withValues(alpha: 0.15) : Colors.orange.withValues(alpha: 0.18),
      margin: const EdgeInsets.only(bottom: 12),
      child: ListTile(
        leading: Icon(net ? Icons.cloud_off : Icons.gpp_maybe, color: net ? Colors.blueGrey : Colors.orange),
        title: Text(net ? 'Offline' : 'The relay\'s copy did not verify'),
        subtitle: Text(net
            ? 'Showing the copy on this device from your last sync. You can view and copy everything; changes need a connection.'
            : 'Showing the copy this device verified last ($reason). Changes are blocked until the relay serves a valid vault.'),
        trailing: IconButton(tooltip: 'Try again', icon: const Icon(Icons.refresh), onPressed: onRetry),
      ),
    );
  }
}
