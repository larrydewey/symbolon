import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app.dart';
import '../managed.dart';
import '../vault_types.dart' show unhex;
import '../widgets.dart';
import 'vault_page.dart';

/// A shared folder as `share list` prints it.
class SharedFolder {
  final String id;
  final String name;
  final bool owner;
  final int people;
  final String waiting;      // why this device has no key yet, "" when it has
  final bool duress;         // this device opens it under the duress PIN too
  const SharedFolder(this.id, this.name, {this.owner = false, this.people = 1, this.waiting = '', this.duress = false});

  static SharedFolder? parse(String line) {
    final p = line.trim().split(' ');
    if (p.length < 4 || p.length > 5 || p[0].length != 32) return null;
    try {
      if (p[1] == '-' && p[2] == 'waiting') return SharedFolder(p[0], 'Shared folder', waiting: unhex(p[3]));
      if (p[2] != 'owner' && p[2] != 'member') return null;
      return SharedFolder(p[0], unhex(p[1]), owner: p[2] == 'owner', people: int.tryParse(p[3]) ?? 1, duress: p.length == 5 && p[4] == 'duress');
    } on FormatException {
      return null;
    }
  }
}

/// A person: a card at the relay (`share people`) or a folder's member
/// (`share members`).
class Person {
  final String log;
  final String name;
  final String fingerprint;
  final String role;          // "me", "-", "owner", "member"
  const Person(this.log, this.name, this.fingerprint, this.role);

  static Person? parse(String line) {
    final p = line.trim().split(' ');
    if (p.length != 4 || p[0].length != 64) return null;
    try {
      return Person(p[0], p[1] == '-' ? '' : unhex(p[1]), p[2], p[3]);
    } on FormatException {
      return null;
    }
  }
}

/// A fingerprint as people read it out: groups of five digits.
String spaced(String fp) => fp.replaceAll('-', ' ');

/// Sharing: folders shared with the people in the household, each with
/// its own key that only their devices hold; the name others see this
/// person by, and the fingerprint they check it with.
class SharingPage extends StatefulWidget {
  final App app;
  const SharingPage({super.key, required this.app});

  @override
  State<SharingPage> createState() => _SharingPageState();
}

class _SharingPageState extends State<SharingPage> {
  List<SharedFolder>? folders;
  String? localCopy;         // why the list is this device's copy (offline), null when it is not
  Person? me;
  String? myFingerprint;
  bool loading = false;

  App get app => widget.app;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => load());
  }

  Future<void> load() async {
    setState(() => loading = true);
    final m = await app.cli.shareMe(app.dir);
    final people = await app.cli.sharePeople(app.dir);
    if (!mounted) return;
    setState(() {
      myFingerprint = m.ok && m.lines.isNotEmpty ? m.lines.first.trim().split(' ').last : null;
      me = people.ok ? people.lines.map(Person.parse).whereType<Person>().where((p) => p.role == 'me').firstOrNull : null;
    });
    final r = await app.withPin(context, (p) => app.cli.shareList(app.dir, p), note: 'Unlock to see your shared folders.');
    if (!mounted) return;
    setState(() {
      loading = false;
      if (r != null && r.ok) localCopy = r.localCopy;
      if (r != null && r.ok) folders = r.lines.map(SharedFolder.parse).whereType<SharedFolder>().toList()..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
    });
    if (r != null && !r.ok) toast(context, friendlyError(r));
  }

  Future<String?> _ask(String title, String label, {String initial = '', String? note, String action = 'Save'}) {
    final c = TextEditingController(text: initial);
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          if (note != null) ...[Text(note), const SizedBox(height: 12)],
          TextField(key: const Key('share-name'), controller: c, autofocus: true, maxLength: 64, decoration: InputDecoration(labelText: label)),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Cancel')),
          FilledButton(key: const Key('share-name-ok'), onPressed: () => Navigator.of(ctx).pop(c.text.trim()), child: Text(action)),
        ],
      ),
    );
  }

  Future<void> setName() async {
    final n = await _ask('Your name', 'Name', initial: me?.name ?? '',
        note: 'The name people in your household see when they share a folder with you. It is signed by this device.');
    if (n == null || n.isEmpty || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Publishing your name', () => app.cli.shareCard(app.dir, n, p), usually: 'a few seconds'));
    if (r != null && r.ok && mounted) load();
  }

  Future<void> create() async {
    final n = await _ask('New shared folder', 'Name', note: 'For example "Family" or "Home". You add people to it next.', action: 'Create');
    if (n == null || n.isEmpty || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Making $n', () => app.cli.shareNew(app.dir, n, p), usually: 'a few seconds'));
    if (r == null || !r.ok || !mounted) return;
    final id = r.lines.map((l) => l.trim()).firstWhere((l) => l.length == 32, orElse: () => '');
    await load();
    if (id.isNotEmpty && mounted) open(SharedFolder(id, n, owner: true));
  }

  Future<void> open(SharedFolder f) async {
    if (f.waiting.isNotEmpty) {
      await showOutput(context, 'Not yet', 'This device does not have the folder\'s key yet. It gets it the next time someone in the folder opens '
          'Sharing on one of their devices.');
      return;
    }
    await Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => SharedFolderPage(app: app, folder: f, offline: localCopy != null)));
    if (mounted) load();
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final fs = folders;
    return Scaffold(
      appBar: AppBar(title: const Text('Sharing')),
      floatingActionButton: fs == null || localCopy != null ? null : FloatingActionButton.extended(key: const Key('share-new'), onPressed: create, icon: const Icon(Icons.create_new_folder_outlined), label: const Text('New shared folder')),
      body: RefreshIndicator(
        onRefresh: load,
        child: PageBody(children: [
          Section('You', children: [
            ListTile(
              key: const Key('share-me'),
              contentPadding: EdgeInsets.zero,
              leading: const CircleAvatar(child: Icon(Icons.person)),
              title: Text(me?.name.isNotEmpty == true ? me!.name : 'No name yet'),
              subtitle: Text(me == null ? 'Choose the name others see you by, so they can share with you.' : 'Others in your household see this name.'),
              trailing: TextButton(key: const Key('share-set-name'), onPressed: setName, child: Text(me == null ? 'Choose' : 'Change')),
            ),
            if (myFingerprint != null) ...[
              const SizedBox(height: 8),
              Text('Your fingerprint', style: t.labelLarge),
              const SizedBox(height: 4),
              SelectableText(spaced(myFingerprint!), key: const Key('share-fingerprint'), style: t.titleMedium?.copyWith(fontFamily: 'monospace', letterSpacing: 1)),
              const SizedBox(height: 4),
              Text('When someone shares a folder with you, they check that their screen shows these digits for you. Read them out to '
                  'each other in person or on a call.', style: t.bodySmall),
            ],
          ]),
          if (localCopy != null)
            Card(
              key: const Key('share-offline'),
              child: ListTile(
                leading: const Icon(Icons.cloud_off),
                title: const Text('Offline'),
                subtitle: Text('Your shared folders as this device last saw them ($localCopy). Changes wait until you are connected.'),
                trailing: IconButton(tooltip: 'Try again', icon: const Icon(Icons.refresh), onPressed: load),
              ),
            ),
          if (fs == null)
            Section('Shared folders', children: [
              if (loading) const Center(child: CircularProgressIndicator()) else WideButton('Unlock', key: const Key('share-unlock'), icon: Icons.lock_open, onPressed: load),
            ])
          else if (fs.isEmpty)
            const Section('Shared folders', children: [
              Text('Nothing shared yet. A shared folder holds what several people use, such as the Wi-Fi, streaming logins or the alarm '
                  'code. Everyone in it can see and change it; the box it is kept on cannot read it.'),
            ])
          else
            Card(
              child: Column(children: [
                for (final f in fs)
                  ListTile(
                    key: Key('folder-${f.name}'),
                    leading: Icon(f.waiting.isEmpty ? Icons.folder_shared : Icons.hourglass_empty),
                    title: Text(f.name),
                    subtitle: Text(f.waiting.isNotEmpty
                        ? 'Waiting for this device\'s key'
                        : '${f.owner ? 'Yours' : 'Shared with you'} · ${f.people} ${f.people == 1 ? 'person' : 'people'}'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => open(f),
                  ),
              ]),
            ),
          const SizedBox(height: 72),
        ]),
      ),
    );
  }
}

/// One shared folder: its items, and who is in it.
class SharedFolderPage extends StatelessWidget {
  final App app;
  final SharedFolder folder;
  final bool offline;
  const SharedFolderPage({super.key, required this.app, required this.folder, this.offline = false});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(folder.name),
        actions: [
          IconButton(
            key: const Key('share-people'),
            tooltip: 'People',
            icon: const Icon(Icons.group_outlined),
            onPressed: () async {
              if (offline) return toast(context, 'Who is in the folder needs a connection to your relay.');
              final gone = await Navigator.of(context).push<bool>(MaterialPageRoute(builder: (_) => PeoplePage(app: app, folder: folder)));
              if (gone == true && context.mounted) Navigator.of(context).pop();
            },
          ),
        ],
      ),
      body: VaultPage(app: app, share: folder.id, active: true),
    );
  }
}

/// Who is in a folder, with their fingerprints; the owner adds and removes
/// people and can delete the folder, a member can leave it; on this device,
/// whether it opens under the duress PIN. Pops true when the folder was
/// deleted or left.
class PeoplePage extends StatefulWidget {
  final App app;
  final SharedFolder folder;
  const PeoplePage({super.key, required this.app, required this.folder});

  @override
  State<PeoplePage> createState() => _PeoplePageState();
}

class _PeoplePageState extends State<PeoplePage> {
  List<Person>? members;
  late bool duress = widget.folder.duress;

  App get app => widget.app;
  bool get owner => widget.folder.owner;

  Future<void> leave() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Leave ${widget.folder.name}?'),
        content: const Text('It goes from all your devices, and the owner\'s phone gives the folder a new key the next time they open '
            'Sharing, so nothing added afterwards reaches you. To come back, the owner adds you again.'),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(key: const Key('leave-ok'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Leave')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Leaving ${widget.folder.name}', () => app.cli.shareLeave(app.dir, widget.folder.id, p), usually: 'a few seconds'));
    if (r != null && r.ok && mounted) Navigator.of(context).pop(true);
  }

  Future<void> setDuress(bool on) async {
    final r = await app.withPin(context, (p) => runTask(context, on ? 'Adding the folder to the duress PIN' : 'Taking the folder off the duress PIN',
        () => app.cli.shareDuress(app.dir, widget.folder.id, on, p), usually: 'a few seconds'));
    if (r != null && r.ok && mounted) setState(() => duress = on);
  }

  bool noDuress = false;   // the organization's device management hides the duress choice

  @override
  void initState() {
    super.initState();
    ManagedConfig.read().then((m) { if (mounted) setState(() => noDuress = m.noDuress); });
    WidgetsBinding.instance.addPostFrameCallback((_) => load());
  }

  Future<void> load() async {
    final r = await app.withPin(context, (p) => app.cli.shareMembers(app.dir, widget.folder.id, p));
    if (!mounted) return;
    if (r == null || !r.ok) {
      if (r != null) toast(context, friendlyError(r));
      return;
    }
    setState(() => members = r.lines.map(Person.parse).whereType<Person>().toList());
  }

  Future<void> add() async {
    final ps = await app.cli.sharePeople(app.dir);
    if (!mounted) return;
    final inside = {for (final m in members ?? <Person>[]) m.log};
    final candidates = ps.lines.map(Person.parse).whereType<Person>().where((p) => p.role != 'me' && !inside.contains(p.log)).toList();
    if (candidates.isEmpty) {
      await showOutput(context, 'No one to add', 'Everyone who has chosen a name in Sharing on their device is listed here. Ask the person to open '
          'More, then Sharing, on their phone and choose their name, then try again.');
      return;
    }
    final who = await showModalBottomSheet<Person>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          ListTile(title: Text('Add to ${widget.folder.name}', style: Theme.of(ctx).textTheme.titleLarge)),
          for (final p in candidates)
            ListTile(key: Key('candidate-${p.name}'), leading: const CircleAvatar(child: Icon(Icons.person)), title: Text(p.name), onTap: () => Navigator.of(ctx).pop(p)),
        ]),
      ),
    );
    if (who == null || !mounted) return;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Is this ${who.name}?'),
        content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Ask ${who.name} to open Sharing on their phone and read you their fingerprint. It must be exactly:'),
          const SizedBox(height: 12),
          SelectableText(spaced(who.fingerprint), key: const Key('candidate-fingerprint'),
              style: Theme.of(ctx).textTheme.titleMedium?.copyWith(fontFamily: 'monospace', letterSpacing: 1)),
          const SizedBox(height: 12),
          const Text('If the digits differ, someone may be pretending to be them: do not add them.'),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('They differ')),
          FilledButton(key: const Key('candidate-ok'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('They match')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Adding ${who.name}', () => app.cli.shareAdd(app.dir, widget.folder.id, who.log, who.name, p), usually: 'a few seconds'));
    if (r != null && r.ok && mounted) load();
  }

  Future<void> remove(Person m) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Remove ${m.name}?'),
        content: Text('${m.name} loses access on all their devices. The folder gets a new key and everything in it is sealed again, so '
            'nothing added or changed from now on reaches them. What they saw before, they may have kept.'),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(key: const Key('remove-ok'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Remove')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Removing ${m.name}', () => app.cli.shareRemove(app.dir, widget.folder.id, m.log, p), usually: 'under a minute'));
    if (r != null && r.ok && mounted) load();
  }

  Future<void> delete() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Delete ${widget.folder.name}?'),
        content: const Text('Everything in it is deleted, for everyone in it. This cannot be undone.'),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(key: const Key('delete-ok'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Delete')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Deleting ${widget.folder.name}', () => app.cli.shareDelete(app.dir, widget.folder.id, p), usually: 'a few seconds'));
    if (r != null && r.ok && mounted) Navigator.of(context).pop(true);
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final ms = members;
    return Scaffold(
      appBar: AppBar(title: Text('People in ${widget.folder.name}')),
      body: PageBody(children: [
        if (ms == null)
          const Padding(padding: EdgeInsets.all(24), child: Center(child: CircularProgressIndicator()))
        else ...[
          Card(
            child: Column(children: [
              for (final m in ms)
                ListTile(
                  key: Key('member-${m.name}'),
                  leading: CircleAvatar(child: Icon(m.role == 'owner' ? Icons.star_outline : Icons.person)),
                  title: Text(m.name.isEmpty ? 'Someone without a name' : m.name),
                  subtitle: Text('${m.role == 'owner' ? 'Owner · ' : ''}${spaced(m.fingerprint)}', style: t.bodySmall?.copyWith(fontFamily: 'monospace')),
                  onLongPress: () {
                    Clipboard.setData(ClipboardData(text: spaced(m.fingerprint)));
                    toast(context, 'Fingerprint copied');
                  },
                  trailing: owner && m.role != 'owner'
                      ? IconButton(key: Key('remove-${m.name}'), tooltip: 'Remove', icon: const Icon(Icons.person_remove_outlined), onPressed: () => remove(m))
                      : null,
                ),
            ]),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8),
            child: Text('Everyone here holds the folder\'s key on their own devices. The digits next to each name are their fingerprint: '
                'they match what their phone shows under Sharing.', style: t.bodySmall),
          ),
          if (owner) ...[
            const SizedBox(height: 8),
            WideButton('Add a person', key: const Key('share-add'), icon: Icons.person_add_alt, onPressed: add),
          ] else
            Text('Only the owner adds or removes people.', style: t.bodySmall),
          const SizedBox(height: 16),
          if (!noDuress) SwitchListTile(
            key: const Key('share-duress'),
            contentPadding: EdgeInsets.zero,
            value: duress,
            onChanged: setDuress,
            title: const Text('Open under the duress PIN'),
            subtitle: const Text('On this device only. Under the duress PIN the folder can be read but not changed; folders without this '
                'stay hidden there.'),
          ),
          const SizedBox(height: 16),
          if (owner)
            TextButton.icon(key: const Key('share-delete'), onPressed: delete, icon: const Icon(Icons.delete_outline), label: const Text('Delete this shared folder'))
          else
            TextButton.icon(key: const Key('share-leave'), onPressed: leave, icon: const Icon(Icons.logout), label: const Text('Leave this shared folder')),
        ],
      ]),
    );
  }
}
