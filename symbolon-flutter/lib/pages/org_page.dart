import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app.dart';
import '../managed.dart';
import '../vault_types.dart' show unhex;
import '../widgets.dart';

/// The organization as `org show` prints it.
class OrgInfo {
  final String id;
  final String name;
  final String role;         // owner, admin, member, pending
  final String policy;
  final String recovery;
  final List<RecoveryRequest> requests;
  const OrgInfo(this.id, this.name, this.role, this.policy, this.recovery, this.requests);

  bool get admin => role == 'owner' || role == 'admin';

  static OrgInfo? parse(List<String> lines) {
    String id = '', name = '', role = '', policy = '', recovery = '';
    final reqs = <RecoveryRequest>[];
    for (final l in lines) {
      final p = l.trim().split(' ');
      if (p.length == 3 && p[0] == 'org') {
        id = p[1];
        try {
          name = unhex(p[2]);
        } on FormatException {
          name = '';
        }
      }
      if (p.length == 2 && p[0] == 'role') role = p[1];
      if (p[0] == 'policy') policy = l.substring(7).trim();
      if (p[0] == 'recovery') recovery = l.substring(9).trim();
      if (p.length == 4 && p[0] == 'recovery-request') reqs.add(RecoveryRequest(p[1], p[2], int.tryParse(p[3]) ?? 0));
    }
    return id.length == 32 ? OrgInfo(id, name, role, policy, recovery, reqs) : null;
  }
}

/// Someone asked to open one of this person's work folders (SPEC 29.8).
class RecoveryRequest {
  final String folder;
  final String requester;
  final int opensAt;
  const RecoveryRequest(this.folder, this.requester, this.opensAt);
}

/// A change queued at the relay's console, waiting for a device to sign it.
class ConsoleChange {
  final String id;
  final String kind;
  final List<String> args;
  final String status;
  const ConsoleChange(this.id, this.kind, this.args, this.status);

  static String _t(String h) {
    if (h == '-') return '';
    try {
      return unhex(h);
    } on FormatException {
      return '';
    }
  }

  static ConsoleChange? parse(String line) {
    final p = line.trim().split(' ');
    if (p.length != 8 || p[0].length != 32) return null;
    return ConsoleChange(p[0], p[1], [_t(p[2]), _t(p[3]), _t(p[4])].where((a) => a.isNotEmpty).toList(), p[6]);
  }

  String get title => '$kind ${args.join(' ')}'.trim();
}

/// A member as `org members` prints it.
class OrgMember {
  final String log;
  final String name;
  final String ext;
  final String role;
  const OrgMember(this.log, this.name, this.ext, this.role);

  static OrgMember? parse(String line) {
    final p = line.trim().split(' ');
    if (p.length != 5 || p[0].length != 64) return null;
    try {
      return OrgMember(p[0], p[1] == '-' ? '' : unhex(p[1]), p[2] == '-' ? '' : unhex(p[2]), p[3]);
    } on FormatException {
      return null;
    }
  }
}

/// The person's organization: who is in it, its policy and recovery
/// setting, and recovery requests that concern them. Administrators
/// invite people and sync. Without an organization: joining, with what
/// device management set filled in.
class OrgPage extends StatefulWidget {
  final App app;
  final Future<ManagedConfig> Function() managed;
  const OrgPage({super.key, required this.app, this.managed = ManagedConfig.read});

  @override
  State<OrgPage> createState() => _OrgPageState();
}

class _OrgPageState extends State<OrgPage> {
  OrgInfo? info;
  List<OrgMember> members = [];
  List<ConsoleChange> changes = [];
  ManagedConfig managed = const ManagedConfig();
  bool loading = true;
  String? problem;
  final orgC = TextEditingController();
  final founderC = TextEditingController();
  final codeC = TextEditingController();

  App get app => widget.app;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => load());
  }

  Future<void> load() async {
    setState(() => loading = true);
    final m = await widget.managed();
    final r = await app.cli.orgShow(app.dir);
    final ms = r.ok ? await app.cli.orgMembers(app.dir) : null;
    final cs = r.ok ? await app.cli.orgChanges(app.dir) : null;
    if (!mounted) return;
    setState(() {
      loading = false;
      managed = m;
      info = r.ok ? OrgInfo.parse(r.lines) : null;
      problem = r.ok || r.err.contains('in no organization') ? null : friendlyError(r);
      members = ms != null && ms.ok ? ms.lines.map(OrgMember.parse).whereType<OrgMember>().toList() : [];
      changes = cs != null && cs.ok ? cs.lines.map(ConsoleChange.parse).whereType<ConsoleChange>().where((c) => c.status == 'pending').toList() : [];
      if (orgC.text.isEmpty) orgC.text = m.orgId;
      if (founderC.text.isEmpty) founderC.text = m.founder;
      if (codeC.text.isEmpty) codeC.text = m.inviteCode;
    });
  }

  Future<void> join() async {
    final org = orgC.text.trim().toLowerCase(), founder = founderC.text.trim().toLowerCase(), code = codeC.text.trim().toLowerCase();
    if (org.length != 32 || founder.length != 64 || (code.isNotEmpty && code.length != 32)) {
      toast(context, 'An organization id has 32 hex digits, its founder 64, an invite code 32.');
      return;
    }
    final r = await app.withPin(context, (p) => runTask(context, 'Joining', () => app.cli.orgJoin(app.dir, org, founder, code, p), usually: 'a few seconds'));
    if (r == null || !mounted) return;
    if (!r.ok) {
      toast(context, friendlyError(r));
      return;
    }
    if (r.lines.isNotEmpty && r.lines.last.endsWith(' pending')) {
      await showOutput(context, 'Waiting for an administrator', 'Your answer is with the organization. You are added the next time an administrator syncs.');
    }
    load();
  }

  Future<void> invite() async {
    final ext = TextEditingController(), name = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Invite someone'),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          TextField(key: const Key('org-invite-ext'), controller: ext, decoration: const InputDecoration(labelText: 'Directory id (work e-mail)')),
          TextField(key: const Key('org-invite-name'), controller: name, maxLength: 64, decoration: const InputDecoration(labelText: 'Name')),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(key: const Key('org-invite-ok'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Invite')),
        ],
      ),
    );
    if (ok != true || ext.text.trim().isEmpty || name.text.trim().isEmpty || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Inviting', () => app.cli.orgInvite(app.dir, ext.text.trim(), name.text.trim(), p), usually: 'a few seconds'));
    if (r == null || !mounted) return;
    if (!r.ok) {
      toast(context, friendlyError(r));
      return;
    }
    final code = r.lines.isEmpty ? '' : r.lines.last.split(' ').first;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Invite code'),
        content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Text('Give this code to the person through the company (work e-mail or device management). It works once, for 14 days.'),
          const SizedBox(height: 12),
          SelectableText(code, key: const Key('org-invite-code'), style: const TextStyle(fontFamily: 'monospace')),
        ]),
        actions: [
          TextButton(onPressed: () => Clipboard.setData(ClipboardData(text: code)), child: const Text('Copy')),
          FilledButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Done')),
        ],
      ),
    );
  }

  Future<void> sync() async {
    final r = await app.withPin(context, (p) => runTask(context, 'Syncing the organization', () => app.cli.orgSync(app.dir, p), usually: 'a minute'));
    if (r == null || !mounted) return;
    if (!r.ok) {
      toast(context, friendlyError(r));
      return;
    }
    await showOutput(context, 'Synced', r.lines.isEmpty ? 'Nothing to change.' : r.lines.join('\n'));
    load();
  }

  Future<void> approve(ConsoleChange c) async {
    final r = await app.withPin(context, (p) => runTask(context, 'Signing ${c.kind}', () => app.cli.orgApprove(app.dir, c.id, p), usually: 'a minute'));
    if (r == null || !mounted) return;
    if (!r.ok) {
      toast(context, friendlyError(r));
    } else {
      await showOutput(context, 'Done', r.lines.join('\n'));
    }
    load();
  }

  Future<void> consoleKey() async {
    final code = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Approve a console passkey'),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('The console shows a code after you register a passkey there. Approve only a code you see on your own screen.'),
          TextField(key: const Key('org-console-code'), controller: code, decoration: const InputDecoration(labelText: 'Code')),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(key: const Key('org-console-ok'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Approve')),
        ],
      ),
    );
    if (ok != true || code.text.trim().isEmpty || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Approving', () => app.cli.orgConsoleKey(app.dir, code.text.trim(), p), usually: 'a few seconds'));
    if (r != null && mounted) toast(context, r.ok ? 'Approved: sign in at the console.' : friendlyError(r));
  }

  String when(int t) => DateTime.fromMillisecondsSinceEpoch(t * 1000).toLocal().toString().substring(0, 16);

  @override
  Widget build(BuildContext context) {
    final o = info;
    return Scaffold(
      appBar: AppBar(title: const Text('Organization')),
      body: RefreshIndicator(
        onRefresh: load,
        child: PageBody(children: [
          if (loading) const Center(child: CircularProgressIndicator())
          else if (problem != null)
            Section('Organization', children: [Text(problem!, key: const Key('org-problem')), WideButton('Try again', icon: Icons.refresh, onPressed: load)])
          else if (o == null)
            Section('Join your organization', children: [
              Text(managed.hasOrg ? 'Your company set up this device for its organization. Check the code and join.'
                  : 'Your company gives you its organization id, its founder\'s id and an invite code.'),
              TextField(key: const Key('org-id'), controller: orgC, decoration: const InputDecoration(labelText: 'Organization id')),
              TextField(key: const Key('org-founder'), controller: founderC, decoration: const InputDecoration(labelText: 'Founder')),
              TextField(key: const Key('org-code'), controller: codeC, decoration: const InputDecoration(labelText: 'Invite code')),
              const SizedBox(height: 12),
              WideButton('Join', key: const Key('org-join'), icon: Icons.business, onPressed: join),
            ])
          else ...[
            for (final q in o.requests)
              Card(
                key: Key('org-request-${q.folder}'),
                color: Theme.of(context).colorScheme.errorContainer,
                child: ListTile(
                  leading: const Icon(Icons.warning_amber),
                  title: const Text('Recovery requested'),
                  subtitle: Text('An administrator asked to open your work folder ${q.folder.substring(0, 8)}. It can open after ${when(q.opensAt)}.'),
                ),
              ),
            Section(o.name.isEmpty ? 'Organization' : o.name, children: [
              ListTile(contentPadding: EdgeInsets.zero, key: const Key('org-role'), leading: const Icon(Icons.badge_outlined), title: Text('You are ${o.role == 'admin' ? 'an administrator' : o.role == 'pending' ? 'waiting to be added' : 'a${o.role == 'owner' ? 'n' : ''} ${o.role}'}')),
              ListTile(contentPadding: EdgeInsets.zero, leading: const Icon(Icons.policy_outlined), title: const Text('Recovery'),
                  subtitle: Text(o.recovery.startsWith('on') ? 'On (${o.recovery.substring(3)} s): administrators together can open work folders you escrow, never your own vault.' : 'Off: no one but you can open your folders.')),
            ]),
            if (o.admin)
              Section('Administration', children: [
                WideButton('Invite someone', key: const Key('org-invite'), icon: Icons.person_add_alt, onPressed: invite),
                const SizedBox(height: 8),
                WideButton('Sync', key: const Key('org-sync'), icon: Icons.sync, onPressed: sync),
                const SizedBox(height: 8),
                WideButton('Approve a console passkey', key: const Key('org-console-key'), icon: Icons.key, onPressed: consoleKey),
              ]),
            if (o.admin && changes.isNotEmpty)
              Section('Changes from the console (${changes.length})', children: [
                const Text('Queued at the console; they take effect when this device signs them.'),
                for (final c in changes)
                  ListTile(
                    key: Key('org-change-${c.id}'),
                    contentPadding: EdgeInsets.zero,
                    leading: const Icon(Icons.pending_actions),
                    title: Text(c.title),
                    trailing: TextButton(key: Key('org-approve-${c.id}'), onPressed: () => approve(c), child: const Text('Approve')),
                  ),
              ]),
            Section('People (${members.length})', children: [
              for (final m in members)
                ListTile(
                  key: Key('org-member-${m.name}'),
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(m.role == 'member' ? Icons.person_outline : Icons.admin_panel_settings_outlined),
                  title: Text(m.name.isEmpty ? m.log.substring(0, 12) : m.name),
                  subtitle: Text([if (m.ext.isNotEmpty) m.ext, m.role].join(' · ')),
                ),
            ]),
          ],
        ]),
      ),
    );
  }
}
