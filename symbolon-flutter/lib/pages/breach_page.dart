import 'package:material_ui/material_ui.dart';

import '../app.dart';
import '../breach.dart';
import '../settings.dart';
import '../vault_types.dart';
import '../widgets.dart';
import 'item_page.dart';

/// The breach check (SPEC 26.1): every login's password against Pwned
/// Passwords, the passwords seen in published breaches. Only the first five
/// hex digits of each password's SHA-1 leave the device. The findings are
/// kept on this device so the vault, the item and the fill windows can warn.
class BreachPage extends StatefulWidget {
  final App app;
  final String share;            // a shared folder's id, "" for the own vault
  const BreachPage({super.key, required this.app, this.share = ''});

  @override
  State<BreachPage> createState() => _BreachPageState();
}

class _BreachPageState extends State<BreachPage> {
  App get app => widget.app;
  Settings get settings => app.settings;

  @override
  void initState() {
    super.initState();
    settings.addListener(_changed);
  }

  @override
  void dispose() {
    settings.removeListener(_changed);
    super.dispose();
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  Future<void> check() async {
    final Map<String, String> env;
    try {
      env = await breachEnv(settings);
    } on StateError catch (e) {
      if (mounted) toast(context, e.message);
      return;
    } on Exception catch (e) {
      if (mounted) toast(context, 'The check could not start: $e');
      return;
    }
    if (!mounted) return;
    final r = await app.withPin(
        context,
        (p) => runTask(context, 'Checking your passwords', () => app.cli.vaultBreach(app.dir, p, share: widget.share, extraEnv: env),
            detail: 'Only the first five characters of each password\'s hash leave this device.', usually: 'under a minute'),
        note: 'Unlock to check your passwords.');
    if (r == null || !r.ok || !mounted) return;
    final report = BreachReport.parse(r.lines);
    if (report == null) return toast(context, 'The check did not finish. Try again.');
    await settings.setBreach(widget.share, BreachFindings(DateTime.now(), report.breached, checked: report.checked, protected: report.protected));
    if (!mounted) return;
    toast(context, report.breached.isEmpty ? 'No breached passwords found.' : '${report.breached.length} breached password${report.breached.length == 1 ? '' : 's'} found.');
  }

  // The vault's names and folders go with it: editing the item there warns
  // before a rename replaces another item, as from the vault list.
  Future<void> open(String name) async {
    final r = await app.withPin(context, (p) => app.cli.vaultList(app.dir, p, share: widget.share));
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    final items = r.lines.map(VaultItem.parse).whereType<VaultItem>().toList();
    final it = items.where((x) => x.name == name).firstOrNull;
    if (it == null) return toast(context, '$name is no longer in the vault.');
    final folders = {for (final x in items) if (x.folder.isNotEmpty) x.folder};
    await Navigator.of(context).push(MaterialPageRoute<void>(
        builder: (_) => ItemPage(app: app, item: it, offline: r.localCopy != null, names: {for (final x in items) x.name}, folders: folders, share: widget.share)));
  }

  static String _date(DateTime d) {
    final l = d.toLocal();
    String two(int n) => n.toString().padLeft(2, '0');
    return '${l.year}-${two(l.month)}-${two(l.day)} ${two(l.hour)}:${two(l.minute)}';
  }

  @override
  Widget build(BuildContext context) {
    final f = settings.breach[widget.share];
    final found = f == null ? <MapEntry<String, int>>[] : (f.items.entries.toList()..sort((a, b) => b.value.compareTo(a.value)));
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Breached passwords')),
      body: PageBody(children: [
        Section(widget.share.isEmpty ? 'Check your logins' : 'Check the shared folder\'s logins', children: [
          const Text('Symbolon checks each login\'s password against Pwned Passwords, the passwords seen in published data breaches. '
              'A password found there is on the lists attackers try first, even if it is long.'),
          const SizedBox(height: 8),
          Text('Your passwords never leave this device. For each one, only the first five characters of its SHA-1 hash are sent, '
              'and the service answers with hundreds of hashes that start the same way; the match is made here.', style: t.bodySmall),
          const SizedBox(height: 16),
          WideButton(f == null ? 'Check now' : 'Check again', key: const Key('breach-check'), icon: Icons.policy_outlined, onPressed: check),
        ]),
        if (f != null)
          Section(found.isEmpty ? 'Nothing found' : '${found.length} breached password${found.length == 1 ? '' : 's'}',
              key: const Key('breach-result'),
              subtitle: 'Checked ${f.checked} login${f.checked == 1 ? '' : 's'} on ${_date(f.at)}',
              children: [
                if (found.isEmpty)
                  const Text('None of your logins\' passwords appear in known breaches.')
                else ...[
                  const Text('Change these passwords first, starting with your email and your bank: whoever controls your email can reset the rest.'),
                  const SizedBox(height: 8),
                  for (final e in found)
                    ListTile(
                      key: Key('breached-${e.key}'),
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(Icons.gpp_bad_outlined, color: Colors.red),
                      title: Text(e.key),
                      subtitle: Text(seenInBreaches(e.value)),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => open(e.key),
                    ),
                ],
                if (f.protected > 0)
                  Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: Text('${f.protected} protected item${f.protected == 1 ? ' was' : 's were'} not checked: their passwords open only with your quorum.',
                        key: const Key('breach-protected'), style: t.bodySmall),
                  ),
              ]),
      ]),
    );
  }
}
