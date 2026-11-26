import 'dart:io';

import 'package:material_ui/material_ui.dart';

import '../app.dart';
import '../vault_types.dart' show unhex;
import '../widgets.dart';

/// Security keys (SPEC 9.4): FIDO2 keys that must be present and touched,
/// besides the PIN, for this device to open.
class SecurityKeysPage extends StatefulWidget {
  final App app;
  const SecurityKeysPage({super.key, required this.app});

  @override
  State<SecurityKeysPage> createState() => _SecurityKeysPageState();
}

class _SecurityKeysPageState extends State<SecurityKeysPage> {
  List<String>? names;
  bool fillsNeedKey = false;   // the device's fill policy (SPEC 22.7 item 2), from its fill-policy file
  App get app => widget.app;

  @override
  void initState() {
    super.initState();
    load();
  }

  // With the PIN the session holds (or the one an add or remove just used),
  // so that the list is the one that PIN sees (under the duress PIN, its
  // acted changes: SPEC 14.2).
  Future<void> load({String? pin}) async {
    final r = await app.cli.keyList(app.dir, pin: pin ?? app.session.held);
    final policy = File('${app.dir}/fill-policy');
    final need = await policy.exists() && (await policy.readAsString()).startsWith('keys');
    if (!mounted) return;
    setState(() {
      names = r.ok ? [for (final l in r.lines) unhex(l.trim())] : [];
      fillsNeedKey = need;
    });
  }

  Future<void> setFills(bool needKey) async {
    final r = await app.withPin(context, (p) => runTask(context, needKey ? 'Requiring a key for fills' : 'Allowing fills with the PIN', () => app.cli.keyFills(app.dir, needKey, p),
        detail: (names ?? []).isEmpty ? null : 'Touch any enrolled key.', usually: 'a few seconds'));
    if (r != null && r.ok && mounted) {
      toast(context, r.lines.isEmpty ? 'Saved' : '${r.lines.last[0].toUpperCase()}${r.lines.last.substring(1)}.');
      load();
    }
  }

  Future<String?> askName() {
    final c = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Name this key'),
        content: TextField(key: const Key('key-name'), controller: c, autofocus: true, decoration: const InputDecoration(labelText: 'Name', hintText: 'YubiKey on my keyring', border: OutlineInputBorder())),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Cancel')),
          FilledButton(key: const Key('key-name-ok'), onPressed: () => Navigator.of(ctx).pop(c.text.trim()), child: const Text('OK')),
        ],
      ),
    );
  }

  Future<void> add() async {
    final n = await askName();
    if (n == null || n.isEmpty || !mounted) return;
    if (names?.contains(n) ?? false) return toast(context, 'A key named $n is already enrolled');
    String? used;
    final r = await app.withPin(context, (p) {
      used = p;
      return runTask(context, 'Adding $n', () => app.cli.keyAdd(app.dir, n, p),
          detail: 'Plug the key in and touch it when it blinks: twice${(names?.isNotEmpty ?? false) ? ', after a key you already enrolled' : ''}.', usually: 'under a minute');
    });
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    app.session.lock();      // the next action asks again, with the key
    toast(context, '$n added. From now on this device opens only with an enrolled key present.');
    await load(pin: used);
  }

  Future<void> remove(String n) async {
    final last = (names?.length ?? 0) == 1;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Remove $n?'),
        content: Text(last ? 'This is the last key: the device will open with the PIN alone again.' : 'Another enrolled key still opens this device.'),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(key: const Key('key-remove-ok'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Remove')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    String? used;
    final r = await app.withPin(context, (p) {
      used = p;
      return runTask(context, 'Removing $n', () => app.cli.keyRemove(app.dir, n, p), detail: 'Touch any enrolled key.', usually: 'a few seconds');
    });
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    await load(pin: used);
  }

  @override
  Widget build(BuildContext context) {
    final ns = names;
    return Scaffold(
      appBar: AppBar(title: const Text('Security keys')),
      body: ns == null
          ? const Center(child: CircularProgressIndicator())
          : PageBody(children: [
              const Text('A security key (a YubiKey or another FIDO2 key) adds something you have to the PIN: '
                  'this device opens only with an enrolled key plugged in and touched. Enroll a second key as a backup.'),
              const SizedBox(height: 12),
              if (ns.isEmpty) const Card(child: ListTile(key: Key('keys-none'), title: Text('No security key: the PIN alone opens this device'))),
              for (final n in ns)
                Card(
                  child: ListTile(
                    key: Key('key-$n'),
                    leading: const Icon(Icons.usb),
                    title: Text(n),
                    trailing: IconButton(key: Key('key-remove-$n'), tooltip: 'Remove', icon: const Icon(Icons.delete_outline), onPressed: () => remove(n)),
                  ),
                ),
              const SizedBox(height: 12),
              WideButton(ns.isEmpty ? 'Add a security key' : 'Add a backup key', key: const Key('key-add'), icon: Icons.add, onPressed: add),
              const SizedBox(height: 16),
              Card(
                child: SwitchListTile(
                  key: const Key('fills-need-key'),
                  title: const Text('Fills need a security key'),
                  subtitle: Text(fillsNeedKey && ns.isEmpty
                      ? 'No key is enrolled, so this device fills nothing until one is.'
                      : 'Filling a login or a card into a page or an app asks for a touch of your key every time, and this device '
                          'refuses to fill on the PIN alone.'),
                  value: fillsNeedKey,
                  onChanged: setFills,
                ),
              ),
            ]),
    );
  }
}
