import 'dart:math';

import 'package:flutter/material.dart';

import '../app.dart';
import '../settings.dart';
import '../validate.dart' as v;
import '../widgets.dart';
import 'provider_card.dart';

/// Threshold passkeys: register one for a site, and sign with it.
class PasskeysPage extends StatefulWidget {
  final App app;
  const PasskeysPage({super.key, required this.app});

  @override
  State<PasskeysPage> createState() => _PasskeysPageState();
}

class _PasskeysPageState extends State<PasskeysPage> {
  final query = TextEditingController();
  int filter = 0;      // all, usable under duress

  App get app => widget.app;

  @override
  void initState() {
    super.initState();
    query.addListener(() => setState(() {}));
    // Passkeys the system made through the passkey screen are added to the
    // settings file apart from this app.
    app.settings.reloadCredentials();
  }

  @override
  void dispose() {
    query.dispose();
    super.dispose();
  }

  Future<void> register() async {
    final rp = TextEditingController();
    var duress = false;
    String? problem;
    final go = await showModalBottomSheet<bool>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, set) => Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 16 + MediaQuery.viewInsetsOf(ctx).bottom),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Text('New passkey', style: Theme.of(ctx).textTheme.titleLarge),
            const SizedBox(height: 12),
            Field(rp, 'Site', hint: 'login.example.com', url: true, fieldKey: const Key('rp'), action: TextInputAction.done, check: v.hostName),
            CheckboxListTile(
              contentPadding: EdgeInsets.zero,
              value: duress,
              onChanged: (v) => set(() => duress = v ?? false),
              title: const Text('Usable under the duress PIN'),
            ),
            WideButton('Create passkey', key: const Key('register'), onPressed: () {
              final m = v.hostName(rp.text);
              if (m != null) return set(() => problem = m);
              Navigator.of(ctx).pop(true);
            }),
            if (problem != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(problem!, style: TextStyle(color: Theme.of(ctx).colorScheme.error))),
          ]),
        ),
      ),
    );
    final name = rp.text.trim().toLowerCase();
    if (go != true || name.isEmpty || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Creating a passkey for $name', () => app.cli.register(app.dir, name, p, duress: duress), usually: 'a few seconds'));
    final id = r?.field('credential-id');
    final pub = r?.field('public-key');
    if (r == null || !r.ok || id == null || pub == null) return;
    await app.settings.addCredential(Credential(name, id, pub, duress: duress));
    if (mounted) {
      setState(() {});
      toast(context, 'Passkey for $name created');
    }
  }

  Future<void> sign(Credential c, {bool test = true}) async {
    String hex;
    if (test) {
      final rnd = Random.secure();
      hex = List.generate(32, (_) => rnd.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
    } else {
      final msg = TextEditingController();
      final d = await showDialog<String>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Sign a digest'),
          content: Field(msg, 'SHA-256 digest (64 hex digits)', action: TextInputAction.done, check: v.hexBytes(32)),
          actions: [
            TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Cancel')),
            FilledButton(onPressed: () => Navigator.of(ctx).pop(msg.text.trim()), child: const Text('Sign')),
          ],
        ),
      );
      if (d == null || !mounted) return;
      if (v.hexBytes(32)(d) != null) return toast(context, 'A digest is 64 hex digits.');
      hex = d.toLowerCase();
    }
    final r = await app.withPin(context, (p) => runTask(context, 'Signing for ${c.rp}', () => app.cli.sign(app.dir, c.rp, c.id, hex, p),
        detail: 'This device and the cosigner sign together; neither can alone.', usually: '10-30 seconds'));
    if (r == null || !r.ok || !mounted) return;
    final sig = r.lines.isEmpty ? '' : r.lines.last;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Signed', key: Key('signed')),
        content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text(test ? 'A test signature over a random digest, made with the cosigner.' : 'Made with the cosigner.'),
          const SizedBox(height: 8),
          HexValue('Digest', hex),
          HexValue('Signature (r || s)', sig),
          HexValue('Public key', c.publicKey),
        ]),
        actions: [FilledButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Close'))],
      ),
    );
  }

  void details(Credential c) {
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Text(c.rp, style: Theme.of(ctx).textTheme.titleLarge),
            if (c.duress) const Text('Also usable under the duress PIN'),
            const SizedBox(height: 8),
            HexValue('Credential ID', c.id),
            HexValue('Public key', c.publicKey),
            const SizedBox(height: 12),
            WideButton('Test signature', key: const Key('test-sign'), icon: Icons.draw, onPressed: () {
              Navigator.of(ctx).pop();
              sign(c);
            }),
            const SizedBox(height: 8),
            WideButton('Sign a digest…', tonal: true, onPressed: () {
              Navigator.of(ctx).pop();
              sign(c, test: false);
            }),
            TextButton(
              onPressed: () async {
                Navigator.of(ctx).pop();
                await app.settings.removeCredential(c.id);
                if (mounted) setState(() {});
              },
              child: const Text('Remove from this list'),
            ),
          ]),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = app.settings.credentials;
    final q = query.text.trim().toLowerCase();
    final shown = cs.where((c) => (filter == 0 || c.duress) && (c.rp.toLowerCase().contains(q) || c.userName.toLowerCase().contains(q))).toList()
      ..sort((a, b) => a.rp.compareTo(b.rp));
    return Scaffold(
      floatingActionButton: FloatingActionButton.extended(heroTag: null, key: const Key('new-passkey'), onPressed: register, icon: const Icon(Icons.add), label: const Text('Passkey')),
      body: PageBody(children: [
        const ProviderCard(),
        if (cs.isEmpty)
          const Section('No passkeys yet', children: [
            Text('A Symbolon passkey signs in to a site without a password. Its key is split between this device and the cosigner, '
                'so a stolen device alone cannot use it.'),
          ]),
        if (cs.isNotEmpty) ...[
          FilterBar(
            query: query,
            hint: 'Search ${cs.length} passkey${cs.length == 1 ? '' : 's'}',
            filters: const ['All', 'Duress'],
            selected: filter,
            onSelected: (i) => setState(() => filter = i),
          ),
          if (shown.isEmpty) const Padding(padding: EdgeInsets.all(24), child: Center(child: Text('Nothing matches.'))),
        ],
        for (final c in shown)
          Card(
            child: ListTile(
              key: Key('passkey-${c.rp}'),
              leading: CircleAvatar(
                backgroundColor: Colors.indigo.withValues(alpha: 0.15),
                foregroundColor: Colors.indigo,
                child: const Icon(Icons.key),
              ),
              title: Text(c.rp),
              subtitle: Wrap(spacing: 6, runSpacing: 4, crossAxisAlignment: WrapCrossAlignment.center, children: [
                const KindTag('Passkey', Colors.indigo),
                if (c.userName.isNotEmpty) Text(c.userName, style: Theme.of(context).textTheme.bodySmall),
                if (c.duress) const KindTag('Duress', Colors.orange),
              ]),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => details(c),
            ),
          ),
        const SizedBox(height: 72),
      ]),
    );
  }
}
