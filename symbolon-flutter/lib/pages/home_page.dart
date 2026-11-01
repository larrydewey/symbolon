import 'package:flutter/material.dart';

import '../app.dart';
import '../cli.dart';
import '../widgets.dart';
import 'hardware_page.dart';
import 'provider_card.dart';
import 'setup_page.dart';

/// The device and its identity at a glance, as `device status` verifies them.
class HomePage extends StatefulWidget {
  final App app;
  final void Function(int tab) go;
  const HomePage({super.key, required this.app, required this.go});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  CliResult? result;
  bool loading = true;

  @override
  void initState() {
    super.initState();
    refresh();
  }

  Future<void> refresh() async {
    setState(() => loading = true);
    final r = await widget.app.cli.status(widget.app.dir);
    if (!mounted) return;
    setState(() {
      result = r;
      loading = false;
    });
  }

  Future<void> setup() async {
    await Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => SetupPage(app: widget.app)));
    refresh();
  }

  @override
  Widget build(BuildContext context) {
    final r = result;
    final s = r == null ? null : DeviceStatus.parse(r);
    final t = Theme.of(context).textTheme;
    final p = r?.problem.toLowerCase() ?? '';
    final offline = r != null && !r.ok && (p.contains('no log at the relay') || p.contains('cannot connect') || p.contains('unreachable'));
    return RefreshIndicator(
      onRefresh: refresh,
      child: PageBody(children: [
        if (loading && s == null) const Padding(padding: EdgeInsets.all(32), child: Center(child: CircularProgressIndicator())),
        if (!loading && s == null)
          Section('Welcome to Symbolon', children: [
            const Text('This device is not set up yet. Setup creates your identity with a cosigner and witnesses, '
                'and gives you a recovery kit.'),
            const SizedBox(height: 16),
            WideButton('Set up this device', key: const Key('start-setup'), icon: Icons.add_moderator, onPressed: setup),
          ]),
        if (s != null && s.log == null)
          Section('Almost there', children: [
            const Text('This device has its keys but no identity yet. Finish setup to create it.'),
            const SizedBox(height: 16),
            WideButton('Finish setup', key: const Key('start-setup'), icon: Icons.add_moderator, onPressed: setup),
          ]),
        if (s != null && s.log != null) ...[
          Card(
            margin: const EdgeInsets.only(bottom: 16),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Icon(r!.ok ? Icons.verified : (offline ? Icons.cloud_off : Icons.error), color: r.ok ? Colors.green : (offline ? Colors.blueGrey : Colors.red), size: 32),
                  const SizedBox(width: 12),
                  Expanded(
                      child: Text(r.ok ? 'Your identity is verified' : (offline ? 'Offline' : 'Your identity log does not verify'),
                          key: const Key('identity-status'), style: t.titleMedium)),
                  if (loading) const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2)),
                ]),
                if (!r.ok && offline)
                  const Padding(
                    padding: EdgeInsets.only(top: 8),
                    child: Text('Cannot reach your relay. Your vault still opens from the copy on this device, read-only. Signing in with a '
                        'passkey and changes need a connection: a signature always takes this device and the cosigner together.'),
                  ),
                if (!r.ok && !offline) Padding(padding: const EdgeInsets.only(top: 8), child: Text(friendlyError(r), style: const TextStyle(color: Colors.red))),
                if (r.ok) ...[
                  const SizedBox(height: 12),
                  Wrap(spacing: 8, runSpacing: 8, children: [
                    Chip(label: Text('Epoch ${s.epoch ?? '-'}')),
                    Chip(label: Text('${s.parties ?? '-'} parties, any ${s.threshold ?? '-'} sign')),
                    if ((s.pending ?? 0) > 0)
                      Chip(avatar: const Icon(Icons.warning_amber, size: 18, color: Colors.orange), label: Text('${s.pending} pending')),
                  ]),
                ],
              ]),
            ),
          ),
          if ((s.pending ?? 0) > 0)
            Section('A change is pending', children: [
              const Text('A delayed event (a recovery?) is waiting to take effect. If you did not start it, veto it now.'),
              const SizedBox(height: 12),
              WideButton('Review in Recovery', tonal: true, onPressed: () => widget.go(3)),
            ]),
          Row(children: [
            Expanded(child: _Action(Icons.key, 'Passkeys', '${widget.app.settings.credentials.length} here', () => widget.go(1))),
            const SizedBox(width: 12),
            Expanded(child: _Action(Icons.lock, 'Vault', 'Passwords, notes', () => widget.go(2))),
          ]),
          const SizedBox(height: 16),
          const ProviderCard(onlyWhenOff: true),
          Section('This device', children: [
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: Icon(s.unprotected ? Icons.warning_amber : Icons.verified_user, color: s.unprotected ? Colors.orange : Colors.green),
              title: Text(s.unprotected ? 'Protected by your PIN only' : (s.keystore ? 'Protected by the Android Keystore and your PIN' : 'Protected by the TPM and your PIN')),
              subtitle: Text(s.unprotected
                  ? 'No hardware key store protects this device. Tap to see how to use one.'
                  : (s.keystore ? 'The unlock keys and the device key never leave the phone\'s secure hardware.' : 'The unlock keys never leave the TPM.')),
              trailing: s.unprotected ? const Icon(Icons.chevron_right) : null,
              onTap: s.unprotected ? () => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => HardwarePage(keystore: widget.app.settings.keystoreAvailable, strongBox: widget.app.settings.strongBox))) : null,
            ),
            HexValue('Device', s.party),
            HexValue('Identity log', s.log!),
          ]),
        ],
      ]),
    );
  }
}

class _Action extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;
  const _Action(this.icon, this.title, this.subtitle, this.onTap);

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: EdgeInsets.zero,
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Icon(icon, color: Theme.of(context).colorScheme.primary),
            const SizedBox(height: 8),
            Text(title, style: Theme.of(context).textTheme.titleSmall),
            Text(subtitle, style: Theme.of(context).textTheme.bodySmall),
          ]),
        ),
      ),
    );
  }
}
