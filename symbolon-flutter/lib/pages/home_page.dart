import 'package:material_ui/material_ui.dart';

import '../app.dart';
import '../brand.dart';
import '../cli.dart';
import '../widgets.dart';
import 'autofill_card.dart';
import 'devices_page.dart';
import 'hardware_page.dart';
import 'provider_card.dart';
import 'recovery_page.dart';
import 'security_advice_page.dart';
import 'security_update_page.dart';
import 'setup_page.dart';
import 'tutorial_page.dart';

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
  List<Openings> unusual = const [];

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
    await _openings(r);
  }

  // Protected openings well above a device's usual (SPEC 18.10.4): shown on
  // every device, as the likely sign of malware in an unlocked one. Asked
  // only while the app is unlocked, so the home page never asks for the PIN.
  Future<void> _openings(CliResult status) async {
    final app = widget.app;
    if (!app.session.unlocked || !(DeviceStatus.parse(status)?.protectedItems ?? false)) return;
    final pin = await app.session.get(context);
    if (pin == null || !mounted) return;
    final o = await app.cli.openings(app.dir, pin);
    if (!mounted || !o.ok) return;
    setState(() => unusual = Openings.parse(o).$2.where((d) => d.unusual).toList());
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
          Padding(
            padding: const EdgeInsets.fromLTRB(8, 24, 8, 8),
            child: Column(children: [
              const SymbolonBadge(size: 104),
              const SizedBox(height: 24),
              Text('Welcome to Symbolon', style: t.headlineSmall, textAlign: TextAlign.center),
              const SizedBox(height: 4),
              Text('Two halves that fit', style: t.titleSmall?.copyWith(color: Theme.of(context).colorScheme.primary), textAlign: TextAlign.center),
              const SizedBox(height: 16),
              const Text('This device is not set up yet. Setup creates your identity with a cosigner and witnesses, '
                  'and gives you a recovery kit.', textAlign: TextAlign.center),
              const SizedBox(height: 24),
              WideButton('Set up this device', key: const Key('start-setup'), icon: Icons.add_moderator, onPressed: setup),
              const SizedBox(height: 8),
              TextButton.icon(
                icon: const Icon(Icons.school_outlined),
                label: const Text('How Symbolon works'),
                onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(fullscreenDialog: true, builder: (_) => const TutorialPage())),
              ),
              TextButton.icon(
                key: const Key('welcome-recover'),
                icon: const Icon(Icons.healing),
                label: const Text('Lost every device? Recover with your kit'),
                onPressed: () async {
                  await Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => RecoveryPage(app: widget.app)));
                  refresh();
                },
              ),
            ]),
          ),
        if (s != null && s.log == null)
          Section('Almost there', children: [
            const Text('This device has its keys but no identity yet. Finish setup to create it.'),
            const SizedBox(height: 16),
            WideButton('Finish setup', key: const Key('start-setup'), icon: Icons.add_moderator, onPressed: setup),
          ]),
        if (s != null && s.log != null) ...[
          Card(
            margin: const EdgeInsets.only(bottom: 16),
            color: Color.alphaBlend((r!.ok ? Colors.green : (offline ? Colors.blueGrey : Colors.red)).withValues(alpha: 0.10), Theme.of(context).colorScheme.surfaceContainerLow),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Icon(r.ok ? Icons.verified : (offline ? Icons.cloud_off : Icons.error), color: r.ok ? Colors.green : (offline ? Colors.blueGrey : Colors.red), size: 32),
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
          if (s.securityUpdate)
            Card(
              key: const Key('security-update'),
              margin: const EdgeInsets.only(bottom: 16),
              color: Color.alphaBlend(Colors.orange.withValues(alpha: 0.18), Theme.of(context).colorScheme.surfaceContainerLow),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Row(children: [
                    const Icon(Icons.security_update_good, color: Colors.orange),
                    const SizedBox(width: 12),
                    Expanded(child: Text('Finish the security update', style: t.titleMedium)),
                  ]),
                  const SizedBox(height: 8),
                  const Text('This device was set up before an important fix. It takes your PIN and, if you have one, your duress PIN, '
                      'and a minute.'),
                  const SizedBox(height: 12),
                  WideButton('Finish the update', key: const Key('start-security-update'), tonal: true, onPressed: () async {
                    await Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => SecurityUpdatePage(app: widget.app)));
                    refresh();
                  }),
                ]),
              ),
            ),
          // The key refresh after the signing fix (SPEC 6.2.2), when the
          // update above is done: the same page runs it.
          if (!s.securityUpdate && s.refreshDue)
            Card(
              key: const Key('security-refresh'),
              margin: const EdgeInsets.only(bottom: 16),
              color: Color.alphaBlend(Colors.orange.withValues(alpha: 0.18), Theme.of(context).colorScheme.surfaceContainerLow),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Row(children: [
                    const Icon(Icons.security_update_good, color: Colors.orange),
                    const SizedBox(width: 12),
                    Expanded(child: Text('Finish the security update', style: t.titleMedium)),
                  ]),
                  const SizedBox(height: 8),
                  Text(refreshSummary(s.securityReshare ?? 'due'), key: const Key('security-refresh-text')),
                  const SizedBox(height: 12),
                  WideButton('Finish the update', key: const Key('start-security-refresh'), tonal: true, onPressed: () async {
                    await Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => SecurityUpdatePage(app: widget.app, refreshOnly: true)));
                    refresh();
                  }),
                ]),
              ),
            ),
          // What to do after that fix: a new household key.
          if (s.rotationAdvised)
            Card(
              key: const Key('security-advice'),
              margin: const EdgeInsets.only(bottom: 16),
              color: Color.alphaBlend((s.rotation == 'compromised' ? Colors.red : Colors.orange).withValues(alpha: 0.18), Theme.of(context).colorScheme.surfaceContainerLow),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Row(children: [
                    Icon(Icons.key_off, color: s.rotation == 'compromised' ? Colors.red : Colors.orange),
                    const SizedBox(width: 12),
                    Expanded(child: Text(adviceSummary(s.rotation!).$1, key: const Key('security-advice-title'), style: t.titleMedium)),
                  ]),
                  const SizedBox(height: 8),
                  Text(adviceSummary(s.rotation!).$2),
                  if (s.rollover == 'avoid')
                    const Padding(
                      padding: EdgeInsets.only(top: 8),
                      child: Text('Don\'t use the rollover browser extension to move your logins: use each site\'s own account recovery instead.', key: Key('security-advice-avoid')),
                    ),
                  const SizedBox(height: 12),
                  WideButton('What to do', key: const Key('open-security-advice'), tonal: true, onPressed: () async {
                    await Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => SecurityAdvicePage(app: widget.app)));
                    refresh();
                  }),
                ]),
              ),
            ),
          if ((s.pending ?? 0) > 0)
            Card(
              key: const Key('pending-change'),
              margin: const EdgeInsets.only(bottom: 16),
              color: Color.alphaBlend(Colors.orange.withValues(alpha: 0.18), Theme.of(context).colorScheme.surfaceContainerLow),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Row(children: [
                    const Icon(Icons.warning_amber, color: Colors.orange),
                    const SizedBox(width: 12),
                    Expanded(child: Text('A change is pending', style: t.titleMedium)),
                  ]),
                  const SizedBox(height: 8),
                  const Text('A delayed event (a recovery?) is waiting to take effect. If you did not start it, veto it now.'),
                  const SizedBox(height: 12),
                  WideButton('Review in Recovery', key: const Key('review-recovery'), tonal: true, onPressed: () async {
                    await Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => RecoveryPage(app: widget.app)));
                    refresh();
                  }),
                ]),
              ),
            ),
          if (unusual.isNotEmpty)
            Card(
              key: const Key('unusual-openings'),
              margin: const EdgeInsets.only(bottom: 16),
              color: Color.alphaBlend(Colors.orange.withValues(alpha: 0.18), Theme.of(context).colorScheme.surfaceContainerLow),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Row(children: [
                    const Icon(Icons.warning_amber, color: Colors.orange),
                    const SizedBox(width: 12),
                    Expanded(child: Text('Unusually many protected openings', style: t.titleMedium)),
                  ]),
                  const SizedBox(height: 8),
                  Text('${unusual.map((d) => d.label.isEmpty ? 'A device' : d.label).join(', ')} opened ${unusual.map((d) => d.day).join(', ')} protected '
                      'items today, far more than usual. If that was not you, that device may be stolen or infected: remove it from your identity.'),
                  const SizedBox(height: 12),
                  WideButton('Review devices', key: const Key('review-devices'), tonal: true, onPressed: () async {
                    await Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => DevicesPage(app: widget.app)));
                    refresh();
                  }),
                ]),
              ),
            ),
          Row(children: [
            Expanded(child: _Action(Icons.key, 'Passkeys', _count(widget.app.settings.credentials.length), () => widget.go(1))),
            const SizedBox(width: 12),
            Expanded(child: _Action(Icons.lock, 'Vault', 'Passwords, notes', () => widget.go(2))),
          ]),
          const SizedBox(height: 16),
          const ProviderCard(onlyWhenOff: true),
          const AutofillCard(onlyWhenOff: true),
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

String _count(int n) => n == 0 ? 'None yet' : (n == 1 ? '1 on this device' : '$n on this device');

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
