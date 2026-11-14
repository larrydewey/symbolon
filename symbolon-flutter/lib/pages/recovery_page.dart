import 'package:flutter/material.dart';

import '../app.dart';
import '../cli.dart';
import '../validate.dart' as v;
import '../widgets.dart';

/// Kit recovery (SPEC 13.2): start it on a new device, veto it from a
/// device you still hold, and finish it after the delay.
class RecoveryPage extends StatefulWidget {
  final App app;
  const RecoveryPage({super.key, required this.app});

  @override
  State<RecoveryPage> createState() => _RecoveryPageState();
}

class _RecoveryPageState extends State<RecoveryPage> {
  final logId = TextEditingController();
  int pending = 0;       // delayed events waiting on this identity, from device status
  bool setUp = false;    // whether this device has an identity

  App get app => widget.app;

  @override
  void initState() {
    super.initState();
    app.cli.status(app.dir).then((r) {
      final s = DeviceStatus.parse(r);
      if (mounted && s != null) {
        setState(() {
          pending = s.pending ?? 0;
          setUp = s.log != null;
        });
      }
    });
  }

  @override
  void dispose() {
    logId.dispose();
    super.dispose();
  }

  Future<void> start() async {
    if (!RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(logId.text.trim())) return toast(context, 'The identity log is 64 hex digits (Home on a lost device, or your records).');
    final seed = await askSecret(context, title: 'Recovery kit', label: 'Kit', note: 'The kit you wrote down at setup.', numeric: false, action: 'Continue');
    if (seed == null || !mounted) return;
    if (v.hex(seed) != null) return toast(context, 'The kit is hex digits (0-9, a-f), as you wrote it down.');
    final r = await runTask(context, 'Starting recovery', () => app.cli.recover(app.dir, seed.trim(), logId.text.trim()), usually: 'a few seconds');
    if (!r.ok || !mounted) return;
    final kit = r.lines.where((l) => l.startsWith('NEW RECOVERY KIT')).map((l) => l.split(': ').last).firstOrNull;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Recovery started'),
        content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text(r.lines.where((l) => !l.startsWith('NEW RECOVERY KIT')).join('\n')),
          if (kit != null) ...[
            const SizedBox(height: 12),
            const Text('Write down the new kit now: it replaces the old one when the recovery takes effect.', style: TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            KitCard(kit, label: 'New recovery kit'),
          ],
        ])),
        actions: [FilledButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Done'))],
      ),
    );
  }

  Future<void> finish() async {
    final seed = await askSecret(context, title: 'Recovery kit', label: 'Kit (the old one)', numeric: false, action: 'Continue');
    if (seed == null || !mounted) return;
    if (v.hex(seed) != null) return toast(context, 'The kit is hex digits (0-9, a-f), as you wrote it down.');
    final r = await app.withPin(context, (p) => runTask(context, 'Finishing recovery', () => app.cli.recoverFinish(app.dir, seed.trim(), p), usually: '1-3 minutes'));
    if (r != null && r.ok && mounted) await showOutput(context, 'Recovered', r.out.trim());
  }


  Future<void> veto() async {
    final r = await app.withPin(context, (p) => runTask(context, 'Stopping the recovery', () => app.cli.veto(app.dir, p), usually: 'a few seconds'));
    if (r != null && r.ok && mounted) {
      setState(() => pending = 0);
      await showOutput(context, 'Stopped', r.out.trim());
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    // On a device that holds the identity, the urgent thing is stopping a
    // recovery someone else started; on a new one, recovering.
    final stop = pending > 0
        ? Card(
            key: const Key('recovery-pending'),
            margin: const EdgeInsets.only(bottom: 16),
            color: Color.alphaBlend(Colors.orange.withValues(alpha: 0.18), Theme.of(context).colorScheme.surfaceContainerLow),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                Row(children: [
                  const Icon(Icons.warning_amber, color: Colors.orange),
                  const SizedBox(width: 12),
                  Expanded(child: Text(pending == 1 ? 'A recovery is waiting to take effect' : '$pending changes are waiting to take effect', style: t.titleMedium)),
                ]),
                const SizedBox(height: 8),
                const Text('Someone started a recovery of your identity with a recovery kit. If it was you, on a new device, let it run. '
                    'If not, stop it now: whoever holds the kit can otherwise take over your identity when the wait ends.'),
                const SizedBox(height: 16),
                FilledButton.icon(
                  key: const Key('veto'),
                  style: FilledButton.styleFrom(backgroundColor: Colors.red.shade700, foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(vertical: 14)),
                  icon: const Icon(Icons.block),
                  label: const Text('Stop this recovery'),
                  onPressed: veto,
                ),
              ]),
            ),
          )
        : Section('Stop a recovery', subtitle: 'On a device you still hold, if someone else started a recovery.', children: [
            OutlinedButton.icon(
              key: const Key('veto'),
              icon: const Icon(Icons.block, color: Colors.red),
              label: const Text('Veto the pending recovery'),
              onPressed: veto,
            ),
          ]);
    final recover = Section(setUp ? 'Recover on a new device' : 'Recover on this device',
        subtitle: 'With your recovery kit, if you lost every device. It takes effect after a waiting period, unless one of your devices stops it.',
        children: [
          Field(logId, 'Identity log', hint: '64 characters, shown on Home on your old device', action: TextInputAction.done, check: v.hexBytes(32)),
          WideButton('Start recovery', icon: Icons.healing, onPressed: start),
          const SizedBox(height: 16),
          const Text('After the waiting period:'),
          const SizedBox(height: 8),
          WideButton('1. Ask the cosigner for its part', tonal: true, onPressed: () async {
            final r = await app.withPin(context, (p) => runTask(context, 'Asking the cosigner', () => app.cli.recoverRelease(app.dir, p), usually: 'a few seconds'));
            if (r != null && r.ok && context.mounted) await showOutput(context, 'Released', r.out.trim());
          }),
          const SizedBox(height: 8),
          WideButton('2. Finish recovery', onPressed: finish),
        ]);
    return Scaffold(
      appBar: AppBar(title: const Text('Recovery')),
      body: PageBody(children: setUp || pending > 0 ? [stop, recover] : [recover, stop]),
    );
  }
}
