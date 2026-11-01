import 'package:flutter/material.dart';

import '../app.dart';
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

  App get app => widget.app;

  @override
  void dispose() {
    logId.dispose();
    super.dispose();
  }

  Future<void> start() async {
    if (!RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(logId.text.trim())) return toast(context, 'The identity log is 64 hex digits (Home on a lost device, or your records).');
    final seed = await askSecret(context, title: 'Recovery kit', label: 'Kit', note: 'The kit you wrote down at setup.', numeric: false);
    if (seed == null || !mounted) return;
    if (v.hex(seed) != null) return toast(context, 'The kit is hex digits (0-9, a-f), as you wrote it down.');
    final r = await runTask(context, 'Starting recovery', () => app.cli.recover(app.dir, seed.trim(), logId.text.trim()), usually: 'a few seconds');
    if (!r.ok || !mounted) return;
    final kit = r.lines.where((l) => l.startsWith('NEW RECOVERY KIT')).map((l) => l.split(': ').last).firstOrNull;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Recovery started'),
        content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text(r.lines.where((l) => !l.startsWith('NEW RECOVERY KIT')).join('\n')),
          if (kit != null) ...[
            const SizedBox(height: 12),
            const Text('Write down the new kit now: it replaces the old one when the recovery takes effect.', style: TextStyle(fontWeight: FontWeight.bold)),
            HexValue('New recovery kit', kit, secret: true),
          ],
        ]),
        actions: [FilledButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Done'))],
      ),
    );
  }

  Future<void> finish() async {
    final seed = await askSecret(context, title: 'Recovery kit', label: 'Kit (the old one)', numeric: false);
    if (seed == null || !mounted) return;
    if (v.hex(seed) != null) return toast(context, 'The kit is hex digits (0-9, a-f), as you wrote it down.');
    final r = await app.withPin(context, (p) => runTask(context, 'Finishing recovery', () => app.cli.recoverFinish(app.dir, seed.trim(), p), usually: '2-5 minutes'));
    if (r != null && r.ok && mounted) await showOutput(context, 'Recovered', r.out.trim());
  }


  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Recovery')),
      body: PageBody(children: [
        Section('Recover on this device', subtitle: 'With your recovery kit. It takes effect after a waiting period, unless one of your devices stops it.', children: [
          Field(logId, 'Identity log', action: TextInputAction.done, check: v.hexBytes(32)),
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
        ]),
        Section('Stop a recovery', subtitle: 'On a device you still hold, if someone else started a recovery.', children: [
          OutlinedButton.icon(
            icon: const Icon(Icons.block, color: Colors.red),
            label: const Text('Veto the pending recovery'),
            onPressed: () async {
              final r = await app.withPin(context, (p) => runTask(context, 'Vetoing', () => app.cli.veto(app.dir, p), usually: 'a few seconds'));
              if (r != null && r.ok && context.mounted) await showOutput(context, 'Vetoed', r.out.trim());
            },
          ),
        ]),
      ]),
    );
  }
}

