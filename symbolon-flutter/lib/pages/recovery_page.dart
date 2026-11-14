import 'dart:io';

import 'package:flutter/material.dart';

import '../app.dart';
import '../cli.dart';
import '../links.dart';
import '../recovery_sheet.dart';
import '../validate.dart' as v;
import '../widgets.dart';
import 'scan_page.dart';

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
  final kitC = TextEditingController();
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
    kitC.dispose();
    super.dispose();
  }

  String get kit => kitC.text.replaceAll(RegExp(r'\s'), '').toLowerCase();

  Future<void> scan() async {
    final text = await Navigator.of(context).push<String>(MaterialPageRoute(
        builder: (_) => const ScanPage(accepts: RecoverySheet.isLink, title: 'Scan your recovery sheet',
            hint: 'Point the camera at the code at the foot of your printed recovery sheet.', wrong: 'That is not a recovery sheet\'s code.')));
    final sheet = text == null ? null : RecoverySheet.parse(text);
    if (sheet == null || !mounted) return;
    setState(() {
      logId.text = sheet.log;
      kitC.text = groupsOf(sheet.kit).join(' ');
    });
    toast(context, 'Read the identity log and the kit from your sheet.');
  }

  Future<void> start() async {
    FocusScope.of(context).unfocus();
    final log = logId.text.replaceAll(RegExp(r'\s'), '').toLowerCase();
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(log)) return toast(context, 'The identity log is 64 characters, 0-9 and a-f: item 1 on your recovery sheet.');
    if (v.hex(kit) != null) return toast(context, 'The kit is 0-9 and a-f: item 2 on your recovery sheet.');
    final r = await runTask(context, 'Starting recovery', () => app.cli.recover(app.dir, kit, log), usually: 'a few seconds');
    if (!r.ok || !mounted) return;
    final fresh = r.lines.where((l) => l.startsWith('NEW RECOVERY KIT')).map((l) => l.split(': ').last.trim().toLowerCase()).firstOrNull;
    await showOutput(context, 'Recovery started', r.lines.where((l) => !l.startsWith('NEW RECOVERY KIT')).join('\n'));
    if (fresh == null || !mounted) return;
    await Navigator.of(context).push(MaterialPageRoute<void>(
        fullscreenDialog: true,
        builder: (_) => SheetPage(
            sheet: RecoverySheet(log, fresh),
            title: 'Your new recovery sheet',
            intro: 'When the recovery takes effect, this sheet replaces your old one: the old kit stops working. Write it down '
                'or print it now. It is shown only this once.')));
  }

  Future<void> finish() async {
    // The old kit: the one typed or scanned above, else asked for.
    var seed = kit;
    if (seed.isEmpty) {
      final s = await askSecret(context, title: 'Recovery kit', label: 'Kit (the old one)', numeric: false, action: 'Continue');
      if (s == null || !mounted) return;
      seed = s.replaceAll(RegExp(r'\s'), '').toLowerCase();
    }
    if (v.hex(seed) != null) return toast(context, 'The kit is 0-9 and a-f: item 2 on your recovery sheet.');
    final r = await app.withPin(context, (p) => runTask(context, 'Finishing recovery', () => app.cli.recoverFinish(app.dir, seed, p), usually: '1-3 minutes'));
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
          if (Platform.isAndroid || Platform.isIOS) ...[
            WideButton('Scan your recovery sheet', key: const Key('scan-sheet'), icon: Icons.qr_code_scanner, onPressed: scan),
            const SizedBox(height: 8),
            Text('Or type it in from your sheet:', style: Theme.of(context).textTheme.bodySmall),
            const SizedBox(height: 8),
          ],
          Field(logId, '1. Identity log', hint: '64 characters; spaces are fine', fieldKey: const Key('recover-log'), url: true),
          Field(kitC, '2. Recovery kit', hint: 'spaces are fine', fieldKey: const Key('recover-kit'), url: true, action: TextInputAction.done),
          WideButton('Start recovery', key: const Key('recover-start'), icon: Icons.healing, onPressed: start),
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
