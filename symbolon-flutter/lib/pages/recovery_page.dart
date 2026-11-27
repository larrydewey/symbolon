import 'dart:io';

import 'package:material_ui/material_ui.dart';

import '../app.dart';
import '../cli.dart';
import '../links.dart';
import '../recovery_sheet.dart';
import '../validate.dart' as v;
import '../widgets.dart';
import 'scan_page.dart';

/// Kit recovery (SPEC 13.2): start it on a new device, veto it from a
/// device you still hold, and finish it after the delay. On a device with
/// an identity, replacing the kit (`device kit renew`): the answer to a
/// lost or seen kit, and how a kit without a passphrase gets one.
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
  String kitKind = 'protected';   // until known: "plain", "unknown" (made before passphrases) or "protected"
  List<PendingEvent> events = const [];   // the pending events (`device pending`), when any

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
        if (s.log != null) {
          app.cli.kitStatus(app.dir).then((k) => mounted ? setState(() => kitKind = k) : null);
          if ((s.pending ?? 0) > 0) loadPending();
        }
      }
    });
  }

  String clean(String s) => s.replaceAll(RegExp(r'[\s-]'), '').toLowerCase();

  /// The kit's passphrase when [k] is a protected sheet: "" when it is not
  /// needed, null when the person cancelled.
  Future<String?> kitPassFor(String k) async {
    if (!kitIsProtected(k)) return '';
    return askSecret(context, title: 'Kit passphrase', label: 'Passphrase', numeric: false, action: 'Continue',
        note: 'This kit is sealed under a passphrase. A wrong one is refused, and nothing is sent.');
  }

  /// Replaces the kit with a new one (SPEC 13.2): every sheet of the old
  /// kit stops working once the replacement is in force and the quorum has
  /// re-shared to the new kit. With other devices it waits out the
  /// recovery delay (any device may stop it); then the same button
  /// finishes it, and no new kit is made. [needPass]: offered to add a
  /// passphrase, so one is required.
  Future<void> renew({bool needPass = false}) async {
    final pass = await askKitPassphrase(context, optional: !needPass, title: 'A passphrase for your new kit');
    if (pass == null || (needPass && pass.isEmpty) || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Replacing your kit', () => app.cli.kitRenew(app.dir, p, pass),
        detail: 'A new kit, a logged change, then a re-share with the cosigner.', usually: '1-5 minutes'));
    if (r == null || !mounted) return;
    final fresh = r.lines.where((l) => l.startsWith('NEW RECOVERY KIT')).map((l) => l.split(': ').last.trim().toLowerCase()).firstOrNull;
    final done = r.lines.any((l) => l.startsWith('kit replaced'));
    if (fresh != null) {
      final log = DeviceStatus.parse(await app.cli.status(app.dir))?.log ?? '';
      if (!mounted) return;
      await Navigator.of(context).push(MaterialPageRoute<void>(
          fullscreenDialog: true,
          builder: (_) => SheetPage(
              sheet: RecoverySheet(log, fresh),
              title: 'Your new recovery sheet',
              intro: done
                  ? 'Your kit was replaced: every old sheet, with or without a passphrase, no longer works. Write this one down or print it.'
                  : 'This kit replaces your old one when the waiting period ends, unless one of your devices stops it. Until then the '
                      'old sheet still works. Write this one down or print it, then come back here to finish the replacement.')));
    }
    if (!mounted) return;
    final rest = [...r.lines.where((l) => !l.startsWith('NEW RECOVERY KIT')), if (!r.ok) r.problem].join('\n').trim();
    if (rest.isNotEmpty) await showOutput(context, done ? 'Kit replaced' : r.ok ? 'Kit replacement waiting' : 'Kit not replaced', rest);
    if (done && mounted) {
      final k = await app.cli.kitStatus(app.dir);
      if (mounted) setState(() => kitKind = k);
    }
  }

  @override
  void dispose() {
    logId.dispose();
    kitC.dispose();
    super.dispose();
  }

  String get kit => clean(kitC.text);

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
    final old = await kitPassFor(kit);
    if (old == null || !mounted) return;
    // The new kit this recovery makes: a passphrase recommended, not required.
    final pass = await askKitPassphrase(context, title: 'A passphrase for your new kit');
    if (pass == null || !mounted) return;
    final r = await runTask(context, 'Starting recovery', () => app.cli.recover(app.dir, kit, log, kitPassphrase: old, newKitPassphrase: pass),
        usually: old.isEmpty && pass.isEmpty ? 'a few seconds' : 'about a minute');
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
      seed = clean(s);
    }
    if (v.hex(seed) != null) return toast(context, 'The kit is 0-9 and a-f: item 2 on your recovery sheet.');
    final old = await kitPassFor(seed);
    if (old == null || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Finishing recovery', () => app.cli.recoverFinish(app.dir, seed, p, kitPassphrase: old), usually: '1-5 minutes'));
    if (r != null && r.ok && mounted) await showOutput(context, 'Recovered', r.out.trim());
  }

  Future<void> loadPending() async {
    final es = await app.cli.pending(app.dir);
    if (mounted) setState(() => events = es);
  }

  /// Approve another device's pending change (SPEC 8.2: a confirm event):
  /// it takes effect now instead of after the waiting period.
  Future<void> approve(PendingEvent e) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Approve change ${e.seq}?'),
        // What the change does (R5-6): the device a removal takes out, the
        // policy before and after, the new kit's id; and the digest this
        // device's approval signs.
        content: SingleChildScrollView(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
            Text(e.what, key: const Key('approve-what')),
            if (e.alone) ...[
              const SizedBox(height: 12),
              Text('Only one device asked for this. A stolen device carries its own name: if you did not ask for it from that device yourself, stop it instead.',
                  key: const Key('approve-alone'), style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
            ],
            const SizedBox(height: 12),
            const Text('Your approval signs the change with digest:'),
            SelectableText(e.digest, key: const Key('approve-digest'), style: const TextStyle(fontFamily: 'monospace')),
            const SizedBox(height: 12),
            const Text('Approve it only if you know who asked for it and why: it then takes effect now, and can no longer be stopped. '
                'If you do not recognise it, stop it instead.'),
          ]),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(key: const Key('confirm-approve'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Approve')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Approving the change', () => app.cli.confirm(app.dir, e.seq, p), usually: 'a few seconds'));
    if (r != null && r.ok && mounted) {
      setState(() => pending = pending > 0 ? pending - 1 : 0);
      await loadPending();
      if (mounted) await showOutput(context, 'Approved', r.out.trim());
    }
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
    // The pending changes, each with Approve when another device's
    // authority change may be confirmed (never a recovery).
    final waiting = events.isEmpty
        ? null
        : Section('Waiting changes',
            subtitle: 'Changes one of your devices asked for, waiting out the waiting period. Approve one from this device '
                'to put it in force now; stop one you do not recognise.',
            children: [
                for (final e in events)
                  ListTile(
                    key: Key('pending-${e.seq}'),
                    contentPadding: EdgeInsets.zero,
                    title: Text(e.what),
                    subtitle: Text('Change ${e.seq} · ${e.shortDigest}'),
                    trailing: e.confirmable
                        ? TextButton(key: Key('approve-${e.seq}'), onPressed: () => approve(e), child: const Text('Approve'))
                        : null,
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
    // A kit without a passphrase (or made before there were any): offer to
    // replace it with one that has one.
    final offer = setUp && kitKind != 'protected'
        ? Card(
            key: const Key('kit-renew-offer'),
            margin: const EdgeInsets.only(bottom: 16),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                Row(children: [
                  const Icon(Icons.lock_outline),
                  const SizedBox(width: 12),
                  Expanded(child: Text('Add a passphrase to your recovery kit', style: t.titleMedium)),
                ]),
                const SizedBox(height: 8),
                Text(kitKind == 'plain'
                    ? 'Your kit has no passphrase, so whoever reads your sheet holds it. With one, the sheet alone is no use to them.'
                    : 'Your kit was made before kits could have a passphrase. With one, the sheet alone is no use to whoever finds it.'),
                const SizedBox(height: 8),
                const Text('This makes a new kit with a passphrase, and your old sheet stops working. If you forget the passphrase, '
                    'the kit cannot be used.'),
                const SizedBox(height: 12),
                WideButton('Add a passphrase', key: const Key('kit-renew'), icon: Icons.lock_outline, tonal: true, onPressed: () => renew(needPass: true)),
              ]),
            ),
          )
        : null;
    // A kit lost, or seen or photographed by someone else: replace it.
    final replace = setUp
        ? Section('Replace your recovery kit',
            subtitle: 'If your kit was lost, or someone else may have seen or photographed it. Every old sheet stops working, '
                'with or without a passphrase. When your identity asks for two devices to approve changes, it waits out the waiting '
                'period first, and any of your devices can stop it; come back here then to finish it.',
            children: [
                WideButton('Replace the kit', key: const Key('kit-replace'), icon: Icons.autorenew, tonal: true, onPressed: renew),
              ])
        : null;
    return Scaffold(
      appBar: AppBar(title: const Text('Recovery')),
      body: PageBody(children: [
        if (offer != null && pending == 0) offer,
        ...(setUp || pending > 0 ? [stop, if (waiting != null) waiting, recover] : [recover, stop]),
        if (replace != null) replace,
      ]),
    );
  }
}
