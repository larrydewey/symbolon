import 'dart:io';

import 'package:material_ui/material_ui.dart';

import '../app.dart';
import '../cli.dart';
import '../widgets.dart';
import 'scan_page.dart';

/// Adding a device to the identity by scanning the code it shows (SPEC
/// 11.5), and removing this device's TPM keys.
class DevicesPage extends StatefulWidget {
  final App app;
  const DevicesPage({super.key, required this.app});

  @override
  State<DevicesPage> createState() => _DevicesPageState();
}

class _DevicesPageState extends State<DevicesPage> {
  final linkText = TextEditingController();
  App get app => widget.app;
  bool? protectedOn;          // the quorum has a vault OPRF key (SPEC 18.10)
  (int, List<Openings>)? openings;

  @override
  void initState() {
    super.initState();
    _status();
  }

  Future<void> _status() async {
    final r = await app.cli.status(app.dir);
    if (!mounted) return;
    setState(() => protectedOn = DeviceStatus.parse(r)?.protectedItems);
  }

  // Protected items (SPEC 18.10): turned on by a re-share with the cosigner.
  Future<void> enableProtection() async {
    final r = await app.withPin(context, (p) => runTask(context, 'Turning protected items on', () => app.cli.protectionEnable(app.dir, p),
        detail: 'Your identity is re-shared with your cosigner, which gives it the key protected items need.', usually: '1-3 minutes'));
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    toast(context, 'Protected items are on');
    _status();
  }

  // Each device's protected openings, from the cosigner's records (SPEC 18.10.4).
  Future<void> checkOpenings() async {
    final r = await app.withPin(context, (p) => runTask(context, 'Asking the cosigner', () => app.cli.openings(app.dir, p), usually: 'a few seconds'));
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    setState(() => openings = Openings.parse(r));
  }

  @override
  void dispose() {
    linkText.dispose();
    super.dispose();
  }

  static bool isLink(String t) => t.trim().startsWith('symbolon://link?') && t.contains('&s=');

  Future<void> scan() async {
    final text = await Navigator.of(context).push<String>(MaterialPageRoute(
        builder: (_) => const ScanPage(accepts: isLink, title: "Scan the new device's code",
            hint: 'Point the camera at the code the new device shows (Join from your other device).', wrong: "That is not a new device's code.")));
    if (text == null || !mounted) return;
    linkText.text = text;
    await add();
  }

  // The person compares the code the new device shows with this one: only
  // the device in front of them is added (SPEC 11.1 step 2). A code someone
  // else made, scanned or pasted here, would otherwise add their device.
  Future<bool> confirmFingerprint(String fp) async {
    if (!mounted) return false;
    final same = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        title: const Text('Is this your new device?'),
        content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Text('Your new device now shows a code. Add it only if it shows exactly this, and it is the device in front of you:'),
          const SizedBox(height: 12),
          SelectableText(fp, key: const Key('add-fingerprint'), style: const TextStyle(fontFamily: 'monospace', fontSize: 18)),
          const SizedBox(height: 12),
          const Text('If it differs, or no device of yours shows a code, someone else made this code: do not add it.'),
        ]),
        actions: [
          TextButton(key: const Key('add-fingerprint-no'), onPressed: () => Navigator.of(ctx).pop(false), child: const Text('It differs')),
          FilledButton(key: const Key('add-fingerprint-yes'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('It is the same')),
        ],
      ),
    );
    return same == true;
  }

  // Adds the device whose code this is (SPEC 11.5): the two devices meet on
  // the local network, the person confirms the new device's fingerprint,
  // then the identity is re-shared to include it.
  Future<void> add() async {
    FocusScope.of(context).unfocus();
    final link = linkText.text.trim();
    if (!isLink(link)) return toast(context, "Scan the new device's code, or paste its link (symbolon://link?…).");
    final r = await app.withPin(context, (p) => runTask(context, 'Adding the new device', () => app.cli.linkAdd(app.dir, link, p, confirmFingerprint),
        detail: 'The new device sets itself up from this one; you then compare the code both devices show, and your identity is re-shared to include it. '
            'Keep both devices on and on this network.',
        usually: '1-3 minutes'));
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    linkText.clear();
    await showOutput(context, 'Device added', 'The new device is part of your identity: it has your vault and passkeys.');
  }

  Future<void> forget() async {
    final sure = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(Platform.isAndroid ? "Remove this phone's keys?" : "Remove this device's TPM keys?"),
        content: const Text('This device will no longer unlock or sign, and it cannot be undone. Do this only for a device you are retiring, after another device has joined your identity.'),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(style: FilledButton.styleFrom(backgroundColor: Colors.red), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Remove')),
        ],
      ),
    );
    if (sure != true || !mounted) return;
    final r = await runTask(context, 'Removing TPM keys', () => app.cli.forget(app.dir));
    if (r.ok && mounted) await showOutput(context, 'TPM keys', r.out.trim());
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Devices')),
      body: PageBody(children: [
        Section('Add a device', subtitle: 'A new phone or computer joins your identity: the same vault, the same passkeys.', children: [
          const Text('On the new device, start setup and choose Join from your other device. It shows a code; scan it here.'),
          const SizedBox(height: 12),
          if (Platform.isAndroid || Platform.isIOS) ...[
            WideButton("Scan the new device's code", key: const Key('add-scan'), icon: Icons.qr_code_scanner, onPressed: scan),
            const SizedBox(height: 12),
          ],
          Field(linkText, Platform.isAndroid || Platform.isIOS ? 'Or paste its link' : 'Paste its link', hint: 'symbolon://link?…', url: true, fieldKey: const Key('add-link'), action: TextInputAction.done,
              helper: 'Only a link your own new device shows, here with you on this network: a link someone sent you would add their device.'),
          WideButton('Add the device', key: const Key('add-device'), icon: Icons.add, tonal: true, onPressed: add),
        ]),
        Section('Protected items', subtitle: 'Items you protect open only with your cosigner, so one stolen or infected device cannot open them on its own.', children: [
          if (protectedOn == false) ...[
            const Text('Protected items are not on for your identity yet. Turning them on re-shares your identity with your cosigner; '
                'do it before adding another device.'),
            const SizedBox(height: 12),
            WideButton('Turn protected items on', key: const Key('protection-enable'), icon: Icons.shield_outlined, tonal: true, onPressed: enableProtection),
          ],
          if (protectedOn == true) ...[
            WideButton('Check protected openings', key: const Key('openings-check'), icon: Icons.fact_check_outlined, tonal: true, onPressed: checkOpenings),
            if (openings case (final limit, final list)) ...[
              const SizedBox(height: 8),
              for (final o in list)
                ListTile(
                  key: Key('openings-${o.label}'),
                  leading: Icon(o.unusual ? Icons.warning_amber : Icons.devices, color: o.unusual ? Colors.orange : null),
                  title: Text(o.label.isEmpty ? 'Device' : o.label),
                  subtitle: Text('${o.hour} in the past hour (limit $limit), ${o.day} today, ${o.week} this week${o.unusual ? ': unusually many' : ''}'),
                ),
            ],
          ],
        ]),
        Section('Retire this device', subtitle: 'Before you sell, give away or wipe it, once another device has joined your identity.', children: [
          OutlinedButton.icon(
            key: const Key('forget'),
            onPressed: forget,
            icon: const Icon(Icons.delete_forever, color: Colors.red),
            label: Text(Platform.isAndroid ? "Remove this phone's keys" : "Remove this device's TPM keys"),
          ),
        ]),
      ]),
    );
  }
}
