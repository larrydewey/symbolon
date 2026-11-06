import 'dart:io';

import 'package:flutter/material.dart';

import '../app.dart';
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

  // Adds the device whose code this is (SPEC 11.5): the two devices meet on
  // the local network, then the identity is re-shared to include it.
  Future<void> add() async {
    FocusScope.of(context).unfocus();
    final link = linkText.text.trim();
    if (!isLink(link)) return toast(context, "Scan the new device's code, or paste its link (symbolon://link?…).");
    final r = await app.withPin(context, (p) => runTask(context, 'Adding the new device', () => app.cli.linkAdd(app.dir, link, p),
        detail: 'The new device sets itself up from this one, then your identity is re-shared to include it. Keep both devices on and on this network.',
        usually: '3-6 minutes'));
    if (r == null || !mounted) return;
    if (!r.ok) return toast(context, friendlyError(r));
    linkText.clear();
    await showOutput(context, 'Device added', 'The new device is part of your identity: it has your vault and passkeys.');
  }

  Future<void> forget() async {
    final sure = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text("Remove this device's TPM keys?"),
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
          Field(linkText, 'Or paste its link', hint: 'symbolon://link?…', url: true, fieldKey: const Key('add-link'), action: TextInputAction.done),
          WideButton('Add the device', key: const Key('add-device'), icon: Icons.add, tonal: true, onPressed: add),
        ]),
        Section('TPM', children: [
          OutlinedButton.icon(onPressed: forget, icon: const Icon(Icons.delete_forever, color: Colors.red), label: const Text("Remove this device's TPM keys")),
        ]),
      ]),
    );
  }
}
