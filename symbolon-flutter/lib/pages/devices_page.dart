import 'package:flutter/material.dart';

import '../app.dart';
import '../validate.dart' as v;
import '../widgets.dart';

/// Adding a device to the identity (enroll here, join on the new one) and
/// removing this device's TPM keys.
class DevicesPage extends StatefulWidget {
  final App app;
  const DevicesPage({super.key, required this.app});

  @override
  State<DevicesPage> createState() => _DevicesPageState();
}

class _DevicesPageState extends State<DevicesPage> {
  final newKeys = TextEditingController();
  final enrollerKeys = TextEditingController();

  App get app => widget.app;

  @override
  void dispose() {
    newKeys.dispose();
    enrollerKeys.dispose();
    super.dispose();
  }

  Future<void> enroll() async {
    if (v.hex(newKeys.text) != null) return toast(context, "Paste the new device's keys (hex) first.");
    final r = await app.withPin(context, (p) => runTask(context, 'Adding the new device', () => app.cli.enroll(app.dir, newKeys.text.trim(), p),
        detail: 'Your identity is re-shared to include it; every passkey keeps its public key.', usually: '2-5 minutes'),
        note: 'Start "Join" on the new device first.');
    if (r != null && r.ok && mounted) await showOutput(context, 'Device added', r.out.trim());
  }

  Future<void> join() async {
    if (v.hex(enrollerKeys.text) != null) return toast(context, "Paste the other device's keys (hex) first.");
    final r = await app.withPin(context, (p) => runTask(context, 'Waiting for the other device', () => app.cli.join(app.dir, enrollerKeys.text.trim(), p),
        detail: 'Now start "Add a device" on the device that already has your identity.', usually: '2-5 minutes'));
    if (r != null && r.ok && mounted) await showOutput(context, 'Joined', r.out.trim());
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
        Section('Add a device', subtitle: 'On this device, which has your identity.', children: [
          Field(newKeys, "The new device's keys", hint: 'shown when it was created', action: TextInputAction.done, check: v.hex),
          WideButton('Add a device', icon: Icons.add, onPressed: enroll),
        ]),
        Section('Join an identity', subtitle: 'On the new device.', children: [
          Field(enrollerKeys, "The other device's keys", action: TextInputAction.done, check: v.hex),
          WideButton('Join', icon: Icons.login, tonal: true, onPressed: join),
        ]),
        Section('TPM', children: [
          OutlinedButton.icon(onPressed: forget, icon: const Icon(Icons.delete_forever, color: Colors.red), label: const Text("Remove this device's TPM keys")),
        ]),
      ]),
    );
  }
}
