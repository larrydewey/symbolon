import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../hardware.dart';
import '../widgets.dart';

/// What a hardware key store adds, whether this device has one Symbolon can
/// use, and the steps to turn it on when it does not.
class HardwarePage extends StatefulWidget {
  final bool keystore;      // Android: the phone has a Keystore Symbolon can use
  final bool strongBox;
  const HardwarePage({super.key, this.keystore = false, this.strongBox = false});

  @override
  State<HardwarePage> createState() => _HardwarePageState();
}

class _HardwarePageState extends State<HardwarePage> {
  HardwareState? state;

  @override
  void initState() {
    super.initState();
    check();
  }

  Future<void> check() async {
    setState(() => state = null);
    final s = await detectHardware(keystore: widget.keystore);
    if (mounted) setState(() => state = s);
  }

  @override
  Widget build(BuildContext context) {
    final s = state;
    return Scaffold(
      appBar: AppBar(title: const Text('Hardware key store'), actions: [IconButton(tooltip: 'Check again', icon: const Icon(Icons.refresh), onPressed: check)]),
      body: PageBody(children: [
        const Section('Why it matters', children: [
          Text('Without a hardware key store, your PIN is all that protects this device\'s share of your keys: someone who copies '
              'the app\'s files can try PINs as fast as their computer allows (the PIN stretch slows each guess down). '
              'With one, the unlock keys stay inside a chip that refuses to be copied and limits wrong guesses.'),
        ]),
        if (s == null) const Padding(padding: EdgeInsets.all(32), child: Center(child: CircularProgressIndicator())) else ..._for(s),
        const Section('Already set up without it?', children: [
          Text('Protection is chosen when a device is created. To move to the hardware key store, set Symbolon up in a new device '
              'directory (Settings › Device directory) and add it to your identity from More › Devices; your identity, passkeys '
              'and vault stay the same.'),
        ]),
      ]),
    );
  }

  List<Widget> _for(HardwareState s) {
    switch (s) {
      case HardwareState.ready:
        return [
          _status(Icons.verified_user, Colors.green, 'TPM ready', 'This computer has a TPM 2.0 you can use. Setup uses it automatically.'),
        ];
      case HardwareState.noAccess:
        return [
          _status(Icons.lock_person, Colors.orange, 'TPM found, but not allowed', 'This computer has a TPM, but your account may not open it.'),
          Section('Turn it on', children: [
            const Text('1. Add your account to the tss group:'),
            const _Command('sudo usermod -aG tss "\$USER"'),
            const Text('2. Log out and back in (or restart), so the new group applies.'),
            const SizedBox(height: 8),
            const Text('3. Come back here and tap Check again.'),
            const SizedBox(height: 12),
            WideButton('Check again', icon: Icons.refresh, tonal: true, onPressed: check),
          ]),
        ];
      case HardwareState.none:
        return [
          _status(Icons.memory, Colors.orange, 'No TPM found', 'No TPM 2.0 is visible ($tpmDevice is missing).'),
          Section('Turn it on', children: [
            const Text('Most computers since 2016 have one, often switched off.'),
            const SizedBox(height: 8),
            const Text('1. Restart into the firmware setup (BIOS/UEFI; usually F2, F10, F12 or Del while starting).'),
            const SizedBox(height: 4),
            const Text('2. Find the security settings and turn on "TPM 2.0". AMD calls it "fTPM", Intel "PTT".'),
            const SizedBox(height: 4),
            const Text('3. Save, start Linux, and check that this lists the device:'),
            const _Command('ls -l /dev/tpmrm0'),
            const Text('4. Then add your account to the tss group:'),
            const _Command('sudo usermod -aG tss "\$USER"'),
            const Text('and log out and back in.'),
            const SizedBox(height: 12),
            WideButton('Check again', icon: Icons.refresh, tonal: true, onPressed: check),
          ]),
        ];
      case HardwareState.keystore:
        return [
          _status(Icons.verified_user, Colors.green, 'Android Keystore ready',
              widget.strongBox
                  ? 'This phone has a StrongBox security chip. Setup keeps the unlock keys and the device key in it.'
                  : 'Setup keeps the unlock keys and the device key in the phone\'s secure hardware (the TEE).'),
          const Section('Good to know', children: [
            Text('• The phone needs a screen lock; the keys work only while the phone is unlocked.\n'
                '• Copying the app\'s files off the phone gains nothing: the keys never leave its hardware.\n'
                '• Unlike a computer\'s TPM, the Keystore does not count wrong PINs. Choose 6 digits or more.'),
          ]),
        ];
      case HardwareState.android:
        return [
          _status(Icons.phone_android, Colors.orange, 'Needs Android 9 or later',
              'This phone is too old for Symbolon to use its Keystore. Your PIN alone protects the device\'s share.'),
          const Section('Until then', children: [
            Text('• Choose a PIN of 6 digits or more.\n'
                '• Keep the phone\'s own screen lock and encryption on: they keep the app\'s files from being copied off it.\n'
                '• Keep the cosigner: even with the phone\'s share, nobody can sign without it.'),
          ]),
        ];
    }
  }

  Widget _status(IconData icon, Color color, String title, String text) {
    return Card(
      margin: const EdgeInsets.only(bottom: 16),
      child: ListTile(
        key: const Key('hardware-status'),
        leading: Icon(icon, color: color, size: 32),
        title: Text(title),
        subtitle: Text(text),
      ),
    );
  }
}

class _Command extends StatelessWidget {
  final String text;
  const _Command(this.text);

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 8),
      color: Theme.of(context).colorScheme.surfaceContainerHighest,
      child: ListTile(
        dense: true,
        title: SelectableText(text, style: const TextStyle(fontFamily: 'monospace')),
        trailing: IconButton(
          tooltip: 'Copy',
          icon: const Icon(Icons.copy, size: 20),
          onPressed: () {
            Clipboard.setData(ClipboardData(text: text));
            toast(context, 'Copied');
          },
        ),
      ),
    );
  }
}
