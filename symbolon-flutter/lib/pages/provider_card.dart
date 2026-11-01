import 'package:flutter/material.dart';

import '../provider.dart';
import '../widgets.dart';

/// Turning Symbolon on as the phone's passkey provider, and how signing in
/// on a computer then works. Checks again when the person comes back from
/// the system settings. With [onlyWhenOff], shows nothing once it is on.
class ProviderCard extends StatefulWidget {
  final bool onlyWhenOff;
  const ProviderCard({super.key, this.onlyWhenOff = false});

  @override
  State<ProviderCard> createState() => _ProviderCardState();
}

class _ProviderCardState extends State<ProviderCard> with WidgetsBindingObserver {
  ProviderState? state;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    check();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState s) {
    if (s == AppLifecycleState.resumed) check();
  }

  Future<void> check() async {
    final s = await PasskeyProvider.state();
    if (mounted) setState(() => state = s);
  }

  static const _computer = 'On a computer: when a site offers a passkey, choose "Use a phone or tablet" (or "another device"). '
      'Scan the QR code it shows with this phone\'s camera, and choose Symbolon. Keep Bluetooth on: the computer checks the phone is nearby.';

  @override
  Widget build(BuildContext context) {
    switch (state) {
      case null:
        return const SizedBox.shrink();
      case ProviderState.unsupported:
        if (widget.onlyWhenOff) return const SizedBox.shrink();
        return const Section('Sign in to sites with Symbolon', children: [
          Text('Using Symbolon passkeys in other apps and browsers, and from a computer\'s QR code, needs Android 14 or later.'),
        ]);
      case ProviderState.off:
        return Section('Sign in to sites with Symbolon', key: const Key('provider-off'), children: [
          const Text('Turn Symbolon on as a passkey provider. Then sites and apps on this phone offer your Symbolon passkeys, '
              'and so does the QR code a computer shows.'),
          const SizedBox(height: 8),
          const Text('In the page that opens, turn on Symbolon (you can keep Google Password Manager on too).'),
          const SizedBox(height: 12),
          WideButton('Turn on Symbolon for passkeys', key: const Key('provider-settings'), icon: Icons.settings, onPressed: PasskeyProvider.openSettings),
        ]);
      case ProviderState.on:
        if (widget.onlyWhenOff) return const SizedBox.shrink();
        return Section('Sign in to sites with Symbolon', key: const Key('provider-on'), children: [
          const ListTile(
            contentPadding: EdgeInsets.zero,
            leading: Icon(Icons.check_circle, color: Colors.green),
            title: Text('Symbolon is on as a passkey provider'),
          ),
          const Text(_computer),
          TextButton(onPressed: PasskeyProvider.openSettings, child: const Text('Passkey provider settings')),
        ]);
    }
  }
}
