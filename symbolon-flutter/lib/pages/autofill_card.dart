import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../widgets.dart';

/// Turning Symbolon on as Android's autofill service (SPEC 22.6): logins,
/// cards and codes in apps and browsers. Checks again when the person comes
/// back from the system settings. With [onlyWhenOff], shows nothing once on.
class AutofillCard extends StatefulWidget {
  final bool onlyWhenOff;
  const AutofillCard({super.key, this.onlyWhenOff = false});

  @override
  State<AutofillCard> createState() => _AutofillCardState();
}

class _AutofillCardState extends State<AutofillCard> with WidgetsBindingObserver {
  static const _ch = MethodChannel('symbolon/platform');
  bool? on;

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
    if (!Platform.isAndroid) return;
    final v = await _ch.invokeMethod<bool>('autofillEnabled').catchError((_) => false);
    if (mounted) setState(() => on = v ?? false);
  }

  @override
  Widget build(BuildContext context) {
    final o = on;
    if (o == null || (o && widget.onlyWhenOff)) return const SizedBox.shrink();
    return Section('Fill in apps and browsers', key: const Key('autofill-card'), children: [
      if (o)
        const ListTile(
          contentPadding: EdgeInsets.zero,
          leading: Icon(Icons.check_circle, color: Colors.green),
          title: Text('Symbolon is your autofill service'),
          subtitle: Text('Sign-in fields offer "Fill with Symbolon". Nothing is filled until you unlock and choose.'),
        )
      else ...[
        const Text('Turn on Symbolon for autofill: sign-in and card fields in apps and browsers then offer "Fill with Symbolon". '
            'It names nothing until you unlock, and fills only what was saved for that app or site.'),
        const SizedBox(height: 12),
      ],
      WideButton(o ? 'Autofill settings' : 'Turn on Symbolon for autofill', key: const Key('autofill-settings'), icon: Icons.settings, tonal: o,
          onPressed: () => _ch.invokeMethod('openAutofillSettings')),
    ]);
  }
}
