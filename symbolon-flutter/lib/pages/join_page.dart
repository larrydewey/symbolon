import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app.dart';
import '../biometric.dart';
import '../hardware.dart';
import '../qr_view.dart';
import '../validate.dart' as v;
import '../widgets.dart';

/// This device's network addresses, for the code: IPv4 first, no loopback.
Future<List<String>> localAddresses() async {
  try {
    final ifs = await NetworkInterface.list(includeLoopback: false, type: InternetAddressType.any);
    final v4 = [for (final i in ifs) for (final a in i.addresses) if (a.type == InternetAddressType.IPv4 && !a.isLinkLocal) a.address];
    final v6 = [for (final i in ifs) for (final a in i.addresses) if (a.type == InternetAddressType.IPv6 && !a.isLinkLocal) a.address];
    return [...v4, ...v6].take(4).toList();
  } catch (_) {
    return [];
  }
}

/// Joining an identity you already have on another device (SPEC 11.5):
/// choose this device's PIN, then this page shows a code. On the other
/// device, More › Devices › Add a device scans it; the two devices find each
/// other on the local network, this one learns the relay from the other,
/// and the identity is re-shared to include it. Nothing to type or copy.
class JoinPage extends StatefulWidget {
  final App app;
  /// Finds this device's addresses; replaced in tests.
  final Future<List<String>> Function() addresses;
  const JoinPage({super.key, required this.app, this.addresses = localAddresses});

  @override
  State<JoinPage> createState() => _JoinPageState();
}

enum _Stage { pin, code, joining, done, failed }

class _JoinPageState extends State<JoinPage> {
  final pin = TextEditingController();
  final pin2 = TextEditingController();
  final duressPin = TextEditingController();
  HardwareState? hardware;
  _Stage stage = _Stage.pin;
  String link = '';
  String status = '';
  String error = '';

  App get app => widget.app;
  bool get unprotected => !(hardware == HardwareState.ready || hardware == HardwareState.keystore);
  int get minPin => unprotected || hardware == HardwareState.keystore ? 6 : 4;

  @override
  void initState() {
    super.initState();
    detectHardware(keystore: app.settings.keystoreAvailable).then((h) {
      if (mounted) setState(() => hardware = h);
    });
  }

  @override
  void dispose() {
    pin.dispose();
    pin2.dispose();
    duressPin.dispose();
    super.dispose();
  }

  void fail(String m) => toast(context, m);

  // What the agent reports, in words for the page.
  String said(String line) {
    final l = line.startsWith('device: ') ? line.substring(8) : line;
    if (l.startsWith('making this device') || l.startsWith('using this device')) return 'Your other device answered. Setting this device up…';
    if (l.startsWith('joining the identity')) return 'Joining your identity. This usually takes 1 to 3 minutes; keep both devices on.';
    if (l.startsWith('waiting for the enrolling device')) return 'Waiting for your other device to add this one…';
    if (l.startsWith('a connection without')) return 'Something else on the network tried to answer; it was refused.';
    return '';
  }

  Future<void> start() async {
    FocusScope.of(context).unfocus();
    final bad = v.pin(pin.text, min: minPin);
    if (bad != null) return fail('PIN: $bad.');
    if (pin.text != pin2.text) return fail('The two PINs differ.');
    if (duressPin.text.isNotEmpty) {
      final d = v.pin(duressPin.text, min: minPin);
      if (d != null) return fail('Duress PIN: $d.');
      if (duressPin.text == pin.text) return fail('The duress PIN must differ from your PIN.');
    }
    final p = pin.text;
    final hosts = await widget.addresses();
    if (!mounted) return;
    setState(() {
      stage = _Stage.code;
      status = 'Starting…';
    });
    final r = await app.cli.linkNew(app.dir, hosts, p, duressPin.text, (line) {
      if (!mounted) return;
      if (line.startsWith('link ')) {
        setState(() {
          link = line.substring(5).trim();
          status = 'Waiting for your other device to scan the code…';
        });
        return;
      }
      final s = said(line);
      if (s.isNotEmpty) {
        setState(() {
          status = s;
          if (line.contains('making this device') || line.contains('using this device') || line.contains('joining')) stage = _Stage.joining;
        });
      }
    }, unprotected: unprotected, keystore: hardware == HardwareState.keystore);
    if (!mounted) return;
    if (!r.ok) {
      setState(() {
        stage = _Stage.failed;
        error = friendlyError(r);
      });
      return;
    }
    final bio = await Bio.state();
    if (bio.supported && bio.biometric) await Bio.enroll(p);
    if (!mounted) return;
    app.session.remember(p);
    pin.clear();
    pin2.clear();
    duressPin.clear();
    setState(() => stage = _Stage.done);
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return PopScope(
      canPop: stage != _Stage.code && stage != _Stage.joining,
      child: Scaffold(
        appBar: AppBar(title: const Text('Join from your other device')),
        body: PageBody(children: [
          if (stage == _Stage.pin) ...[
            Text('Choose a PIN for this device', style: t.headlineSmall),
            const SizedBox(height: 8),
            const Text('This device will join the identity you already use on your phone or another computer: '
                'the same vault, the same passkeys. It gets its own PIN.'),
            const SizedBox(height: 16),
            Field(pin, 'PIN', obscure: true, numeric: true, fieldKey: const Key('join-pin')),
            Field(pin2, 'The same PIN again', obscure: true, numeric: true, fieldKey: const Key('join-pin2')),
            Field(duressPin, 'Duress PIN (optional)', obscure: true, numeric: true, fieldKey: const Key('join-duress'), action: TextInputAction.done),
            WideButton('Show the code', key: const Key('join-start'), icon: Icons.qr_code_2, onPressed: hardware == null ? null : start),
          ],
          if (stage == _Stage.code || stage == _Stage.joining) ...[
            Text(stage == _Stage.code ? 'Scan this with your other device' : 'Joining', style: t.headlineSmall, textAlign: TextAlign.center),
            const SizedBox(height: 8),
            if (stage == _Stage.code)
              const Text('On the device that already has your identity: More › Devices › Add a device › Scan the code. '
                  'Both devices must be on the same network.', textAlign: TextAlign.center),
            const SizedBox(height: 16),
            if (stage == _Stage.code && link.isNotEmpty) ...[
              Center(child: QrView(link, key: const Key('join-qr'))),
              const SizedBox(height: 8),
              Center(
                child: TextButton.icon(
                  key: const Key('join-copy'),
                  icon: const Icon(Icons.copy, size: 18),
                  label: const Text('Copy the link instead'),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: link));
                    toast(context, 'Copied. Paste it on the other device under Add a device.');
                  },
                ),
              ),
            ],
            if (stage == _Stage.joining) const Center(child: Padding(padding: EdgeInsets.all(24), child: CircularProgressIndicator())),
            Text(status, key: const Key('join-status'), textAlign: TextAlign.center),
          ],
          if (stage == _Stage.done) ...[
            const Icon(Icons.check_circle, size: 56, color: Colors.green),
            const SizedBox(height: 12),
            Text('This device is part of your identity', style: t.headlineSmall, textAlign: TextAlign.center, key: const Key('join-done')),
            const SizedBox(height: 8),
            const Text('Your vault and passkeys are here now. Your recovery kit stays as it was.', textAlign: TextAlign.center),
            const SizedBox(height: 16),
            WideButton('Done', key: const Key('join-finish'), onPressed: () => Navigator.of(context).pop(true)),
          ],
          if (stage == _Stage.failed) ...[
            Text('That did not work', style: t.headlineSmall),
            const SizedBox(height: 8),
            Text(error, key: const Key('join-error')),
            const SizedBox(height: 16),
            WideButton('Try again', key: const Key('join-retry'), onPressed: () => setState(() => stage = _Stage.pin)),
          ],
        ]),
      ),
    );
  }
}
