import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

import '../app.dart';
import '../biometric.dart';
import '../hardware.dart';
import '../home_link.dart';
import '../validate.dart' as v;
import '../widgets.dart';
import 'hardware_page.dart';
import 'join_page.dart';
import 'scan_page.dart';

/// Setting up this device, as a guided flow: where the services are, a PIN,
/// then one step that creates the device, pairs it with the cosigner and
/// runs the inception, and last the recovery kit to write down.
class SetupPage extends StatefulWidget {
  final App app;
  const SetupPage({super.key, required this.app});

  @override
  State<SetupPage> createState() => _SetupPageState();
}

class _SetupPageState extends State<SetupPage> {
  int step = 0;

  // 1. Connect: a Symbolon Home box's pairing link (its QR code) fills in
  // everything; so does a demo stack (tools/demo.sh --lan).
  final homeLinkText = TextEditingController();
  HomeLink? home;          // pairing with a box: the device pairs through it after device new
  String? homeName;        // the person the box's invite is for
  bool otherWays = false;
  late final demoUrl = TextEditingController(text: widget.app.settings.demoUrl);
  bool manual = false;
  final relayHost = TextEditingController();
  final relayPort = TextEditingController();
  final ca = TextEditingController();
  final cosignerKeys = TextEditingController();
  final ws = [TextEditingController(), TextEditingController(), TextEditingController()];
  String? demoPrimes;      // fixture primes from the demo helper, written next to the device

  // 2. PIN.
  final pin = TextEditingController();
  final pin2 = TextEditingController();
  final duressPin = TextEditingController();
  HardwareState? hardware;
  bool useTpm = true;
  BioState bio = BioState.none;
  bool useBio = true;
  bool get hasHardware => hardware == HardwareState.ready || hardware == HardwareState.keystore;
  bool get unprotected => !hasHardware || !useTpm;

  // 3. The kit.
  String? kit;
  bool keptKit = false;

  App get app => widget.app;

  @override
  void initState() {
    super.initState();
    checkHardware();
  }

  Future<void> checkHardware() async {
    final h = await detectHardware(keystore: app.settings.keystoreAvailable);
    final b = await Bio.state();
    if (mounted) {
      setState(() {
        hardware = h;
        bio = b;
      });
    }
  }

  @override
  void dispose() {
    for (final c in [homeLinkText, demoUrl, relayHost, relayPort, ca, cosignerKeys, ...ws, pin, pin2, duressPin]) {
      c.dispose();
    }
    super.dispose();
  }

  void fail(String m) => ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(m), backgroundColor: Colors.red.shade700));

  String get demoBase => demoUrl.text.trim().replaceAll(RegExp(r'/+$'), '');

  Future<String> http(String method, String path, [String body = '']) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    try {
      final rq = method == 'POST' ? await client.postUrl(Uri.parse('$demoBase$path')) : await client.getUrl(Uri.parse('$demoBase$path'));
      if (body.isNotEmpty) {
        final bytes = utf8.encode(body);
        rq.contentLength = bytes.length;
        rq.add(bytes);
      }
      final rs = await rq.close();
      final text = await rs.transform(utf8.decoder).join();
      if (rs.statusCode != 200) throw HttpException('$path: ${rs.statusCode} $text');
      return text;
    } finally {
      client.close();
    }
  }

  Future<void> fetchDemo() async {
    FocusScope.of(context).unfocus();
    final bad = v.serviceUrl(demoUrl.text);
    if (bad != null) return fail('$bad, as shown by tools/demo.sh --lan.');
    try {
      final j = jsonDecode(await http('GET', '/setup')) as Map<String, dynamic>;
      final dir = '${app.dir}-demo';
      await Directory(dir).create(recursive: true);
      await File('$dir/device.primes').writeAsString(j['device_primes'] as String);
      await File('$dir/kit.primes').writeAsString(j['kit_primes'] as String);
      final w = (j['witnesses'] as List).cast<String>();
      await app.settings.update(demoUrl: demoBase);
      setState(() {
        relayHost.text = j['relay_host'] as String;
        relayPort.text = '${j['relay_port']}';
        cosignerKeys.text = j['cosigner_keys'] as String;
        for (var i = 0; i < 3; i++) {
          ws[i].text = w[i];
        }
        demoPrimes = dir;
        step = 1;
      });
    } catch (e) {
      fail('Cannot reach the demo stack at $demoBase. Is tools/demo.sh --lan running, and is this device on the same network?');
    }
  }

  Future<void> scanHome() async {
    final text = await Navigator.of(context).push<String>(MaterialPageRoute(builder: (_) => const ScanPage()));
    if (text == null || !mounted) return;
    homeLinkText.text = text;
    await joinHome();
  }

  // Fetches the setup from the box the link names (its certificate pinned
  // by the link), and keeps its CA for the agent.
  Future<void> joinHome() async {
    FocusScope.of(context).unfocus();
    final link = HomeLink.parse(homeLinkText.text);
    if (link == null) return fail('That is not a Symbolon Home code. It starts with symbolon://pair');
    try {
      final s = await HomeClient(link).setup();
      final caFile = File('${app.dir}-home-ca.pem');
      await caFile.parent.create(recursive: true);
      await caFile.writeAsString(s.caPem);
      setState(() {
        relayHost.text = s.relayHost;
        relayPort.text = '${s.relayPort}';
        cosignerKeys.text = s.cosignerKeys;
        for (var i = 0; i < 3 && i < s.witnesses.length; i++) {
          ws[i].text = s.witnesses[i];
        }
        ca.text = caFile.path;
        home = link;
        homeName = s.name;
        demoPrimes = null;
        step = 1;
      });
    } on HomeError catch (e) {
      fail(e.message);
    }
  }

  bool get connectReady =>
      relayHost.text.trim().isNotEmpty &&
      v.port(relayPort.text) == null &&
      v.hex(cosignerKeys.text) == null &&
      ws.every((w) => v.witness(w.text) == null);

  // The Keystore counts no wrong PINs, unlike a TPM: as long a PIN as without one.
  int get minPin => unprotected || hardware == HardwareState.keystore ? 6 : 4;

  Future<void> create() async {
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
    final hasDevice = File('${app.dir}/config.cbor').existsSync();
    if (!hasDevice) {
      final made = await runTask(
          context,
          "Creating this device's keys",
          () => app.cli.deviceNew(app.dir, relayHost.text.trim(), int.parse(relayPort.text.trim()), p, duressPin.text,
              unprotected: unprotected, keystore: hardware == HardwareState.keystore, ca: ca.text.trim()),
          detail: 'Your PIN is stretched so that guessing it is slow.',
          usually: 'a few seconds');
      if (!made.ok || !mounted) return;
      final h = home;
      if (h != null) {
        try {
          await HomeClient(h).pair(made.lines.last);
        } on HomeError catch (e) {
          return fail(e.message);
        }
      } else if (demoPrimes != null) {
        try {
          await http('POST', '/pair', made.lines.last);
        } catch (e) {
          return fail('The demo cosigner did not accept this device: $e');
        }
      }
    }
    if (!mounted) return;
    final dp = demoPrimes;
    final r = await runTask(
        context,
        'Creating your identity',
        () => app.cli.deviceInit(app.dir, cosignerKeys.text.trim(), [for (final w in ws) w.text.trim()], p,
            devicePrimes: dp == null ? '' : '$dp/device.primes', kitPrimes: dp == null ? '' : '$dp/kit.primes'),
        detail: dp == null
            ? 'This device and your Symbolon Home box make your key together. It is real work for the phone: keep the app open.'
            : 'This device and the cosigner generate a key together, and the witnesses record the result.',
        usually: dp == null ? '5-20 minutes' : '1-3 minutes');
    if (!r.ok || !mounted) return;
    if (bio.supported && bio.biometric && useBio) await Bio.enroll(p);
    if (!mounted) return;
    app.session.remember(p);
    pin.clear();
    pin2.clear();
    duressPin.clear();
    setState(() {
      kit = r.lines.where((l) => l.startsWith('RECOVERY KIT')).map((l) => l.split(': ').last).firstOrNull;
      step = 2;
    });
  }

  @override
  Widget build(BuildContext context) {
    final steps = [connectStep, pinStep, kitStep];
    return PopScope(
      canPop: step != 2 || keptKit,
      child: Scaffold(
        appBar: AppBar(
          title: const Text('Set up this device'),
          bottom: PreferredSize(preferredSize: const Size.fromHeight(4), child: LinearProgressIndicator(value: (step + 1) / 3)),
        ),
        body: PageBody(children: [steps[step]()]),
      ),
    );
  }

  Widget connectStep() {
    final t = Theme.of(context).textTheme;
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Text('Step 1 of 3 · Connect', style: t.labelLarge),
      const SizedBox(height: 4),
      Text('Connect to your Symbolon Home', style: t.headlineSmall),
      const SizedBox(height: 8),
      const Text('Your Symbolon Home box shows a code when you invite someone. Scan it, or paste the link it gives.'),
      const SizedBox(height: 16),
      if (Platform.isAndroid || Platform.isIOS) ...[
        WideButton('Scan the code', key: const Key('scan-home'), icon: Icons.qr_code_scanner, onPressed: scanHome),
        const SizedBox(height: 12),
      ],
      Field(homeLinkText, 'Or paste the link', hint: 'symbolon://pair?…', url: true, fieldKey: const Key('home-link'), action: TextInputAction.done,
          check: v.optional((s) => HomeLink.parse(s) == null ? 'Not a Symbolon Home link' : null)),
      WideButton('Connect', key: const Key('join-home'), icon: Icons.link, tonal: true, onPressed: joinHome),
      const SizedBox(height: 16),
      Section('Already use Symbolon?', subtitle: 'On your phone or another computer: this device joins that identity, with the same vault and passkeys.', children: [
        WideButton('Join from your other device', key: const Key('join-identity'), icon: Icons.devices, tonal: true, onPressed: () async {
          final joined = await Navigator.of(context).push<bool>(MaterialPageRoute(builder: (_) => JoinPage(app: app)));
          if (joined == true && mounted) Navigator.of(context).pop();
        }),
      ]),
      const SizedBox(height: 8),
      TextButton(onPressed: () => setState(() => otherWays = !otherWays), child: Text(otherWays ? 'Hide other ways' : 'Other ways to connect')),
      if (otherWays) ...[
      Section('Demo stack', subtitle: 'From tools/demo.sh --lan on a computer on this network.', children: [
        Field(demoUrl, 'Demo address', hint: 'http://192.168.1.20:47000', url: true, fieldKey: const Key('demo-url'), action: TextInputAction.done, check: v.serviceUrl),
        WideButton('Connect', key: const Key('join-demo'), icon: Icons.wifi, onPressed: fetchDemo),
      ]),
      TextButton(onPressed: () => setState(() => manual = !manual), child: Text(manual ? 'Hide manual setup' : 'Enter the details by hand')),
      if (manual)
        Section('Manual setup', children: [
          Field(relayHost, 'Relay host', url: true, check: (s) => v.required(s, 'The relay host')),
          Field(relayPort, 'Relay port', numeric: true, check: v.port),
          Field(ca, 'CA certificate file (TLS)', hint: 'leave empty for plain HTTP'),
          Field(cosignerKeys, "Cosigner's keys", hint: 'printed by symbolon cosigner new', check: v.hex),
          for (var i = 0; i < 3; i++) Field(ws[i], 'Witness ${i + 1}', hint: 'host:port:public key', check: v.witness),
          WideButton('Next', onPressed: () => connectReady ? setState(() => step = 1) : fail('Check the relay, the cosigner\'s keys and the three witnesses (marked in red).')),
        ]),
      ],
    ]);
  }

  Widget pinStep() {
    final t = Theme.of(context).textTheme;
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Text('Step 2 of 3 · PIN', style: t.labelLarge),
      const SizedBox(height: 4),
      Text('Choose your PIN', style: t.headlineSmall),
      const SizedBox(height: 8),
      Text(unprotected
          ? 'Your PIN unlocks this device. No hardware key store is in use here, so choose at least 6 digits.'
          : hardware == HardwareState.keystore
              ? 'Your PIN unlocks this device, together with keys in the phone\'s security chip that cannot be copied off it.'
              : 'Your PIN unlocks this device; the TPM limits how many wrong guesses it allows.'),
      const SizedBox(height: 12),
      protectionCard(),
      if (bio.supported && bio.biometric)
        Padding(
          padding: const EdgeInsets.only(top: 12),
          child: Card(
            margin: EdgeInsets.zero,
            child: SwitchListTile(
              key: const Key('use-bio'),
              secondary: const Icon(Icons.fingerprint),
              title: const Text('Unlock with your fingerprint or face'),
              subtitle: const Text('The PIN stays the way back in, after a restart or a new fingerprint.'),
              value: useBio,
              onChanged: (v) => setState(() => useBio = v),
            ),
          ),
        ),
      const SizedBox(height: 12),
      Field(pin, 'PIN', obscure: true, numeric: true, fieldKey: const Key('pin'), check: (s) => v.pin(s, min: minPin)),
      Field(pin2, 'PIN again', obscure: true, numeric: true, fieldKey: const Key('pin2'), action: TextInputAction.done, check: (s) => s == pin.text ? null : 'The PINs differ'),
      ExpansionTile(
        tilePadding: EdgeInsets.zero,
        title: const Text('Duress PIN (optional)'),
        subtitle: const Text('A second PIN that opens a harmless view'),
        children: [
          const Text('Under the duress PIN this device shows only the passkeys you mark for it, and quietly refuses to change your '
              'identity. Use it if someone forces you to unlock.'),
          const SizedBox(height: 12),
          Field(duressPin, 'Duress PIN', obscure: true, numeric: true, check: v.optional((s) => s == pin.text ? 'Must differ from your PIN' : v.pin(s, min: minPin))),
        ],
      ),
      if (demoPrimes != null)
        const Padding(
          padding: EdgeInsets.only(bottom: 12),
          child: Text('Demo stack: test keys, for trying Symbolon out only.', style: TextStyle(color: Colors.orange)),
        ),
      const SizedBox(height: 8),
      WideButton('Create my identity', key: const Key('create'), icon: Icons.fingerprint, onPressed: create),
      TextButton(onPressed: () => setState(() => step = 0), child: const Text('Back')),
    ]);
  }

  // Which key store protects the device, with help to turn one on.
  Widget protectionCard() {
    final h = hardware;
    if (h == null) return const LinearProgressIndicator();
    if (h == HardwareState.keystore) {
      return Card(
        margin: EdgeInsets.zero,
        child: SwitchListTile(
          key: const Key('use-tpm'),
          secondary: const Icon(Icons.verified_user, color: Colors.green),
          title: const Text('Protect with the Android Keystore'),
          subtitle: Text('Recommended: the unlock keys and the device key stay in ${app.settings.strongBox ? 'the phone\'s StrongBox chip' : 'the phone\'s secure hardware'}. '
              'The phone needs a screen lock.'),
          value: useTpm,
          onChanged: (v) => setState(() => useTpm = v),
        ),
      );
    }
    if (h == HardwareState.ready) {
      return Card(
        margin: EdgeInsets.zero,
        child: SwitchListTile(
          key: const Key('use-tpm'),
          secondary: const Icon(Icons.verified_user, color: Colors.green),
          title: const Text('Protect with the TPM'),
          subtitle: const Text('Recommended: the unlock keys stay in this computer\'s security chip.'),
          value: useTpm,
          onChanged: (v) => setState(() => useTpm = v),
        ),
      );
    }
    return Card(
      margin: EdgeInsets.zero,
      child: ListTile(
        key: const Key('hardware-help'),
        leading: const Icon(Icons.warning_amber, color: Colors.orange),
        title: const Text('No hardware key store'),
        subtitle: Text(h == HardwareState.android
            ? 'This phone is too old (before Android 9). Tap to learn more.'
            : h == HardwareState.noAccess
                ? 'This computer has a TPM you are not allowed to use yet. Tap to fix.'
                : 'No TPM found. Tap to see how to turn one on.'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () async {
          await Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => HardwarePage(keystore: app.settings.keystoreAvailable, strongBox: app.settings.strongBox)));
          checkHardware();
        },
      ),
    );
  }

  Widget kitStep() {
    final t = Theme.of(context).textTheme;
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Text('Step 3 of 3 · Recovery kit', style: t.labelLarge),
      const SizedBox(height: 4),
      Text('Your identity is ready', key: const Key('setup-done'), style: t.headlineSmall),
      const SizedBox(height: 12),
      const Text('Write down your recovery kit now and keep it somewhere safe. With it you can recover your identity '
          'if you lose every device. It is shown only this once.'),
      const SizedBox(height: 16),
      if (kit != null)
        Card(
          color: Colors.amber.shade100,
          child: Padding(padding: const EdgeInsets.all(12), child: Theme(data: ThemeData.light(), child: HexValue('Recovery kit', kit!, secret: true))),
        ),
      CheckboxListTile(
        key: const Key('kept-kit'),
        contentPadding: EdgeInsets.zero,
        value: keptKit,
        onChanged: (v) => setState(() => keptKit = v ?? false),
        title: const Text('I have written it down'),
      ),
      WideButton('Done', key: const Key('setup-finish'), onPressed: keptKit ? () => Navigator.of(context).pop() : null),
    ]);
  }
}
