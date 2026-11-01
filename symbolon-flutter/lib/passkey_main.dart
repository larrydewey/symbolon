// The passkey screen Android opens when a site or an app (or a computer,
// through a QR code) asks Symbolon for a passkey (SPEC 22.1, 22.2). It runs
// apart from the app: it shows who is asking and for which site, takes the
// PIN (so the response truthfully says the user was verified), and has the
// agent make or use the passkey with the cosigner.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'biometric.dart';
import 'cli.dart';
import 'main.dart' show loadSettings;
import 'settings.dart';
import 'webauthn.dart';
import 'widgets.dart';

const _channel = MethodChannel('symbolon/passkey');

/// Started by `passkeyMain` in main.dart (an entry point must be in the
/// library the app is built from).
Future<void> runPasskeyScreen() async {
  WidgetsFlutterBinding.ensureInitialized();
  final settings = await loadSettings();
  final request = Map<String, dynamic>.from(await _channel.invokeMapMethod<String, dynamic>('request') ?? {});
  runApp(PasskeyApp(settings: settings, request: request, channel: _channel));
}

class PasskeyApp extends StatelessWidget {
  final Settings settings;
  final Map<String, dynamic> request;
  final MethodChannel channel;
  const PasskeyApp({super.key, required this.settings, required this.request, required this.channel});

  @override
  Widget build(BuildContext context) {
    const seed = Colors.indigo;
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorSchemeSeed: seed, useMaterial3: true),
      darkTheme: ThemeData(colorSchemeSeed: seed, brightness: Brightness.dark, useMaterial3: true),
      home: PasskeyPage(settings: settings, request: request, channel: channel),
    );
  }
}

class PasskeyPage extends StatefulWidget {
  final Settings settings;
  final Map<String, dynamic> request;
  final MethodChannel channel;
  const PasskeyPage({super.key, required this.settings, required this.request, required this.channel});

  @override
  State<PasskeyPage> createState() => _PasskeyPageState();
}

class _PasskeyPageState extends State<PasskeyPage> {
  final pin = TextEditingController();
  String? problem;     // why this request cannot be served, shown instead of the form
  String? error;       // a failed attempt (wrong PIN), shown above the form
  bool busy = false;

  Map<String, dynamic> get rq => widget.request;
  bool get create => rq['kind'] == 'create';
  String get origin => (rq['origin'] as String?) ?? '';
  SymbolonCli get cli => SymbolonCli(widget.settings.binary, env: widget.settings.agentEnv);
  String get dir => widget.settings.deviceDir;

  late final CreateRequest? cr = create ? CreateRequest.parse(rq['requestJson'] as String, origin) : null;
  late final Credential? cred = create ? null : widget.settings.credentials.where((c) => c.id == rq['cid']).firstOrNull;
  String get rpId => create ? cr!.rpId : ((rq['rp'] as String?) ?? '');

  BioState bio = BioState.none;

  @override
  void initState() {
    super.initState();
    problem = _check();
    Bio.state().then((b) {
      if (mounted) setState(() => bio = b);
    });
  }

  // The fingerprint gives the kept PIN; the check also lets the agent's
  // Keystore keys work for the next 30 seconds.
  Future<void> goBio() async {
    final p = await Bio.unlock(create ? 'Create a passkey for $rpId' : 'Sign in to $rpId');
    if (p == null || !mounted) return;
    pin.text = p;
    await go();
  }

  String? _check() {
    if (rq.isEmpty) return 'The request could not be read.';
    if (!originMayUse(origin, rpId)) return 'The page at $origin may not use passkeys of $rpId.';
    if (create) {
      final c = cr!;
      if (!c.es256) return '$rpId does not accept the kind of passkey Symbolon makes (ES256).';
      final mine = widget.settings.credentials.where((x) => x.rp == c.rpId).map((x) => b64u(fromHex(x.id)));
      if (mine.any(c.exclude.contains)) return 'You already have a Symbolon passkey for this account at ${c.rpId}.';
    } else if (cred == null) {
      return 'That passkey is no longer on this device.';
    }
    return null;
  }

  String get requester {
    if (origin.startsWith('android:')) return 'the app ${rq['callingPackage']}';
    return origin;
  }

  Future<void> cancel() => widget.channel.invokeMethod('cancel');

  Future<void> go() async {
    if (pin.text.isEmpty || busy) return;
    setState(() {
      busy = true;
      error = null;
    });
    final p = pin.text;
    final cdh = rq['clientDataHash'] as String;
    final cdj = rq['clientDataJSON'] as String?;
    final r = create
        ? await runTask(context, 'Creating a passkey for $rpId', () => cli.waRegister(dir, rpId, p),
            detail: 'Its key is split between this device and the cosigner.', usually: 'a few seconds')
        : await runTask(context, 'Signing in to $rpId', () => cli.waAssert(dir, rpId, cred!.id, cdh, p),
            detail: 'This device and the cosigner sign together.', usually: '10-30 seconds');
    pin.clear();
    if (!mounted) return;
    if (!r.ok) {
      setState(() {
        busy = false;
        error = friendlyError(r);
      });
      return;
    }
    final ad = r.field('authenticator-data') ?? '';
    if (create) {
      final c = cr!;
      final id = r.field('credential-id') ?? '', pub = r.field('public-key') ?? '';
      await widget.settings.addCredential(
          Credential(c.rpId, id, pub, userName: c.userName, displayName: c.displayName, userHandle: toHex(c.userId)));
      await widget.channel.invokeMethod('finish', {
        'json': registrationResponse(cidHex: id, publicKeyHex: pub, authDataHex: ad, attestationHex: r.field('attestation-object') ?? '', clientDataJSON: cdj),
      });
    } else {
      await widget.channel.invokeMethod('finish', {
        'json': assertionResponse(cidHex: cred!.id, authDataHex: ad, signatureDerHex: r.field('signature-der') ?? '', userHandleHex: cred!.userHandle, clientDataJSON: cdj),
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final account = create ? (cr!.userName.isNotEmpty ? cr!.userName : cr!.displayName) : (cred?.userName ?? '');
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (popped, _) {
        if (!popped && !busy) cancel();
      },
      child: Scaffold(
        body: PageBody(children: [
          const SizedBox(height: 24),
          Icon(Icons.fingerprint, size: 56, color: Theme.of(context).colorScheme.primary),
          const SizedBox(height: 16),
          Text(create ? 'Create a passkey' : 'Sign in with a passkey', style: t.headlineSmall, textAlign: TextAlign.center),
          const SizedBox(height: 24),
          Card(
            child: Column(children: [
              ListTile(key: const Key('pk-site'), leading: const Icon(Icons.language), title: Text(rpId), subtitle: const Text('Site')),
              if (account.isNotEmpty) ListTile(leading: const Icon(Icons.person_outline), title: Text(account), subtitle: const Text('Account')),
              ListTile(leading: const Icon(Icons.open_in_new), title: Text(requester), subtitle: const Text('Asked by')),
            ]),
          ),
          const SizedBox(height: 16),
          if (problem != null) ...[
            Text(problem!, key: const Key('pk-problem'), style: TextStyle(color: Theme.of(context).colorScheme.error)),
            const SizedBox(height: 16),
            WideButton('Close', onPressed: cancel),
          ] else ...[
            if (error != null)
              Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
            if (bio.enrolled) ...[
              WideButton(create ? 'Create with fingerprint' : 'Sign in with fingerprint', key: const Key('pk-bio'), icon: Icons.fingerprint, onPressed: busy ? null : goBio),
              const SizedBox(height: 16),
              const Text('Or type your PIN:'),
              const SizedBox(height: 8),
            ],
            Field(pin, 'Your Symbolon PIN', obscure: true, numeric: true, fieldKey: const Key('pk-pin'), action: TextInputAction.done),
            WideButton(create ? 'Create passkey' : 'Sign in', key: const Key('pk-go'), icon: Icons.check, onPressed: busy ? null : go),
            const SizedBox(height: 8),
            TextButton(onPressed: busy ? null : cancel, child: const Text('Cancel')),
          ],
        ]),
      ),
    );
  }
}
