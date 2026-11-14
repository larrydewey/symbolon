// Symbolon for the Linux desktop and Android: a front end to the `symbolon` agent.

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'app.dart';
import 'brand.dart';
import 'fill_consent.dart';
import 'ssh_consent.dart';
import 'pages/home_page.dart';
import 'pages/more_page.dart';
import 'pages/passkeys_page.dart';
import 'pages/tutorial_page.dart';
import 'pages/vault_page.dart';
import 'passkey_main.dart';
import 'settings.dart';

Future<void> main(List<String> args) async {
  // The browser extension's fill request (SPEC 22.5), opened by the agent.
  if (args.length == 2 && args[0] == '--fill-consent') return runFillConsent(args[1]);
  // The SSH agent's signature request (SPEC 16.1).
  if (args.length == 2 && args[0] == '--ssh-consent') return runSshConsent(args[1]);
  WidgetsFlutterBinding.ensureInitialized();
  runApp(SymbolonApp(settings: await loadSettings()));
}

/// The passkey screen Android opens for a site or an app (PasskeyActivity).
@pragma('vm:entry-point')
Future<void> passkeyMain() => runPasskeyScreen();

/// On Android the agent is the app's own `lib/<abi>/libsymbolon.so` and
/// everything lives in the app's files directory; elsewhere, the XDG paths.
Future<Settings> loadSettings() async {
  if (!Platform.isAndroid) return Settings.load(Settings.defaultFile());
  final paths = await const MethodChannel('symbolon/platform').invokeMapMethod<String, String>('paths') ?? {};
  final files = paths['filesDir'] ?? '.';
  final s = await Settings.load(File('$files/settings.json'), defaultDeviceDir: '$files/device');
  // The library directory changes with every install: always the bundled agent.
  s.binary = '${paths['nativeLibraryDir']}/libsymbolon.so';
  final ks = await const MethodChannel('symbolon/platform').invokeMapMethod<String, dynamic>('keystore') ?? {};
  s.agentEnv = {'SYMBOLON_KEYSTORE': (ks['endpoint'] as String?) ?? ''};
  s.keystoreAvailable = (ks['available'] as bool?) ?? false;
  s.strongBox = (ks['strongbox'] as bool?) ?? false;
  s.authBound = (ks['authBound'] as bool?) ?? false;
  return s;
}

class SymbolonApp extends StatefulWidget {
  final Settings settings;
  const SymbolonApp({super.key, required this.settings});

  @override
  State<SymbolonApp> createState() => _SymbolonAppState();
}

class _SymbolonAppState extends State<SymbolonApp> {
  late final App app = App(widget.settings);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Symbolon',
      debugShowCheckedModeBanner: false,
      theme: Brand.theme(Brightness.light),
      darkTheme: Brand.theme(Brightness.dark),
      home: Shell(app: app),
    );
  }
}

class Shell extends StatefulWidget {
  final App app;
  const Shell({super.key, required this.app});

  @override
  State<Shell> createState() => _ShellState();
}

class _ShellState extends State<Shell> with WidgetsBindingObserver {
  int index = 0;
  int refresh = 0;   // bumped to rebuild Home after setup or a settings change

  static const tabs = [
    (Icons.home_outlined, Icons.home, 'Home'),
    (Icons.key_outlined, Icons.key, 'Passkeys'),
    (Icons.lock_outline, Icons.lock, 'Vault'),
    (Icons.more_horiz, Icons.more_horiz, 'More'),
  ];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    widget.app.session.addListener(_changed);
    widget.app.settings.addListener(_changed);
    if (!widget.app.settings.tutorialSeen) WidgetsBinding.instance.addPostFrameCallback((_) => _tutorial());
  }

  // The first start: how the app works, which the user may skip.
  Future<void> _tutorial() async {
    await Navigator.of(context).push(MaterialPageRoute<void>(fullscreenDialog: true, builder: (_) => const TutorialPage()));
    await widget.app.settings.update(tutorialSeen: true);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    widget.app.session.removeListener(_changed);
    widget.app.settings.removeListener(_changed);
    super.dispose();
  }

  void _changed() => setState(() {});

  // Leaving the app (another app, the home screen, the screen off) locks.
  @override
  void didChangeAppLifecycleState(AppLifecycleState s) {
    if (s == AppLifecycleState.paused || s == AppLifecycleState.hidden) widget.app.session.lock();
  }

  void go(int i) => setState(() {
        index = i;
        refresh++;
      });

  @override
  Widget build(BuildContext context) {
    final app = widget.app;
    final pages = [
      HomePage(key: ValueKey('home$refresh'), app: app, go: go),
      // Their own messengers: a message lifts the tab's Add button instead
      // of covering it.
      ScaffoldMessenger(child: PasskeysPage(app: app)),
      ScaffoldMessenger(child: VaultPage(key: ValueKey('vault${app.dir}'), app: app, active: index == 2)),
      MorePage(app: app, onSetupDone: () => go(0)),
    ];
    final lock = app.session.unlocked
        ? IconButton(key: const Key('lock'), tooltip: 'Lock now', icon: const Icon(Icons.lock_open), onPressed: app.session.lock)
        : const IconButton(tooltip: 'Locked', icon: Icon(Icons.lock), onPressed: null);
    final wide = MediaQuery.sizeOf(context).width >= 720;
    final body = IndexedStack(index: index, children: pages);
    if (wide) {
      return Scaffold(
        body: Row(children: [
          NavigationRail(
            selectedIndex: index,
            labelType: NavigationRailLabelType.all,
            leading: Padding(
              padding: const EdgeInsets.symmetric(vertical: 12),
              child: Column(children: [const SymbolonMark(size: 40), const SizedBox(height: 8), lock]),
            ),
            destinations: [for (final t in tabs) NavigationRailDestination(icon: Icon(t.$1), selectedIcon: Icon(t.$2), label: Text(t.$3))],
            onDestinationSelected: go,
          ),
          const VerticalDivider(width: 1),
          Expanded(child: body),
        ]),
      );
    }
    return Scaffold(
      appBar: AppBar(
        // Home carries the name and the mark; the other tabs their own name.
        title: index == 0
            ? const Row(mainAxisSize: MainAxisSize.min, children: [SymbolonMark(size: 28), SizedBox(width: 10), Text('Symbolon')])
            : Text(tabs[index].$3),
        actions: [lock],
      ),
      body: body,
      bottomNavigationBar: NavigationBar(
        selectedIndex: index,
        onDestinationSelected: go,
        destinations: [for (final t in tabs) NavigationDestination(icon: Icon(t.$1), selectedIcon: Icon(t.$2), label: t.$3)],
      ),
    );
  }
}
