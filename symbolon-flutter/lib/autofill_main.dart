// The screen Android opens when the person chooses "Fill with Symbolon", or
// when the system's prompt saves a login (SPEC 22.6). It runs apart from the
// app. It shows the requester first (the app, its publisher and where it was
// installed from; for a privileged browser, the page), opens the device with
// the agent (22.7: afresh, a security key's touch when one is enrolled), and
// offers only the items that may fill here: logins saved for this page or
// app, linked to the app in Symbolon, or linked by the site's Digital Asset
// Links; or cards. No item can be chosen by hand for an app or page that
// matches none.

import 'dart:io';

import 'package:material_ui/material_ui.dart';
import 'package:flutter/services.dart';

import 'applinks.dart';
import 'biometric.dart';
import 'brand.dart';
import 'cli.dart';
import 'fill_consent.dart' show siteCovers;
import 'main.dart' show loadSettings;
import 'pages/item_editor.dart' show strongPassword;
import 'settings.dart';
import 'vault_types.dart';
import 'widgets.dart';

const _channel = MethodChannel('symbolon/autofill');

/// Started by `autofillMain` in main.dart.
Future<void> runAutofillScreen() async {
  WidgetsFlutterBinding.ensureInitialized();
  final settings = await loadSettings();
  final request = Map<String, dynamic>.from(await _channel.invokeMapMethod<String, dynamic>('request') ?? {});
  runApp(AutofillApp(settings: settings, request: AutofillRequest.of(request), channel: _channel,
      links: AppLinks(File('${settings.file.parent.path}/applinks.json'))));
}

const _cardKinds = {'cc-name', 'cc-number', 'cc-exp', 'cc-exp-month', 'cc-exp-year', 'cc-csc'};

/// What Android asked, as AutofillActivity reports it.
class AutofillRequest {
  final bool save;
  final String package, label, installer, origin, apkKeyHash;
  final List<String> certs, kinds, claimed;
  final String saveUser, savePassword;
  const AutofillRequest({this.save = false, required this.package, this.label = '', this.installer = '', this.origin = '', this.apkKeyHash = '',
      this.certs = const [], this.kinds = const [], this.claimed = const [], this.saveUser = '', this.savePassword = ''});

  static AutofillRequest of(Map<String, dynamic> m) {
    List<String> ls(String k) => [for (final x in (m[k] as List?) ?? const []) '$x'];
    return AutofillRequest(
      save: m['mode'] == 'save',
      package: '${m['package'] ?? ''}',
      label: '${m['label'] ?? ''}',
      installer: '${m['installer'] ?? ''}',
      origin: '${m['origin'] ?? ''}',
      apkKeyHash: '${m['apkKeyHash'] ?? ''}',
      certs: ls('certs'),
      kinds: ls('kinds'),
      claimed: ls('claimed'),
      saveUser: '${m['saveUser'] ?? ''}',
      savePassword: '${m['savePassword'] ?? ''}',
    );
  }

  /// A privileged browser's page; else the request is the app's own.
  bool get isPage => origin.isNotEmpty;
  bool get wantsCard => kinds.any(_cardKinds.contains);
  bool asks(String kind) => kinds.contains(kind);

  /// Where it was installed from, in words; "" when not by an app store.
  String get store => switch (installer) {
        'com.android.vending' => 'Google Play',
        'org.fdroid.fdroid' || 'org.fdroid.basic' => 'F-Droid',
        'com.sec.android.app.samsungapps' => 'Galaxy Store',
        'com.amazon.venezia' => 'Amazon Appstore',
        'com.huawei.appmarket' => 'AppGallery',
        _ => '',
      };

  /// The request the agent's opening is bound to (22.7 item 4).
  String get fillText => 'fill ${wantsCard ? 'card' : 'login'} ${isPage ? origin : '$apkKeyHash $package'} ${([...kinds]..sort()).join(',')}';

  /// Whether the login [it] may fill here (22.6 item 3, without the
  /// Digital Asset Links, which [verifiedHosts] carries).
  bool fits(VaultItem it, List<String> verifiedHosts) {
    if (it.type != 'login') return false;
    if (isPage) return siteCovers(it.detail, origin);
    if (it.appLinks.any((l) => l.$1 == package && certs.contains(l.$2))) return true;
    return verifiedHosts.any((h) => siteCovers(it.detail, 'https://$h'));
  }
}

class AutofillApp extends StatelessWidget {
  final Settings settings;
  final AutofillRequest request;
  final MethodChannel channel;
  final AppLinks links;
  const AutofillApp({super.key, required this.settings, required this.request, required this.channel, required this.links});

  @override
  Widget build(BuildContext context) => MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: Brand.theme(Brightness.light),
        darkTheme: Brand.theme(Brightness.dark),
        home: AutofillPage(settings: settings, request: request, channel: channel, links: links),
      );
}

class AutofillPage extends StatefulWidget {
  final Settings settings;
  final AutofillRequest request;
  final MethodChannel channel;
  final AppLinks links;
  const AutofillPage({super.key, required this.settings, required this.request, required this.channel, required this.links});

  @override
  State<AutofillPage> createState() => _AutofillPageState();
}

class _AutofillPageState extends State<AutofillPage> {
  final pin = TextEditingController();
  final newUser = TextEditingController();
  String generated = strongPassword();
  bool busy = false, showPassword = false;
  String? error;
  String? unlocked;                 // the PIN, once the vault opened with it
  List<VaultItem>? all, matches;
  String? chosen;
  List<String> verifiedHosts = [];
  late final Future<void> checking = _checkLinks();

  AutofillRequest get r => widget.request;
  String get dir => widget.settings.deviceDir;
  // Every agent run is for this fill (22.7): the device's fill policy, and a
  // security key's touch bound to the request.
  SymbolonCli get cli => SymbolonCli(widget.settings.binary, env: {...widget.settings.agentEnv, 'SYMBOLON_FILL': r.fillText});
  // Saving reads and writes the whole item: not a fill.
  SymbolonCli get plainCli => SymbolonCli(widget.settings.binary, env: widget.settings.agentEnv);

  @override
  void initState() {
    super.initState();
    checking;
    WidgetsBinding.instance.addPostFrameCallback((_) => _biometric());
  }

  @override
  void dispose() {
    pin.dispose();
    newUser.dispose();
    super.dispose();
  }

  // The sites the app claims, confirmed by their Digital Asset Links.
  Future<void> _checkLinks() async {
    if (r.isPage || r.save || r.claimed.isEmpty) return;
    final v = await widget.links.verified(r.claimed, r.package, r.certs);
    if (mounted) setState(() => verifiedHosts = v);
  }

  // The fingerprint or face first, when it is set up; the PIN otherwise.
  Future<void> _biometric() async {
    final s = await Bio.state();
    if (!s.enrolled || !mounted) return;
    final p = await Bio.unlock(r.save ? 'Save to Symbolon' : 'Fill with Symbolon');
    if (p != null && mounted) await unlock(p);
  }

  Future<void> unlock([String? withPin]) async {
    final p = withPin ?? pin.text;
    if (p.isEmpty || busy) return;
    setState(() {
      busy = true;
      error = null;
    });
    final res = await (r.save ? plainCli : cli).vaultList(dir, p);
    await checking;
    if (!mounted) return;
    if (!res.ok) {
      setState(() {
        busy = false;
        error = friendlyError(res);
      });
      return;
    }
    final items = [for (final l in res.lines) VaultItem.parse(l)].whereType<VaultItem>().toList();
    final found = r.wantsCard ? items.where((i) => i.type == 'card').toList() : items.where((i) => r.fits(i, verifiedHosts)).toList();
    found.sort((a, b) => a.name.compareTo(b.name));
    pin.clear();
    setState(() {
      busy = false;
      unlocked = p;
      all = items;
      matches = found;
      // Filling: the only match is chosen. Saving: nothing is, so another
      // account's password is never replaced without a tap.
      chosen = !r.save && found.length == 1 ? found.first.name : null;
      if (r.save) newUser.text = r.saveUser;
    });
  }

  Future<void> fill() async {
    final name = chosen, p = unlocked;
    if (name == null || p == null || busy) return;
    setState(() => busy = true);
    final res = await cli.vaultShow(dir, name, p);
    if (!mounted) return;
    if (!res.ok) {
      setState(() {
        busy = false;
        error = friendlyError(res);
      });
      return;
    }
    final f = {
      for (final l in res.lines)
        if (l.contains(' ')) l.substring(0, l.indexOf(' ')): unhex(l.substring(l.indexOf(' ') + 1).trim()),
    };
    await widget.channel.invokeMethod('finish', {'values': valuesFor(f, r)});
  }

  /// The item's values by the kinds Android asked for; nothing else.
  static Map<String, String> valuesFor(Map<String, String> f, AutofillRequest r) {
    final exp = f['expiry'] ?? '';
    final mmyy = exp.length == 5;
    final v = <String, String>{
      'username': f['username'] ?? '',
      'email': f['username'] ?? '',
      'current-password': f['current'] ?? '',
      if (r.asks('one-time-code')) 'one-time-code': f['otp'] ?? '',
      'cc-name': f['cardholder'] ?? '',
      'cc-number': f['number'] ?? '',
      'cc-csc': f['cvv'] ?? '',
      'cc-exp': mmyy ? exp : '',
      'cc-exp-month': mmyy ? exp.substring(0, 2) : '',
      'cc-exp-year': mmyy ? '20${exp.substring(3)}' : '',
    };
    return {for (final k in r.kinds) if ((v[k] ?? '').isNotEmpty) k: v[k]!};
  }

  String freeName(String base) {
    final names = {for (final i in all ?? <VaultItem>[]) i.name};
    var n = base.isEmpty ? 'Login' : base;
    for (var i = 2; names.contains(n); i++) {
      n = '$base ($i)';
    }
    return n;
  }

  /// Where a new login is saved for: the page, or this app (22.6 item 6).
  Map<String, String> get placeFields => r.isPage ? {'origin': r.origin} : {'apps': '${r.package} ${r.certs.isEmpty ? '' : r.certs.first}'};
  String get placeName => r.isPage ? Uri.parse(r.origin).host : r.label;

  // Sign-up: a strong password, saved first and filled only once saved.
  Future<void> create() async {
    final p = unlocked;
    if (p == null || busy) return;
    setState(() => busy = true);
    final user = newUser.text.trim(), pw = generated;
    final saved = await cli.vaultSet(dir, freeName(placeName), 'login', {...placeFields, if (user.isNotEmpty) 'username': user, 'current': pw}, p);
    if (!mounted) return;
    if (!saved.ok) {
      setState(() {
        busy = false;
        error = friendlyError(saved);
      });
      return;
    }
    final out = {'username': user, 'email': user, 'current-password': pw, 'new-password': pw};
    await widget.channel.invokeMethod('finish', {'values': {for (final k in r.kinds) if ((out[k] ?? '').isNotEmpty) k: out[k]!}});
  }

  // Saving (22.6 item 6): a new login, or a new version of the matching one
  // with its previous password kept as a hidden field.
  Future<void> save() async {
    final p = unlocked;
    if (p == null || busy) return;
    setState(() => busy = true);
    final user = newUser.text.trim();
    final same = (matches ?? []).where((i) => i.name == chosen).firstOrNull;
    CliResult res;
    if (same != null) {
      final shown = await plainCli.vaultShow(dir, same.name, p);
      final f = {
        for (final l in shown.lines)
          if (l.contains(' ')) l.substring(0, l.indexOf(' ')): unhex(l.substring(l.indexOf(' ') + 1).trim()),
      }..remove('type')..remove('name');
      final old = f['current'] ?? '';
      if (old.isNotEmpty && old != r.savePassword) {
        var n = 1;
        while (f.containsKey('custom_$n')) {
          n++;
        }
        f['custom_$n'] = CustomField('Previous password', old, hidden: true).encode();
      }
      res = await plainCli.vaultSet(dir, same.name, 'login', {...f, if (user.isNotEmpty) 'username': user, 'current': r.savePassword}, p);
    } else {
      res = await plainCli.vaultSet(dir, freeName(placeName), 'login', {...placeFields, if (user.isNotEmpty) 'username': user, 'current': r.savePassword}, p);
    }
    // The saved login has a new password: the last breach check's finding is
    // about the old one.
    if (res.ok && same != null) await widget.settings.clearBreached(same.name);
    if (!mounted) return;
    if (!res.ok) {
      setState(() {
        busy = false;
        error = friendlyError(res);
      });
      return;
    }
    await widget.channel.invokeMethod('done');
  }

  Future<void> cancel() => widget.channel.invokeMethod('cancel');

  static String shortCert(String hex) => hex.length < 16 ? hex : [for (var i = 0; i < 16; i += 2) hex.substring(i, i + 2)].join(':').toUpperCase();

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final scheme = Theme.of(context).colorScheme;
    return Scaffold(
      body: PageBody(children: [
        const SizedBox(height: 16),
        const Center(child: SymbolonMark(size: 44)),
        const SizedBox(height: 12),
        Text(r.save ? 'Save to Symbolon' : (r.wantsCard ? 'Fill a card' : 'Fill a login'), style: t.headlineSmall, textAlign: TextAlign.center),
        const SizedBox(height: 16),
        _requester(t, scheme),
        const SizedBox(height: 16),
        if (error != null) Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(error!, key: const Key('af-error'), style: TextStyle(color: scheme.error))),
        if (unlocked == null) ...[
          Field(pin, 'Your Symbolon PIN', obscure: true, numeric: true, fieldKey: const Key('af-pin'), action: TextInputAction.done, onSubmitted: (_) => unlock()),
          WideButton('Unlock', key: const Key('af-unlock'), icon: Icons.lock_open, onPressed: busy ? null : unlock),
        ] else if (r.save)
          ..._saveForm(t)
        else ...[
          if (matches!.isEmpty)
            Text(r.wantsCard ? 'There is no card in your vault.'
                : 'Nothing in your vault is saved for ${r.isPage ? Uri.parse(r.origin).host : 'this app'}. '
                  'To use a login you have here, open it in Symbolon and choose "Use in an app". '
                  'Symbolon does not let an app pick one of your logins.',
                key: const Key('af-none')),
          for (final it in matches!) _choice(it),
          if (matches!.isNotEmpty) WideButton('Fill', key: const Key('af-fill'), icon: Icons.check, onPressed: busy || chosen == null ? null : fill),
          if (r.asks('new-password') && !r.wantsCard) _createCard(t),
        ],
        const SizedBox(height: 8),
        TextButton(key: const Key('af-cancel'), onPressed: busy ? null : cancel, child: Text(r.save ? 'Not now' : 'Cancel')),
      ]),
    );
  }

  // Who is asking, first (22.6 item 4).
  Widget _requester(TextTheme t, ColorScheme scheme) {
    final store = r.store;
    return Card(
      key: const Key('af-requester'),
      child: Column(children: [
        if (r.isPage)
          ListTile(
            leading: const Icon(Icons.language),
            title: Text(Uri.parse(r.origin).host, style: const TextStyle(fontWeight: FontWeight.w700)),
            subtitle: Text('The page at ${r.origin}, in ${r.label}'),
          )
        else
          ListTile(
            leading: const Icon(Icons.apps),
            title: Text(r.label, style: const TextStyle(fontWeight: FontWeight.w700)),
            subtitle: Text('${r.package}\nPublisher key ${r.certs.isEmpty ? 'unknown' : shortCert(r.certs.first)}'),
            isThreeLine: true,
          ),
        if (!r.isPage)
          ListTile(
            key: const Key('af-installer'),
            leading: Icon(store.isEmpty ? Icons.warning_amber : Icons.verified_outlined, color: store.isEmpty ? Colors.orange : null),
            title: Text(store.isEmpty ? 'Not installed from an app store' : 'Installed from $store'),
            subtitle: store.isEmpty ? const Text('Be sure you know where this app came from.') : null,
          ),
        if (verifiedHosts.isNotEmpty)
          ListTile(
            leading: const Icon(Icons.link),
            title: Text(verifiedHosts.join(', ')),
            subtitle: const Text('These sites say this app may use their logins'),
          ),
      ]),
    );
  }

  Widget _choice(VaultItem it) {
    final selected = chosen == it.name;
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: InkWell(
        key: Key('af-item-${it.name}'),
        borderRadius: BorderRadius.circular(16),
        onTap: () => setState(() => chosen = it.name),
        child: Container(
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: selected ? Theme.of(context).colorScheme.primary : Colors.transparent, width: 3),
          ),
          padding: const EdgeInsets.all(3),
          child: ListTile(
            leading: Icon(it.type == 'card' ? Icons.credit_card : Icons.person_outline),
            title: Text(it.name),
            // A protected item (SPEC 18.10.6): filled once the cosigner answers.
            trailing: it.protected ? Tooltip(message: 'Protected item: asks your cosigner', child: Icon(Icons.shield_outlined, key: Key('af-protected-${it.name}'))) : null,
            subtitle: breachedUnder(Text(it.type == 'card' ? '•••• ${it.detail}' : (it.detail.isEmpty ? 'Saved for this app' : it.detail)),
                it.type == 'card' ? null : widget.settings.breachedCount(it.name), Key('af-breached-${it.name}')),
          ),
        ),
      ),
    );
  }

  Widget _createCard(TextTheme t) => Card(
        key: const Key('af-create'),
        margin: const EdgeInsets.only(top: 16),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Text('Create a login for $placeName', style: t.titleMedium),
            const SizedBox(height: 4),
            Text('A strong password, saved in your vault before it is filled.', style: t.bodySmall),
            const SizedBox(height: 12),
            Field(newUser, 'Username or email (optional)', fieldKey: const Key('af-new-user'), action: TextInputAction.done),
            Row(children: [
              Expanded(child: SelectableText(generated, key: const Key('af-generated'), style: const TextStyle(fontFamily: 'monospace', fontSize: 16))),
              IconButton(tooltip: 'Another password', icon: const Icon(Icons.refresh), onPressed: busy ? null : () => setState(() => generated = strongPassword())),
            ]),
            WideButton('Create and fill', key: const Key('af-create-fill'), icon: Icons.add, tonal: true, onPressed: busy ? null : create),
          ]),
        ),
      );

  List<Widget> _saveForm(TextTheme t) => [
        Field(newUser, 'Username or email', fieldKey: const Key('af-save-user'), action: TextInputAction.done),
        ListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('Password'),
          subtitle: Text(showPassword ? r.savePassword : '•' * 10, style: const TextStyle(fontFamily: 'monospace')),
          trailing: IconButton(tooltip: showPassword ? 'Hide' : 'Show', icon: Icon(showPassword ? Icons.visibility_off : Icons.visibility),
              onPressed: () => setState(() => showPassword = !showPassword)),
        ),
        if (matches!.isNotEmpty) ...[
          Text('Update a login saved here, or save a new one:', style: t.bodySmall),
          for (final it in matches!) _choice(it),
          if (chosen != null) TextButton(onPressed: () => setState(() => chosen = null), child: const Text('Save as a new login instead')),
        ],
        const SizedBox(height: 8),
        WideButton(chosen == null ? 'Save a new login' : 'Update $chosen', key: const Key('af-save'), icon: Icons.save_outlined, onPressed: busy ? null : save),
      ];
}
