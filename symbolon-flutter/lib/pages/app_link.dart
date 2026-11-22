// Linking a login to an Android app (SPEC 22.6 item 8): chosen here, in
// Symbolon, never from a fill, since an in-the-moment choice is what a
// lookalike app would prompt. The person picks an installed app; the link
// screen shows its name, package, signing certificate and where it was
// installed from, and warns when no app store installed it.

import 'package:material_ui/material_ui.dart';
import 'package:flutter/services.dart';

import '../widgets.dart';

/// An installed app, as the platform reports it.
class InstalledApp {
  final String package, label, installer;
  final List<String> certs;     // SHA-256 of each signing certificate, hex
  const InstalledApp(this.package, this.label, this.certs, this.installer);

  static InstalledApp of(Map m) => InstalledApp('${m['package']}', '${m['label']}', [for (final c in (m['certs'] as List?) ?? const []) '$c'], '${m['installer'] ?? ''}');

  String get store => switch (installer) {
        'com.android.vending' => 'Google Play',
        'org.fdroid.fdroid' || 'org.fdroid.basic' => 'F-Droid',
        'com.sec.android.app.samsungapps' => 'Galaxy Store',
        'com.amazon.venezia' => 'Amazon Appstore',
        'com.huawei.appmarket' => 'AppGallery',
        _ => '',
      };
}

Future<List<InstalledApp>> installedApps() async {
  final l = await const MethodChannel('symbolon/platform').invokeListMethod<Map>('installedApps') ?? [];
  return [for (final m in l) InstalledApp.of(m)];
}

/// "AB:CD:..." for a hex SHA-256, all of it, in two lines' worth.
String spacedCert(String hex) => [for (var i = 0; i + 1 < hex.length; i += 2) hex.substring(i, i + 2)].join(':').toUpperCase();

/// Picks an app and confirms the link; the chosen app, or null.
class AppPickerPage extends StatefulWidget {
  final String login;
  final Future<List<InstalledApp>> Function() apps;
  const AppPickerPage({super.key, required this.login, this.apps = installedApps});

  @override
  State<AppPickerPage> createState() => _AppPickerPageState();
}

class _AppPickerPageState extends State<AppPickerPage> {
  late final Future<List<InstalledApp>> apps = widget.apps();
  final query = TextEditingController();

  @override
  void initState() {
    super.initState();
    query.addListener(() => setState(() {}));
  }

  @override
  void dispose() {
    query.dispose();
    super.dispose();
  }

  Future<void> confirm(InstalledApp a) async {
    final scheme = Theme.of(context).colorScheme;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Use ${widget.login} in ${a.label}?'),
        content: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(a.package, style: const TextStyle(fontWeight: FontWeight.w600)),
            const SizedBox(height: 8),
            const Text('Publisher key (SHA-256):'),
            SelectableText(a.certs.isEmpty ? 'unknown' : spacedCert(a.certs.first), key: const Key('link-cert'), style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
            const SizedBox(height: 8),
            Row(children: [
              Icon(a.store.isEmpty ? Icons.warning_amber : Icons.verified_outlined, size: 18, color: a.store.isEmpty ? Colors.orange : null),
              const SizedBox(width: 6),
              Expanded(child: Text(a.store.isEmpty ? 'Not installed from an app store' : 'Installed from ${a.store}', key: const Key('link-installer'))),
            ]),
            if (a.store.isEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text('Only link it if you know where this app came from.', style: TextStyle(color: scheme.error)),
              ),
            const SizedBox(height: 12),
            const Text('Symbolon then fills this login in this app, after you unlock. If an app asked you to link it, '
                'stop: no genuine app needs that. An update signed with another key will not match.'),
          ]),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(key: const Key('link-ok'), onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Link')),
        ],
      ),
    );
    if (ok == true && mounted) Navigator.of(context).pop(a);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Use in an app')),
      body: FutureBuilder<List<InstalledApp>>(
        future: apps,
        builder: (context, s) {
          final all = s.data;
          if (all == null) return const Center(child: CircularProgressIndicator());
          final q = query.text.trim().toLowerCase();
          final shown = all.where((a) => a.label.toLowerCase().contains(q) || a.package.contains(q)).toList();
          return PageBody(children: [
            Text('Choose the app ${widget.login} is for. Linking is only done here, never from an app\'s request.'),
            const SizedBox(height: 12),
            FilterBar(query: query, hint: 'Search ${all.length} apps', onSelected: (_) {}),
            for (final a in shown)
              ListTile(
                key: Key('app-${a.package}'),
                leading: Icon(a.store.isEmpty ? Icons.warning_amber : Icons.apps, color: a.store.isEmpty ? Colors.orange : null),
                title: Text(a.label),
                subtitle: Text(a.package),
                onTap: () => confirm(a),
              ),
          ]);
        },
      ),
    );
  }
}
