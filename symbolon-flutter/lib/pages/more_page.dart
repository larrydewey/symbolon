import 'dart:io';

import 'package:flutter/material.dart';

import '../app.dart';
import '../widgets.dart';
import 'devices_page.dart';
import 'hardware_page.dart';
import 'import_page.dart';
import 'recovery_page.dart';
import 'settings_page.dart';
import 'sharing_page.dart';
import 'setup_page.dart';
import 'tutorial_page.dart';

class MorePage extends StatelessWidget {
  final App app;
  final VoidCallback onSetupDone;
  const MorePage({super.key, required this.app, required this.onSetupDone});

  @override
  Widget build(BuildContext context) {
    void open(Widget page) => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => page));
    return PageBody(children: [
      Card(
        child: Column(children: [
          ListTile(
            leading: const Icon(Icons.devices_other),
            title: const Text('Devices'),
            subtitle: const Text('Add a device to your identity'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => open(DevicesPage(app: app)),
          ),
          ListTile(
            key: const Key('open-sharing'),
            leading: const Icon(Icons.folder_shared_outlined),
            title: const Text('Sharing'),
            subtitle: const Text('Folders shared with your household'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => open(SharingPage(app: app)),
          ),
          ListTile(
            key: const Key('open-import'),
            leading: const Icon(Icons.move_to_inbox),
            title: const Text('Import'),
            subtitle: const Text('From Bitwarden, LastPass, 1Password, a browser…'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => open(ImportPage(app: app)),
          ),
          ListTile(
            leading: const Icon(Icons.healing),
            title: const Text('Recovery'),
            subtitle: const Text('Recover with your kit, or stop a recovery'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => open(RecoveryPage(app: app)),
          ),
          ListTile(
            leading: const Icon(Icons.add_moderator),
            title: const Text('Set up this device'),
            subtitle: const Text('Create a new identity'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () async {
              await Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => SetupPage(app: app)));
              onSetupDone();
            },
          ),
          ListTile(
            key: const Key('open-hardware'),
            leading: const Icon(Icons.memory),
            title: const Text('Hardware key store'),
            subtitle: Text(Platform.isAndroid ? 'The Android Keystore' : 'Protect this device with a TPM'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => open(HardwarePage(keystore: app.settings.keystoreAvailable, strongBox: app.settings.strongBox)),
          ),
          ListTile(
            key: const Key('open-tutorial'),
            leading: const Icon(Icons.school_outlined),
            title: const Text('How Symbolon works'),
            subtitle: const Text('The short tour'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.of(context).push(MaterialPageRoute<void>(fullscreenDialog: true, builder: (_) => const TutorialPage())),
          ),
          ListTile(
            key: const Key('open-settings'),
            leading: const Icon(Icons.settings),
            title: const Text('Settings'),
            subtitle: const Text('Locking, the agent'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => open(SettingsPage(app: app)),
          ),
        ]),
      ),
    ]);
  }
}
