import 'dart:io';

import 'package:flutter/material.dart';

import '../app.dart';
import '../widgets.dart';
import 'devices_page.dart';
import 'hardware_page.dart';
import 'keys_page.dart';
import 'import_page.dart';
import 'org_page.dart';
import 'recovery_page.dart';
import 'settings_page.dart';
import 'sharing_page.dart';
import 'ssh_page.dart';
import 'setup_page.dart';
import 'tutorial_page.dart';

class MorePage extends StatelessWidget {
  final App app;
  final VoidCallback onSetupDone;
  const MorePage({super.key, required this.app, required this.onSetupDone});

  @override
  Widget build(BuildContext context) {
    void open(Widget page) => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => page));
    Widget group(String title, List<Widget> tiles) => Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Padding(padding: const EdgeInsets.fromLTRB(16, 8, 16, 8), child: Text(title, style: Theme.of(context).textTheme.titleSmall?.copyWith(color: Theme.of(context).colorScheme.primary))),
          Card(margin: const EdgeInsets.only(bottom: 16), child: Column(children: tiles)),
        ]);
    return PageBody(children: [
      group('Your identity', [
        ListTile(
          leading: const Icon(Icons.devices_other),
          title: const Text('Devices'),
          subtitle: const Text('Add a device to your identity'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => open(DevicesPage(app: app)),
        ),
        ListTile(
          leading: const Icon(Icons.healing),
          title: const Text('Recovery'),
          subtitle: const Text('Recover with your kit, or stop a recovery'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => open(RecoveryPage(app: app)),
        ),
        ListTile(
          key: const Key('open-keys'),
          leading: const Icon(Icons.usb),
          title: const Text('Security keys'),
          subtitle: const Text('Require a YubiKey or other FIDO2 key to open this device'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => open(SecurityKeysPage(app: app)),
        ),
        ListTile(
          key: const Key('open-hardware'),
          leading: const Icon(Icons.memory),
          title: const Text('Hardware key store'),
          subtitle: Text(Platform.isAndroid ? 'The phone\'s secure hardware' : 'Protect this device with a TPM'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => open(HardwarePage(keystore: app.settings.keystoreAvailable, strongBox: app.settings.strongBox)),
        ),
      ]),
      group('Sharing and work', [
        ListTile(
          key: const Key('open-sharing'),
          leading: const Icon(Icons.folder_shared_outlined),
          title: const Text('Sharing'),
          subtitle: const Text('Folders shared with your household'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => open(SharingPage(app: app)),
        ),
        ListTile(
          key: const Key('open-org'),
          leading: const Icon(Icons.business_outlined),
          title: const Text('Organization'),
          subtitle: const Text('Your company: people, invites, recovery'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => open(OrgPage(app: app)),
        ),
      ]),
      group('Bring in, use elsewhere', [
        ListTile(
          key: const Key('open-import'),
          leading: const Icon(Icons.move_to_inbox),
          title: const Text('Import'),
          subtitle: const Text('From Bitwarden, LastPass, 1Password, a browser…'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => open(ImportPage(app: app)),
        ),
        ListTile(
          key: const Key('open-ssh'),
          leading: const Icon(Icons.vpn_key_outlined),
          title: const Text('SSH keys'),
          subtitle: const Text('For ssh and git, through the Symbolon agent'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => open(SshPage(app: app)),
        ),
      ]),
      group('This app', [
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
        ListTile(
          leading: const Icon(Icons.add_moderator),
          title: const Text('Set up this device'),
          subtitle: const Text('Start again with a new identity on this device'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () async {
          await Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => SetupPage(app: app)));
          onSetupDone();
          },
        ),
      ]),
    ]);
  }
}
