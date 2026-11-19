// What the UI remembers between runs: where the agent and the device
// directory are, and the credentials registered from it (public data: the
// relying party, credential ID and public key). Never a PIN or a secret.
// Kept as JSON in $XDG_CONFIG_HOME/symbolon-ui/settings.json.

import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

class Credential {
  final String rp;
  final String id;
  final String publicKey;
  final bool duress;
  // For a passkey a site made through the system (WebAuthn): the account
  // it is for, as the site named it, and the site's user handle (hex).
  final String userName;
  final String displayName;
  final String userHandle;
  // A passkey imported from another manager (SPEC 5.2, 22.3): a whole key
  // that signs on this device alone, to be replaced by a Symbolon passkey;
  // [replacedBy] is the credential ID of the one that replaced it.
  final bool synced;
  final String replacedBy;
  const Credential(this.rp, this.id, this.publicKey,
      {this.duress = false, this.userName = '', this.displayName = '', this.userHandle = '', this.synced = false, this.replacedBy = ''});

  Credential replaced(String by) =>
      Credential(rp, id, publicKey, duress: duress, userName: userName, displayName: displayName, userHandle: userHandle, synced: synced, replacedBy: by);

  Map<String, dynamic> toJson() => {
        'rp': rp, 'id': id, 'publicKey': publicKey, 'duress': duress, 'userName': userName, 'displayName': displayName, 'userHandle': userHandle,
        if (synced) 'synced': true,
        if (replacedBy.isNotEmpty) 'replacedBy': replacedBy,
      };

  static Credential fromJson(Map<String, dynamic> j) => Credential(j['rp'] as String, j['id'] as String, j['publicKey'] as String,
      duress: (j['duress'] as bool?) ?? false,
      userName: (j['userName'] as String?) ?? '',
      displayName: (j['displayName'] as String?) ?? '',
      userHandle: (j['userHandle'] as String?) ?? '',
      synced: (j['synced'] as bool?) ?? false,
      replacedBy: (j['replacedBy'] as String?) ?? '');

  /// The lines of `device webauthn synced`: "passkey CID RP USER USERNAME
  /// DISPLAY PUBLIC-KEY REPLACED-BY", text in hex, "-" for none.
  static List<Credential> syncedFrom(List<String> lines) {
    String text(String h) => h == '-' ? '' : utf8.decode([for (var i = 0; i + 1 < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)], allowMalformed: true);
    return [
      for (final l in lines)
        if (l.startsWith('passkey ') && l.split(' ').length == 8)
          () {
            final f = l.split(' ');
            return Credential(text(f[2]), f[1], f[6], userHandle: f[3] == '-' ? '' : f[3], userName: text(f[4]), displayName: text(f[5]),
                synced: true, replacedBy: f[7] == '-' ? '' : f[7]);
          }(),
    ];
  }
}

class Settings extends ChangeNotifier {
  final File file;
  String binary;
  String deviceDir;
  String chromium;
  int keepUnlockedMinutes;               // 0: ask for the PIN every time; -1: until locked by hand
  String demoUrl;                        // the demo helper last used (tools/demo.sh --lan)
  bool tutorialSeen;                     // the first-start tutorial was shown (or skipped)
  bool siteIcons;                        // fetch logins' icons from their sites
  List<Credential> credentials;

  // Not saved: what this run of the app found. On Android, where the agent
  // reaches the Keystore through the app (SYMBOLON_KEYSTORE), and whether
  // the phone has one Symbolon can use, in StrongBox or else the TEE.
  Map<String, String> agentEnv = {};
  bool keystoreAvailable = false;
  bool strongBox = false;
  bool authBound = false;   // new Keystore keys will need a recent check (a screen lock, Android 11+)

  Settings(this.file,
      {this.binary = 'symbolon', this.deviceDir = '', this.chromium = 'chromium', this.keepUnlockedMinutes = 5, this.demoUrl = '', this.tutorialSeen = false, this.siteIcons = true, List<Credential>? credentials})
      : credentials = credentials ?? [];

  static File defaultFile() {
    final env = Platform.environment;
    final base = env['XDG_CONFIG_HOME'] ?? '${env['HOME'] ?? '.'}/.config';
    return File('$base/symbolon-ui/settings.json');
  }

  static String defaultDeviceDir() => '${Platform.environment['HOME'] ?? '.'}/.local/share/symbolon/device';

  static Future<Settings> load(File f, {String? defaultDeviceDir}) async {
    final s = Settings(f, deviceDir: defaultDeviceDir ?? Settings.defaultDeviceDir());
    if (!await f.exists()) return s;
    try {
      final j = jsonDecode(await f.readAsString()) as Map<String, dynamic>;
      s.binary = (j['binary'] as String?) ?? s.binary;
      s.deviceDir = (j['deviceDir'] as String?) ?? s.deviceDir;
      s.chromium = (j['chromium'] as String?) ?? s.chromium;
      s.keepUnlockedMinutes = (j['keepUnlockedMinutes'] as int?) ?? s.keepUnlockedMinutes;
      s.demoUrl = (j['demoUrl'] as String?) ?? s.demoUrl;
      s.tutorialSeen = (j['tutorialSeen'] as bool?) ?? s.tutorialSeen;
      s.siteIcons = (j['siteIcons'] as bool?) ?? s.siteIcons;
      s.credentials = ((j['credentials'] as List?) ?? []).map((e) => Credential.fromJson(e as Map<String, dynamic>)).toList();
    } on FormatException {
      // A damaged file: start from the defaults rather than refuse to open.
    }
    return s;
  }

  Future<void> save() async {
    await file.parent.create(recursive: true);
    await file.writeAsString(const JsonEncoder.withIndent('  ').convert({
      'binary': binary,
      'deviceDir': deviceDir,
      'chromium': chromium,
      'keepUnlockedMinutes': keepUnlockedMinutes,
      'demoUrl': demoUrl,
      'tutorialSeen': tutorialSeen,
      'siteIcons': siteIcons,
      'credentials': credentials.map((c) => c.toJson()).toList(),
    }));
    notifyListeners();
  }

  Future<void> update({String? binary, String? deviceDir, String? chromium, int? keepUnlockedMinutes, String? demoUrl, bool? tutorialSeen, bool? siteIcons}) async {
    this.binary = binary ?? this.binary;
    this.deviceDir = deviceDir ?? this.deviceDir;
    this.chromium = chromium ?? this.chromium;
    this.keepUnlockedMinutes = keepUnlockedMinutes ?? this.keepUnlockedMinutes;
    this.demoUrl = demoUrl ?? this.demoUrl;
    this.tutorialSeen = tutorialSeen ?? this.tutorialSeen;
    this.siteIcons = siteIcons ?? this.siteIcons;
    await save();
  }

  // The passkey screen the system opens runs apart from the app and adds
  // to the same file: read the list again before changing it.
  Future<void> reloadCredentials() async {
    try {
      if (!await file.exists()) return;
      final j = jsonDecode(await file.readAsString()) as Map<String, dynamic>;
      credentials = ((j['credentials'] as List?) ?? []).map((e) => Credential.fromJson(e as Map<String, dynamic>)).toList();
      notifyListeners();
    } on FormatException {
      // keep what is in memory
    }
  }

  Future<void> addCredential(Credential c) async {
    await reloadCredentials();
    credentials = [...credentials.where((x) => x.id != c.id), c];
    await save();
  }

  /// The imported passkeys as the agent lists them now, in place of those
  /// this file had.
  Future<void> setSynced(List<Credential> synced) async {
    await reloadCredentials();
    credentials = [...credentials.where((x) => !x.synced), ...synced];
    await save();
  }

  Future<void> removeCredential(String id) async {
    await reloadCredentials();
    credentials = credentials.where((x) => x.id != id).toList();
    await save();
  }
}
