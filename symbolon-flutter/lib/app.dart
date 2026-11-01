// What every page shares: the settings, the unlocked session and the agent.

import 'dart:io';

import 'package:flutter/widgets.dart';

import 'biometric.dart';
import 'cli.dart';
import 'favicons.dart';
import 'session.dart';
import 'settings.dart';

class App {
  final Settings settings;
  final PinSession session;
  App(this.settings) : session = PinSession(keepMinutes: settings.keepUnlockedMinutes) {
    session.unlocker = () => Bio.unlock('Unlock Symbolon');
  }

  late final Favicons _favicons = Favicons(Directory('${settings.file.parent.path}/icons'));

  SymbolonCli get cli => SymbolonCli(settings.binary, env: settings.agentEnv);

  /// Site icons for logins, unless turned off in the settings.
  Favicons? get favicons => settings.siteIcons ? _favicons : null;
  String get dir => settings.deviceDir;

  /// Runs an agent operation that needs the PIN, through the session. (A
  /// Keystore key that needs a fresh check of the person asks for it itself,
  /// KeystoreServer.kt.)
  Future<CliResult?> withPin(BuildContext context, Future<CliResult> Function(String pin) op, {String? note}) {
    return session.withPin<CliResult>(context, op,
        ok: (r) => r.ok, wrongPin: (r) => r.problem.toLowerCase().contains('wrong pin'), note: note);
  }
}
