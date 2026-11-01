// Fingerprint or face unlock (Android; android/.../Biometric.kt): the PIN
// kept encrypted under a Keystore key that a fresh biometric or screen-lock
// check opens. (The agent's Keystore keys, on a phone with a screen lock,
// need such a check within 30 seconds; the app's Keystore server asks for
// it when they do.) Elsewhere, unsupported.

import 'dart:io';

import 'package:flutter/services.dart';

class BioState {
  final bool supported;   // Android 11+ with a screen lock
  final bool biometric;   // a fingerprint or face is enrolled
  final bool enrolled;    // the PIN is kept for biometric unlock
  const BioState(this.supported, this.biometric, this.enrolled);
  static const none = BioState(false, false, false);
}

class Bio {
  static const _ch = MethodChannel('symbolon/platform');

  /// How long a check lets the agent's keys work (Biometric.kt, with margin).
  static const window = Duration(seconds: 25);

  static DateTime? _last;

  static Future<BioState> state() async {
    if (!Platform.isAndroid) return BioState.none;
    final m = await _ch.invokeMapMethod<String, dynamic>('bioState') ?? {};
    return BioState(m['supported'] == true, m['biometric'] == true, m['enrolled'] == true);
  }

  /// Keeps [pin] for biometric unlock, after a check. False when cancelled.
  static Future<bool> enroll(String pin) async {
    if (!Platform.isAndroid) return false;
    try {
      final ok = await _ch.invokeMethod<bool>('bioEnroll', {'pin': pin}) == true;
      if (ok) _last = DateTime.now();
      return ok;
    } on PlatformException {
      return false;
    }
  }

  /// The kept PIN after a check; null when cancelled, when none is kept, or
  /// when a new fingerprint was enrolled since (then the PIN is typed again).
  static Future<String?> unlock(String reason) async {
    if (!Platform.isAndroid) return null;
    try {
      final p = await _ch.invokeMethod<String>('bioUnlock', {'reason': reason});
      if (p != null) _last = DateTime.now();
      return p;
    } on PlatformException {
      return null;
    }
  }

  /// A check of the person, unless one happened within [window].
  static Future<bool> fresh(String reason) async {
    final l = _last;
    if (l != null && DateTime.now().difference(l) < window) return true;
    if (!Platform.isAndroid) return true;
    try {
      final ok = await _ch.invokeMethod<bool>('bioAuthenticate', {'reason': reason}) == true;
      if (ok) _last = DateTime.now();
      return ok;
    } on PlatformException {
      return false;
    }
  }

  static Future<void> forget() async {
    if (Platform.isAndroid) await _ch.invokeMethod('bioForget');
  }
}
