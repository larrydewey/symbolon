// The unlocked session: the PIN, held in memory for a few minutes after it
// was last used so that each action does not ask for it again. It is never
// written anywhere, and it is dropped when the time runs out, when the app
// goes to the background, or on "Lock now". With keepMinutes 0 every
// action asks; with -1 it stays until locked by hand or the app goes away.

import 'dart:async';

import 'package:flutter/material.dart';

import 'widgets.dart';

class PinSession extends ChangeNotifier {
  String? _pin;
  Timer? _timer;
  int keepMinutes;

  PinSession({this.keepMinutes = 5});

  bool get unlocked => _pin != null;

  void _arm() {
    _timer?.cancel();
    if (keepMinutes == 0) {
      _pin = null;
      return;
    }
    if (keepMinutes > 0) _timer = Timer(Duration(minutes: keepMinutes), forget);
  }

  /// Remembers [pin] (after an action it unlocked succeeded).
  void remember(String pin) {
    if (keepMinutes == 0) return;
    _pin = pin;
    _arm();
    notifyListeners();
  }

  /// Drops the PIN (the "stay unlocked" time ran out, or a PIN was wrong).
  /// What is on screen stays: the next action asks again.
  void forget() {
    _timer?.cancel();
    final was = _pin != null;
    _pin = null;
    if (was) notifyListeners();
  }

  /// Counts the locks: each one closes whatever shows vault contents.
  int locks = 0;

  /// Locks the app: the person left it (another app, the home screen, the
  /// screen off) or tapped the lock. Drops the PIN, and every screen that
  /// shows vault contents closes or clears, even when no PIN was kept
  /// ("Ask every time").
  void lock() {
    _timer?.cancel();
    _pin = null;
    locks++;
    notifyListeners();
  }

  /// Where a PIN can come from before it is typed (biometric unlock);
  /// null when it gives none.
  Future<String?> Function()? unlocker;

  /// The PIN: the remembered one, the unlocker's, or asked for. Null when
  /// cancelled.
  Future<String?> get(BuildContext context, {String? note}) async {
    final p = _pin;
    if (p != null) {
      _arm();
      return p;
    }
    final u = unlocker;
    if (u != null) {
      final b = await u();
      if (b != null) return b;
    }
    if (!context.mounted) return null;
    return askSecret(context, note: note);
  }

  /// Runs [op] with the PIN; remembers it when [op] succeeds, forgets it
  /// when the agent says it was wrong.
  Future<T?> withPin<T>(BuildContext context, Future<T> Function(String pin) op, {required bool Function(T) ok, required bool Function(T) wrongPin, String? note}) async {
    final p = await get(context, note: note);
    if (p == null) return null;
    final r = await op(p);
    if (ok(r)) {
      remember(p);
    } else if (wrongPin(r)) {
      forget();
    }
    return r;
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }
}

/// For a screen that shows vault contents: when the app locks (the person
/// left it, or tapped the lock), it closes whatever is open above it (a
/// dialog, a sheet, the editor) and then itself, so nothing of the vault is
/// on screen when the app is opened again.
mixin ClosesOnLock<T extends StatefulWidget> on State<T> {
  PinSession get lockingSession;
  late final int _opened = lockingSession.locks;

  @override
  void initState() {
    super.initState();
    _opened;
    lockingSession.addListener(_onSession);
  }

  @override
  void dispose() {
    lockingSession.removeListener(_onSession);
    super.dispose();
  }

  void _onSession() {
    if (!mounted || lockingSession.locks == _opened) return;
    final me = ModalRoute.of(context);
    if (me == null || !me.isActive) return;
    final nav = Navigator.of(context);
    nav.popUntil((r) => r == me);
    nav.removeRoute(me);
  }
}
