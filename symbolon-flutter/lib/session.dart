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
    if (keepMinutes > 0) _timer = Timer(Duration(minutes: keepMinutes), lock);
  }

  /// Remembers [pin] (after an action it unlocked succeeded).
  void remember(String pin) {
    if (keepMinutes == 0) return;
    _pin = pin;
    _arm();
    notifyListeners();
  }

  void lock() {
    _timer?.cancel();
    final was = _pin != null;
    _pin = null;
    if (was) notifyListeners();
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
      lock();
    }
    return r;
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }
}
