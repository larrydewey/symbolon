// Symbolon as the phone's passkey provider (Android 14+;
// android/.../SymbolonCredentialService.kt). Once it is turned on in the
// system settings, sites and apps on the phone offer Symbolon passkeys, and
// so does the "Use a phone or tablet" QR code a computer shows: the phone's
// camera opens it, and Android asks which provider to use.

import 'dart:io';

import 'package:flutter/services.dart';

enum ProviderState { unsupported, off, on }

class PasskeyProvider {
  static const _ch = MethodChannel('symbolon/platform');

  static Future<ProviderState> state() async {
    if (!Platform.isAndroid) return ProviderState.unsupported;
    try {
      if (await _ch.invokeMethod<bool>('providerSupported') != true) return ProviderState.unsupported;
      return await _ch.invokeMethod<bool>('providerEnabled') == true ? ProviderState.on : ProviderState.off;
    } on PlatformException {
      return ProviderState.unsupported;
    }
  }

  /// The system page where the person turns Symbolon on.
  static Future<void> openSettings() => _ch.invokeMethod('openProviderSettings');
}
