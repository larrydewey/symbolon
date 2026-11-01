// Whether this device has a hardware key store Symbolon can use. On Linux
// that is a TPM 2.0 behind the kernel's resource manager (/dev/tpmrm0),
// which the agent uses for its two unlock keys; the user must be allowed to
// open it (the tss group). On Android it is the Keystore (Android 9+),
// which the app serves to the agent.

import 'dart:io';

enum HardwareState {
  ready,       // a TPM this user can open
  noAccess,    // a TPM, but this user may not open it
  none,        // no TPM visible (absent, or off in the firmware)
  keystore,    // a phone with the Android Keystore
  android,     // a phone too old for it (before Android 9)
}

const tpmDevice = '/dev/tpmrm0';

Future<HardwareState> detectHardware({bool keystore = false}) async {
  if (Platform.isAndroid) return keystore ? HardwareState.keystore : HardwareState.android;
  if (!await File(tpmDevice).exists()) return HardwareState.none;
  try {
    final r = await Process.run('test', ['-r', tpmDevice, '-a', '-w', tpmDevice]);
    return r.exitCode == 0 ? HardwareState.ready : HardwareState.noAccess;
  } on ProcessException {
    return HardwareState.noAccess;
  }
}
